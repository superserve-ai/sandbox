package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
)

const (
	maxHostCapabilities     = 32
	maxHostCapabilityLength = 64
)

type hostHeartbeatRequest struct {
	Capabilities []string `json:"capabilities"`
}

// HostHeartbeat handles POST /internal/hosts/:host_id/heartbeat.
// VMD calls this every 30s to prove liveness. The control plane updates
// last_heartbeat_at; a background detector marks hosts unhealthy after
// 2 minutes of silence. If the host was previously marked unhealthy, the
// heartbeat automatically re-activates it (recovery from transient outage).
func (h *Handlers) HostHeartbeat(c *gin.Context) {
	hostID := c.Param("host_id")
	if hostID == "" {
		respondErrorMsg(c, "bad_request", "host_id is required", http.StatusBadRequest)
		return
	}

	var req hostHeartbeatRequest
	if c.Request.ContentLength != 0 {
		if err := bindJSONStrict(c, &req); err != nil {
			respondErrorMsg(c, "bad_request", "Invalid request body: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	if len(req.Capabilities) > maxHostCapabilities {
		respondErrorMsg(c, "bad_request", "too many capabilities", http.StatusBadRequest)
		return
	}
	capabilities := make([]string, 0, len(req.Capabilities))
	for _, capability := range req.Capabilities {
		if capability == "" || len(capability) > maxHostCapabilityLength {
			respondErrorMsg(c, "bad_request", "capability entries must be non-empty and short", http.StatusBadRequest)
			return
		}
		capabilities = append(capabilities, capability)
	}

	ctx := c.Request.Context()
	replace := func(q *db.Queries) (db.UpdateHostHeartbeatRow, error) {
		host, err := q.UpdateHostHeartbeat(ctx, hostID)
		if err != nil {
			return db.UpdateHostHeartbeatRow{}, err
		}
		// Missing capabilities is an explicit empty replacement. This clears a
		// stale attestation immediately when VMD can no longer verify its proxy.
		if err := q.DeleteHostCapabilities(ctx, hostID); err != nil {
			return db.UpdateHostHeartbeatRow{}, err
		}
		for _, capability := range capabilities {
			if err := q.InsertHostCapability(ctx, db.InsertHostCapabilityParams{
				HostID: hostID, Capability: capability,
			}); err != nil {
				return db.UpdateHostHeartbeatRow{}, err
			}
		}
		return host, nil
	}

	var host db.UpdateHostHeartbeatRow
	var err error
	if h.Pool == nil {
		host, err = replace(h.DB)
	} else {
		var tx pgx.Tx
		if tx, err = h.Pool.Begin(ctx); err == nil {
			defer tx.Rollback(ctx)
			if host, err = replace(h.DB.WithTx(tx)); err == nil {
				err = tx.Commit(ctx)
			}
		}
	}
	if err != nil {
		if err == pgx.ErrNoRows {
			respondErrorMsg(c, "not_found", "host not found", http.StatusNotFound)
			return
		}
		log.Error().Err(err).Str("host_id", hostID).Msg("UpdateHostHeartbeat failed")
		respondError(c, ErrInternal)
		return
	}

	if host.PrevStatus == "unhealthy" && host.Status == "active" {
		// The heartbeat just recovered this host; drop the scheduler's cached
		// list so its capacity is usable now, not after the cache TTL.
		log.Info().Str("host_id", hostID).Msg("host recovered via heartbeat")
		if h.Scheduler != nil {
			h.Scheduler.Invalidate()
		}
	}

	c.JSON(http.StatusOK, gin.H{"status": host.Status})
}
