package api

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
)

const (
	maxHostCapabilities     = 32
	maxHostCapabilityLength = 64
)

type hostHeartbeatRequest struct {
	Capabilities []string `json:"capabilities"`
	// MaintenanceWindowStart: RFC3339 start of the machine's next announced
	// maintenance window; empty string means an authoritative "nothing
	// announced"; absent means the host couldn't tell this beat (keep the
	// last known answer — a flaky metadata read must never un-record a
	// window).
	MaintenanceWindowStart *string `json:"maintenance_window_start,omitempty"`
}

// drainLeadTime is how far ahead of an announced maintenance window the host
// begins draining (pausing its active sandboxes). Late on purpose: pausing
// disrupts live workloads, so the platform waits until the restart is close;
// a full fleet drain measures in low minutes, so an hour holds generous
// margin for retries. One reviewed constant, derived from measured drain
// time × safety factor — not host config.
const drainLeadTime = time.Hour

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

	status := host.Status
	if req.MaintenanceWindowStart != nil {
		status = h.recordMaintenanceWindow(ctx, hostID, *req.MaintenanceWindowStart, status)
	}

	c.JSON(http.StatusOK, gin.H{"status": status})
}

// recordMaintenanceWindow persists the heartbeat's announced-maintenance
// answer and makes the drain decision: a host with a window inside
// drainLeadTime flips active → draining, which removes it from placement and
// puts the drain reaper to work pausing its active sandboxes. Un-draining is
// deliberately NOT done here — see UndrainHost. Returns the (possibly
// updated) host status for the heartbeat response.
func (h *Handlers) recordMaintenanceWindow(ctx context.Context, hostID, raw, status string) string {
	var window *time.Time
	if raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			log.Warn().Str("host_id", hostID).Str("value", raw).Msg("heartbeat carried unparseable maintenance window; ignoring")
			return status
		}
		window = &t
	}
	var ts pgtype.Timestamptz
	if window != nil {
		ts = pgtype.Timestamptz{Time: *window, Valid: true}
	}
	if err := h.DB.UpdateHostMaintenanceWindow(ctx, db.UpdateHostMaintenanceWindowParams{
		ID: hostID, MaintenanceWindowStart: ts,
	}); err != nil {
		log.Error().Err(err).Str("host_id", hostID).Msg("failed to record maintenance window")
		return status
	}
	if window == nil || status != "active" || time.Until(*window) > drainLeadTime {
		return status
	}
	n, err := h.DB.DrainHost(ctx, hostID)
	if err != nil {
		log.Error().Err(err).Str("host_id", hostID).Msg("failed to drain host for maintenance")
		return status
	}
	if n > 0 {
		log.Warn().Str("host_id", hostID).Time("window_start", *window).
			Msg("host maintenance window imminent — draining: placement stopped, active sandboxes will be paused")
		if h.Scheduler != nil {
			h.Scheduler.Invalidate()
		}
		return "draining"
	}
	return status
}

// DrainHost handles POST /internal/hosts/:host_id/drain — the operator
// entry point for planned host work (reboots, kernel updates): drain, wait
// for the drain-complete log/zero actives, then restart the host; paused
// sandboxes survive where active ones would not.
func (h *Handlers) DrainHost(c *gin.Context) {
	hostID := c.Param("host_id")
	if hostID == "" {
		respondErrorMsg(c, "bad_request", "host_id is required", http.StatusBadRequest)
		return
	}
	n, err := h.DB.DrainHost(c.Request.Context(), hostID)
	if err != nil {
		log.Error().Err(err).Str("host_id", hostID).Msg("DrainHost failed")
		respondError(c, ErrInternal)
		return
	}
	if n == 0 {
		respondErrorMsg(c, "conflict", "host is not active (already draining, or unhealthy)", http.StatusConflict)
		return
	}
	log.Warn().Str("host_id", hostID).Msg("host draining via operator request")
	if h.Scheduler != nil {
		h.Scheduler.Invalidate()
	}
	c.JSON(http.StatusOK, gin.H{"status": "draining"})
}

// UndrainHost handles POST /internal/hosts/:host_id/undrain. Manual-only by
// design: automatic un-draining on a cleared metadata signal would put fresh
// workloads on a machine about to restart whenever the signal flickers; the
// asymmetric mistake costs mean only the safe direction is automated.
func (h *Handlers) UndrainHost(c *gin.Context) {
	hostID := c.Param("host_id")
	if hostID == "" {
		respondErrorMsg(c, "bad_request", "host_id is required", http.StatusBadRequest)
		return
	}
	n, err := h.DB.UndrainHost(c.Request.Context(), hostID)
	if err != nil {
		log.Error().Err(err).Str("host_id", hostID).Msg("UndrainHost failed")
		respondError(c, ErrInternal)
		return
	}
	if n == 0 {
		respondErrorMsg(c, "conflict", "host is not draining", http.StatusConflict)
		return
	}
	log.Info().Str("host_id", hostID).Msg("host un-drained via operator request")
	if h.Scheduler != nil {
		h.Scheduler.Invalidate()
	}
	c.JSON(http.StatusOK, gin.H{"status": "active"})
}
