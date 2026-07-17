package api

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
)

const (
	// Keep the server-side deadline below Cloud Run's 300-second request cap,
	// leaving time for a final compensation and HTTP response.
	hostDrainTimeout = 4 * time.Minute
	// Claim at most one parallel wave at a time. Once rows are marked pausing,
	// every claimed row must run the saga even if the request is canceled.
	hostDrainBatchSize   = int32(10)
	hostDrainParallelism = 10
	hostDrainPollEvery   = 500 * time.Millisecond
)

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

	host, err := h.DB.UpdateHostHeartbeat(c.Request.Context(), hostID)
	if err != nil {
		if err == pgx.ErrNoRows {
			respondErrorMsg(c, "not_found", "host not found", http.StatusNotFound)
			return
		}
		log.Error().Err(err).Str("host_id", hostID).Msg("UpdateHostHeartbeat failed")
		respondError(c, ErrInternal)
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": host.Status})
}

// DrainHost handles POST /internal/hosts/:host_id/drain. It first marks the
// host draining so normal admission stops, then cooperatively claims and
// pauses every running sandbox on that host. Transitional rows and active
// saved-snapshot captures are allowed to converge before another claim pass.
func (h *Handlers) DrainHost(c *gin.Context) {
	hostID := c.Param("host_id")
	if hostID == "" {
		respondErrorMsg(c, "bad_request", "host_id is required", http.StatusBadRequest)
		return
	}

	status, err := h.DB.BeginHostDrain(c.Request.Context(), hostID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondErrorMsg(c, "not_found", "host not found", http.StatusNotFound)
			return
		}
		log.Error().Err(err).Str("host_id", hostID).Msg("BeginHostDrain failed")
		respondError(c, ErrInternal)
		return
	}

	drainCtx, cancel := context.WithTimeout(c.Request.Context(), hostDrainTimeout)
	defer cancel()
	pausedCount, err := h.drainHostSandboxes(drainCtx, hostID)
	if err != nil {
		log.Error().Err(err).
			Str("host_id", hostID).
			Int("paused_count", pausedCount).
			Msg("host drain failed; host remains draining")
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			respondErrorMsg(c, "host_drain_timeout", "Host drain did not converge before its deadline; the host remains draining", http.StatusGatewayTimeout)
			return
		}
		respondErrorMsg(c, "host_drain_failed", "Host drain failed; the host remains draining", http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"host_id":      hostID,
		"status":       status,
		"paused_count": pausedCount,
	})
}

// ActivateHost handles POST /internal/hosts/:host_id/activate. Host heartbeats
// never re-admit draining hosts, so maintenance automation must explicitly call
// this endpoint only after the host deployment has been verified.
func (h *Handlers) ActivateHost(c *gin.Context) {
	hostID := c.Param("host_id")
	if hostID == "" {
		respondErrorMsg(c, "bad_request", "host_id is required", http.StatusBadRequest)
		return
	}

	status, err := h.DB.ActivateDrainedHost(c.Request.Context(), hostID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// The guarded UPDATE returns no row both when the host is missing and
			// when it is not yet safe to re-admit. Distinguish those outcomes for
			// maintenance automation without weakening the atomic SQL boundary.
			if _, getErr := h.DB.GetHost(c.Request.Context(), hostID); errors.Is(getErr, pgx.ErrNoRows) {
				respondErrorMsg(c, "not_found", "host not found", http.StatusNotFound)
				return
			} else if getErr != nil {
				log.Error().Err(getErr).Str("host_id", hostID).Msg("GetHost after failed activation guard")
				respondError(c, ErrInternal)
				return
			}
			respondErrorMsg(c, "host_not_drained", "Host is not draining or still has active lifecycle work", http.StatusConflict)
			return
		}
		log.Error().Err(err).Str("host_id", hostID).Msg("ActivateDrainedHost failed")
		respondError(c, ErrInternal)
		return
	}

	c.JSON(http.StatusOK, gin.H{"host_id": hostID, "status": status})
}

// drainHostSandboxes repeatedly claims active rows and runs the same pause
// saga used by the timeout reaper. A successful return proves there are no
// non-destroyed starting/active/pausing/resuming rows left on the host.
func (h *Handlers) drainHostSandboxes(ctx context.Context, hostID string) (int, error) {
	pausedCount := 0
	for {
		if err := ctx.Err(); err != nil {
			return pausedCount, err
		}

		claimed, err := h.DB.ClaimHostDrainSandboxes(ctx, db.ClaimHostDrainSandboxesParams{
			HostID:    hostID,
			BatchSize: hostDrainBatchSize,
		})
		if err != nil {
			return pausedCount, err
		}

		var (
			batchMu     sync.Mutex
			batchPaused int
			firstErr    error
		)
		// Do not abandon already-claimed rows on cancellation. Each saga sees
		// the original context for the primary VMD attempt, then uses its bounded
		// detached retry/compensation path to converge durable state.
		dispatchBounded(context.WithoutCancel(ctx), claimed, hostDrainParallelism, func(row db.ClaimHostDrainSandboxesRow) {
			claim := db.ClaimExpiredSandboxesRow{
				ID:         row.ID,
				TeamID:     row.TeamID,
				Name:       row.Name,
				SnapshotID: row.SnapshotID,
				HostID:     row.HostID,
			}
			pauseErr := h.pauseClaimedSandbox(ctx, claim, hostDrainPauseOperation)
			batchMu.Lock()
			defer batchMu.Unlock()
			if pauseErr != nil {
				if firstErr == nil {
					firstErr = pauseErr
				}
				return
			}
			batchPaused++
		})
		pausedCount += batchPaused
		if firstErr != nil {
			return pausedCount, firstErr
		}

		remaining, err := h.DB.CountHostLifecycleActiveSandboxes(ctx, hostID)
		if err != nil {
			return pausedCount, err
		}
		if remaining == 0 {
			return pausedCount, nil
		}

		// A full/partial batch usually means more active rows are immediately
		// claimable. Only back off when every remaining row is transitional or
		// temporarily owned by a saved-snapshot operation.
		if len(claimed) > 0 {
			continue
		}
		timer := time.NewTimer(hostDrainPollEvery)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return pausedCount, ctx.Err()
		case <-timer.C:
		}
	}
}
