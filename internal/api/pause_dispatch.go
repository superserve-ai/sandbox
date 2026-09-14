package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/db"
)

var errPauseLeaseExpired = errors.New("pause lease expired before the host could be asked")

// prefersAsync reports whether the client asked for a 202 over a held
// connection (RFC 7240 Prefer: respond-async).
func prefersAsync(c *gin.Context) bool {
	for _, v := range c.Request.Header.Values("Prefer") {
		for _, p := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(p), "respond-async") {
				return true
			}
		}
	}
	return false
}

type pauseOutcome int

const (
	pauseDone       pauseOutcome = iota // snapshot taken; bookkeeping in flight
	pauseGone                           // host has no such VM; row marked failed
	pauseUndecided                      // row still 'pausing'; the reconciler finishes it
	pauseUnresolved                     // host unknown; nothing dispatched, row back to 'active'
)

// respondPause answers a dispatch the caller waited for. Only a row known to
// be 'active' again is reported as failed; one still 'pausing' is accepted,
// since the reconciler will pause it.
func respondPause(c *gin.Context, o pauseOutcome) {
	switch o {
	case pauseDone:
		c.Status(http.StatusNoContent)
	case pauseGone:
		respondError(c, ErrSandboxGone)
	case pauseUndecided:
		acceptPausing(c)
	default:
		respondError(c, ErrInternal)
	}
}

func acceptPausing(c *gin.Context) {
	c.Header("Retry-After", "1")
	c.JSON(http.StatusAccepted, gin.H{"status": db.SandboxStatusPausing})
}

// dispatchPause runs the host RPC for a claimed pause and records its answer.
// It knows nothing of the HTTP request; every write runs detached.
func (h *Handlers) dispatchPause(ctx context.Context, sandbox db.BeginPauseRow, leaseUntil time.Time, actorID *uuid.UUID, l zerolog.Logger) pauseOutcome {
	sandboxID, teamID := sandbox.ID, sandbox.TeamID
	lease := pauseLease{id: sandbox.PauseOpID, version: sandbox.PauseOpLeaseVersion}
	// BeginPause already claimed 'pausing', so a host lookup failure reverts:
	// nothing was dispatched, so the VM is known to be running. This is the
	// only revert after BeginPause. If it cannot be written the claim stands
	// and the reconciler pauses the VM, so the answer is 'pausing'.
	vmd, err := h.vmdForHost(ctx, sandbox.HostID)
	if err != nil {
		l.Error().Err(err).Msg("resolve VMD for pause failed")
		if !h.revertPause(ctx, sandboxID, teamID, lease, actorID, l) {
			return pauseUndecided
		}
		return pauseUnresolved
	}
	// The pause's identity rides the RPC into the host's backup pipeline and
	// returns in the upload report, naming this exact pause.
	pauseToken := uuid.UUID(sandbox.PauseOpID.Bytes).String()
	snapshotPath, memPath, manifest, ackedPauseToken, err := h.pauseWithRetry(ctx, vmd, sandbox.HostID, sandboxID.String(), pauseToken, leaseUntil)
	if err != nil {
		bg := context.WithoutCancel(ctx)
		// The resolved host has no such VM, or one it can never pause:
		// 'active' was already a lie.
		if isVMDNotFound(err) || isVMDFailedPrecondition(err) {
			l.Warn().Err(err).Msg("VMD PauseInstance: VM unavailable, marking sandbox failed")
			h.asyncBookkeeping("fail-pause", func() { h.failPause(bg, sandboxID, sandbox.HostID, lease, l) })
			return pauseGone
		}
		// Timeout, unavailable, or any other error after dispatch says
		// nothing about whether the VM still runs; the row stays 'pausing'
		// and the reconciler asks the host again (see pause_reconcile.go).
		l.Warn().Err(err).Msg("VMD PauseInstance undecided — left pausing for reconciliation")
		h.asyncBookkeeping("release-pause-lease", func() { h.releasePauseLease(bg, sandboxID, lease, 0, l) })
		return pauseUndecided
	}

	l.Debug().
		Str("snapshot_path", snapshotPath).
		Str("mem_path", memPath).
		Msg("VMD pause complete")

	// The snapshot exists on disk, so the bookkeeping (snapshot row upsert +
	// pausing → paused in one CTE) is fire-and-forget: every other
	// transition is status-gated and a racing resume 409s until it lands.
	finalizeCtx := context.WithoutCancel(ctx)
	h.asyncBookkeeping("finalize-pause", func() {
		fctx, fcancel := context.WithTimeout(finalizeCtx, asyncTimeout)
		defer fcancel()
		params := db.FinalizePauseParams{
			ID:                  sandboxID,
			TeamID:              teamID,
			PauseOpID:           sandbox.PauseOpID,
			PauseOpLeaseVersion: &sandbox.PauseOpLeaseVersion,
			Path:                snapshotPath,
			MemPath:             &memPath,
			Trigger:             "pause",
			// Store only what the daemon echoed: an older daemon drops the
			// token, and storing it anyway would demand of its reports an
			// identity they can never carry.
			PauseToken: ackedPauseToken,
		}
		applyManifest(&params, manifest)
		if _, err := h.finalizePause(fctx, params); err != nil {
			// The row left 'pausing' first (deleted mid-pause): the VM is
			// stopped and its files are on disk, nothing left to record.
			if err == pgx.ErrNoRows {
				l.Warn().Msg("FinalizePause: sandbox deleted mid-pause")
				return
			}
			if !h.pauseLanded(finalizeCtx, sandboxID, teamID) {
				l.Error().Err(err).Msg("async DB FinalizePause failed — sandbox stays 'pausing' for reconciliation")
				return
			}
			l.Warn().Err(err).Msg("FinalizePause answer lost after it committed")
		}
		// Recorded once the row says paused: a finalize the reconciler has
		// to redo must not leave two success entries for one pause.
		h.logSandboxActivity(finalizeCtx, sandboxID, teamID, actorID, "sandbox", "paused", "success", &sandbox.Name, nil, nil)
		h.captureFor(actorID, teamID, "sandbox_paused", map[string]any{"sandbox_id": sandboxID.String()})
	})
	return pauseDone
}
