package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/db"
)

// pauseAcceptBudget is how long a request that prefers an asynchronous answer
// (Prefer: respond-async) waits for the host before it is told 'pausing' and
// left to poll. Long enough that a normal pause still returns 204. A variable
// so tests can shorten it.
var pauseAcceptBudget = 20 * time.Second

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
	pauseDone      pauseOutcome = iota // snapshot taken; bookkeeping in flight
	pauseGone                          // host has no such VM; row marked failed
	pauseUndecided                     // no answer; row left 'pausing' for the reconciler
)

func respondPause(c *gin.Context, o pauseOutcome) {
	switch o {
	case pauseDone:
		c.Status(http.StatusNoContent)
	case pauseGone:
		respondError(c, ErrSandboxGone)
	default:
		respondError(c, ErrInternal)
	}
}

// dispatchPause runs the host RPC for a claimed pause and the bookkeeping its
// answer calls for. It knows nothing of the HTTP request: ctx is whatever the
// caller is willing to wait on, every write runs detached, and the outcome is
// the same whether or not anyone is still listening.
func (h *Handlers) dispatchPause(ctx context.Context, vmd VMDClient, sandbox db.BeginPauseRow, actorID *uuid.UUID, l zerolog.Logger) pauseOutcome {
	sandboxID, teamID := sandbox.ID, sandbox.TeamID
	// The pause's identity rides the RPC into the host's backup pipeline and
	// returns in the upload report, naming this exact pause.
	pauseToken := uuid.UUID(sandbox.PauseOpID.Bytes).String()
	snapshotPath, memPath, manifest, ackedPauseToken, err := pauseWithRetry(ctx, vmd, sandboxID.String(), pauseToken)
	if err != nil {
		// The resolved host has no such VM: it crashed or was removed
		// out-of-band, so 'active' was already a lie.
		if isVMDNotFound(err) {
			l.Warn().Err(err).Msg("VMD PauseInstance: VM unavailable, marking sandbox failed")
			h.markSandboxFailedAsync(ctx, sandboxID, teamID, sandbox.HostID, false)
			return pauseGone
		}
		// Timeout, unavailable, or any other error after dispatch says
		// nothing about whether the VM still runs; the row stays 'pausing'
		// and the reconciler asks the host again (see pause_reconcile.go).
		l.Warn().Err(err).Msg("VMD PauseInstance undecided — left pausing for reconciliation")
		lease := pauseLease{id: sandbox.PauseOpID, version: sandbox.PauseOpLeaseVersion}
		releaseCtx := context.WithoutCancel(ctx)
		h.asyncBookkeeping("release-pause-lease", func() { h.releasePauseLease(releaseCtx, sandboxID, lease, 0, l) })
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
			l.Error().Err(err).Msg("async DB FinalizePause failed — sandbox stays 'pausing' for reconciliation")
			return
		}
	})

	// The interval closed at BeginPause; this is the end of the host work,
	// not the moment the sandbox left active.
	h.logSandboxActivity(ctx, sandboxID, teamID, actorID, "sandbox", "paused", "success", &sandbox.Name, nil, nil)
	h.captureFor(actorID, teamID, "sandbox_paused", map[string]any{"sandbox_id": sandboxID.String()})
	return pauseDone
}

// captureFor is capture for code that no longer holds the request.
func (h *Handlers) captureFor(actorID *uuid.UUID, teamID uuid.UUID, event string, props map[string]any) {
	if h.Analytics == nil {
		return
	}
	var actor string
	if actorID != nil {
		actor = actorID.String()
	}
	h.Analytics.Capture(actor, teamID.String(), event, props)
}
