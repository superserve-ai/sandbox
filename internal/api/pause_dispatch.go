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
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/db"
)

var errPauseLeaseExpired = errors.New("pause lease expired before the host could be asked")

// leaseDeadline is when a claim stops being its holder's: the expiry the claim
// returned, or the nominal lease from when it was taken.
func leaseDeadline(stored pgtype.Timestamptz, claimedAt time.Time, leaseSeconds int32) time.Time {
	if stored.Valid {
		return stored.Time
	}
	return claimedAt.Add(time.Duration(leaseSeconds) * time.Second)
}

// attemptDeadline bounds one host attempt: budget from now, or what is left of
// the lease after room for the finalize write and clock skew, whichever comes
// first. ok is false when nothing is left.
func attemptDeadline(leaseUntil time.Time, budget time.Duration) (time.Time, bool) {
	now := time.Now()
	d := now.Add(budget)
	if lease := leaseUntil.Add(-asyncTimeout - pauseLeaseSkew); lease.Before(d) {
		d = lease
	}
	return d, d.After(now)
}

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

// respondPause answers a dispatch the caller waited for. An undecided one is
// still 'pausing' and being reconciled; the caller keeps today's error.
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

func acceptPausing(c *gin.Context) {
	c.Header("Retry-After", "1")
	c.JSON(http.StatusAccepted, gin.H{"status": db.SandboxStatusPausing})
}

// dispatchPause runs the host RPC for a claimed pause and records its answer.
// It knows nothing of the HTTP request; every write runs detached.
func (h *Handlers) dispatchPause(ctx context.Context, vmd VMDClient, sandbox db.BeginPauseRow, leaseUntil time.Time, actorID *uuid.UUID, l zerolog.Logger) pauseOutcome {
	sandboxID, teamID := sandbox.ID, sandbox.TeamID
	// The pause's identity rides the RPC into the host's backup pipeline and
	// returns in the upload report, naming this exact pause.
	pauseToken := uuid.UUID(sandbox.PauseOpID.Bytes).String()
	lease := pauseLease{id: sandbox.PauseOpID, version: sandbox.PauseOpLeaseVersion}
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
			l.Error().Err(err).Msg("async DB FinalizePause failed — sandbox stays 'pausing' for reconciliation")
			return
		}
		// Recorded once the row says paused: a finalize the reconciler has
		// to redo must not leave two success entries for one pause.
		h.logSandboxActivity(finalizeCtx, sandboxID, teamID, actorID, "sandbox", "paused", "success", &sandbox.Name, nil, nil)
		h.captureFor(actorID, teamID, "sandbox_paused", map[string]any{"sandbox_id": sandboxID.String()})
	})
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
