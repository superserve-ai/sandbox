package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/analytics"
	"github.com/superserve-ai/sandbox/internal/auth"
	"github.com/superserve-ai/sandbox/internal/authz"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/secrets"
	"github.com/superserve-ai/sandbox/internal/sentrylog"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

// VMDClient is the interface for talking to a VM daemon.
type VMDClient = vmdclient.Client

// SQLSTATE raised by the sandbox_quota_on_insert trigger.
const sandboxQuotaErrCode = "SS001"

func isSandboxQuotaErr(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == sandboxQuotaErrCode
}

// respondQuotaExceeded best-effort fetches the team's cap for the message;
// falls back to a generic phrasing if GetTeam errs.
func (h *Handlers) respondQuotaExceeded(c *gin.Context, teamID uuid.UUID) {
	msg := "team has reached its sandbox limit; delete some or contact support@superserve.ai for higher"
	if team, err := h.DB.GetTeam(c.Request.Context(), teamID); err == nil {
		msg = fmt.Sprintf("team has reached the limit of %d sandboxes; delete some or contact support@superserve.ai for higher", team.MaxSandboxes)
	}
	respondErrorMsg(c, "too_many_sandboxes", msg, http.StatusTooManyRequests)
}

// Scheduler selects a host for new sandboxes.
type Scheduler interface {
	SelectHost(ctx context.Context) (hostID string, err error)
	// Invalidate drops any cached host state so the next SelectHost
	// reflects host status changes immediately.
	Invalidate()
}

// HostRegistry resolves a host ID to a VMD client.
type HostRegistry interface {
	ClientFor(ctx context.Context, hostID string) (vmdclient.Client, error)
}

// Handlers holds shared dependencies for all route handlers.
type Handlers struct {
	VMD       VMDClient // default VMD client (used when Hosts is nil or host lookup fails on legacy sandboxes)
	DB        *db.Queries
	Pool      *pgxpool.Pool // required by paths that need their own transaction (e.g. build-concurrency admission)
	Config    *config.Config
	Hosts     HostRegistry      // when set, routes VMD calls via host_id
	Scheduler Scheduler         // when set, picks host on create
	Analytics *analytics.Client // when set, emits product-usage events; nil is a no-op
	Encryptor secrets.Encryptor // KMS envelope used by /secrets endpoints; nil disables them
	Signer    *SecretsSigner    // signs sandbox JWTs and serves the JWKS; nil disables both

	// asyncMu/asyncCond/asyncCount track fire-and-forget bookkeeping goroutines
	// (ActivateSandbox, FinalizePause) so tests can wait for quiescence;
	// production never waits. Not a sync.WaitGroup: concurrent requests Add
	// while a test's Wait is in flight, which WaitGroup forbids once the
	// counter can touch zero mid-wait (the race detector flags the reuse).
	asyncMu    sync.Mutex
	asyncCond  *sync.Cond // lazily created by WaitAsyncBookkeeping, guarded by asyncMu
	asyncCount int

	// authzSvc is a process-lifetime singleton so its permission cache persists
	// across requests. Built lazily from Pool on first use.
	authzOnce sync.Once
	authzSvc  *authz.Service
}

// asyncBookkeeping runs fire-and-forget post-VMD work in a background
// goroutine — bookkeeping DB writes, and the create path's hostname stamp.
// This is off the hot path by design: the gate write (BeginPause/BeginResume/
// create INSERT) already owns the row, and every subsequent transition is
// status-gated, so nothing can proceed until the job lands — a racing request
// just sees the transitional status and 409s until it commits. Work that
// needs that protection must therefore run BEFORE the status flip inside the
// same job, the way the create path orders its stamp before ActivateSandbox.
func (h *Handlers) asyncBookkeeping(name string, fn func()) {
	h.asyncMu.Lock()
	h.asyncCount++
	h.asyncMu.Unlock()
	go func() {
		defer func() {
			h.asyncMu.Lock()
			h.asyncCount--
			if h.asyncCount == 0 && h.asyncCond != nil {
				h.asyncCond.Broadcast()
			}
			h.asyncMu.Unlock()
		}()
		defer sentrylog.Recover(name)
		fn()
	}()
}

// WaitAsyncBookkeeping blocks until no fire-and-forget bookkeeping goroutines
// are in flight. Test-only: lets tests assert post-transition DB state
// deterministically. Unlike WaitGroup.Wait it is safe to call while other
// requests keep spawning bookkeeping work.
func (h *Handlers) WaitAsyncBookkeeping() {
	h.asyncMu.Lock()
	defer h.asyncMu.Unlock()
	if h.asyncCond == nil {
		h.asyncCond = sync.NewCond(&h.asyncMu)
	}
	for h.asyncCount > 0 {
		h.asyncCond.Wait()
	}
}

// capture emits a usage event attributed to the API key's owner and team.
func (h *Handlers) capture(c *gin.Context, event string, props map[string]any) {
	if h.Analytics == nil {
		return
	}
	var actor string
	if a := actorIDFromContext(c); a != nil {
		actor = a.String()
	}
	var team string
	if t, err := teamIDFromContext(c); err == nil {
		team = t.String()
	}
	h.Analytics.Capture(actor, team, event, props)
}

// NewHandlers creates a new Handlers instance.
func NewHandlers(vmd VMDClient, queries *db.Queries, cfg *config.Config) *Handlers {
	return &Handlers{
		VMD:    vmd,
		DB:     queries,
		Config: cfg,
	}
}

func (h *Handlers) authzService() *authz.Service {
	if h == nil || h.Pool == nil {
		return nil
	}
	h.authzOnce.Do(func() {
		h.authzSvc = authz.NewCached(h.Pool)
	})
	return h.authzSvc
}

// vmdForHost returns the VMDClient for the given host. When a registry is
// configured, it resolves via DB lookup. If the lookup fails because the host
// row is missing (legacy sandbox with a backfilled host_id whose row is gone),
// falls back to the default VMD client so existing sandboxes keep working
// during the migration period. Any other error is surfaced.
func (h *Handlers) vmdForHost(ctx context.Context, hostID string) (VMDClient, error) {
	if h.Hosts == nil {
		return h.VMD, nil
	}
	c, err := h.Hosts.ClientFor(ctx, hostID)
	if err == nil {
		return c, nil
	}
	if errors.Is(err, pgx.ErrNoRows) && h.VMD != nil {
		log.Warn().Err(err).Str("host_id", hostID).Msg("unknown host row; falling back to default VMD client")
		return h.VMD, nil
	}
	return nil, err
}

// vmdTimeout is the default deadline for VMD gRPC calls.
const vmdTimeout = 30 * time.Second

// retryTransientBoot runs one vmd boot call under vmdTimeout and, when the
// attempt dies on a transient — DeadlineExceeded, or Unavailable that
// outlived the dial-site interceptor's window — with the caller's context
// still alive, runs exactly one more under a fresh vmdTimeout; worst case
// 2×vmdTimeout for a caller that waits (the API LB's backend timeout is
// sized above that envelope). The daemon serializes same-ID boots and
// recognizes a completed prior attempt, so the retry either adopts the VM
// the first attempt brought up or boots cleanly — never a double boot; at
// most one retry per boot and the daemon's restore semaphore bound the
// added load. A dead caller skips the retry: a boot landing after the
// client gave up would activate a sandbox the caller believes failed.
// (pauseWithRetry deliberately differs on both points — any-error retry,
// detached context — because a late pause reconciles state instead of
// surprising the caller.)
func retryTransientBoot(parent context.Context, sandboxID string, boot func(context.Context) (string, uint32, uint32, error)) (ip string, vcpu, memMiB uint32, retried bool, err error) {
	attempt := func() (string, uint32, uint32, error) {
		ctx, cancel := context.WithTimeout(parent, vmdTimeout)
		defer cancel()
		return boot(ctx)
	}
	ip, vcpu, memMiB, err = attempt()
	if err == nil || !(isVMDDeadline(err) || isVMDUnavailable(err)) || parent.Err() != nil {
		return ip, vcpu, memMiB, false, err
	}
	log.Warn().Str("sandbox_id", sandboxID).Msg("vmd boot hit a transient — retrying once")
	ip, vcpu, memMiB, err = attempt()
	return ip, vcpu, memMiB, true, err
}

// asyncTimeout is the deadline for fire-and-forget DB writes.
const asyncTimeout = 5 * time.Second

// activateSettleWindow bounds how long status-gated read paths wait for the
// fire-and-forget activate write to land. Create/resume respond before the
// starting/resuming→active flip commits, so the owner's immediate follow-up
// (create then exec — the canonical SDK flow) may read the pre-flip status;
// waiting briefly preserves read-your-writes instead of 409ing it. Normally
// the write lands in single-digit ms, but a hostname-only create's stamp runs
// before the flip and its guest round trip is bounded by the boxd client's
// timeout — the window must outlast that bound, or a slow-but-alive guest
// turns the canonical follow-up into a 409. A genuinely lost write still 409s
// once the window expires. Var, not const, so tests can shrink it.
var activateSettleWindow = 6 * time.Second

// activateSettlePoll is the re-read interval within activateSettleWindow.
const activateSettlePoll = 50 * time.Millisecond

// staleTransitionGrace is how long a sandbox must sit in a transitional state
// (starting/resuming/pausing) before DELETE may claim it: past this, its worker
// is provably gone (every VMD call caps at vmdTimeout and a live worker reverts),
// so deleting it cannot race a live resume/pause.
const staleTransitionGrace = 15 * time.Minute

// logSandboxActivity writes a sandbox-scoped activity record in a background
// goroutine. The request context is stripped of cancellation via
// context.WithoutCancel so the goroutine is not killed when the HTTP response
// completes, but the trace/span context is kept so the async write appears in
// the same request trace as the synchronous work.
func (h *Handlers) logSandboxActivity(reqCtx context.Context, sandboxID, teamID uuid.UUID, actorID *uuid.UUID, category, action, status string, sandboxName *string, durationMs *int32, metadata []byte) {
	asyncCtx := context.WithoutCancel(reqCtx)
	go func() {
		defer sentrylog.Recover("activity-log")
		ctx, cancel := context.WithTimeout(asyncCtx, asyncTimeout)
		defer cancel()
		_, err := h.DB.CreateActivity(ctx, db.CreateActivityParams{
			SandboxID:    pgtype.UUID{Bytes: sandboxID, Valid: true},
			ResourceType: "sandbox",
			TeamID:       teamID,
			ActorID:      actorUUID(actorID),
			Category:     category,
			Action:       action,
			Status:       &status,
			SandboxName:  sandboxName,
			DurationMs:   durationMs,
			Metadata:     metadata,
		})
		if err != nil {
			log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msgf("async %s/%s activity log failed", category, action)
		}
	}()
}

// logSecretActivity writes a secret-scoped activity record. secretName is a
// denormalized snapshot stored at write time so the row stays readable even
// after the underlying secret is hard-deleted.
func (h *Handlers) logSecretActivity(reqCtx context.Context, secretID, teamID uuid.UUID, actorID *uuid.UUID, action, status, secretName string, metadata []byte) {
	asyncCtx := context.WithoutCancel(reqCtx)
	go func() {
		defer sentrylog.Recover("secret-activity-log")
		ctx, cancel := context.WithTimeout(asyncCtx, asyncTimeout)
		defer cancel()
		_, err := h.DB.CreateActivity(ctx, db.CreateActivityParams{
			SecretID:     pgtype.UUID{Bytes: secretID, Valid: true},
			SecretName:   &secretName,
			ResourceType: "secret",
			TeamID:       teamID,
			ActorID:      actorUUID(actorID),
			Category:     "secret",
			Action:       action,
			Status:       &status,
			Metadata:     metadata,
		})
		if err != nil {
			log.Error().Err(err).Str("secret_id", secretID.String()).Msgf("async secret/%s activity log failed", action)
		}
	}()
}

// logTemplateActivity writes a template-scoped activity record. Same async
// semantics as logSandboxActivity.
func (h *Handlers) logTemplateActivity(reqCtx context.Context, templateID, teamID uuid.UUID, actorID *uuid.UUID, category, action, status string, metadata []byte) {
	asyncCtx := context.WithoutCancel(reqCtx)
	go func() {
		defer sentrylog.Recover("template-activity-log")
		ctx, cancel := context.WithTimeout(asyncCtx, asyncTimeout)
		defer cancel()
		_, err := h.DB.CreateActivity(ctx, db.CreateActivityParams{
			TemplateID:   pgtype.UUID{Bytes: templateID, Valid: true},
			ResourceType: "template",
			TeamID:       teamID,
			ActorID:      actorUUID(actorID),
			Category:     category,
			Action:       action,
			Status:       &status,
			Metadata:     metadata,
		})
		if err != nil {
			log.Error().Err(err).Str("template_id", templateID.String()).Msgf("async %s/%s activity log failed", category, action)
		}
	}()
}

func actorUUID(actorID *uuid.UUID) pgtype.UUID {
	if actorID == nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: *actorID, Valid: true}
}

// openSandboxInterval records the start of an active period in
// sandbox_active_interval. Called when a sandbox transitions into 'active'
// (created or resumed). Run synchronously rather than in a goroutine so the
// DB-side partial unique index on open rows is the single arbiter of
// per-sandbox open/close ordering; an async goroutine could race a quickly-
// following close. Cancellation is stripped from reqCtx so a client
// disconnect after the status update can't leave us with an active sandbox
// and no open interval row. Best-effort: failures are logged but do not
// fail the request — losing an interval row degrades metrics, not the user
// flow.
func (h *Handlers) openSandboxInterval(reqCtx context.Context, sandboxID, teamID uuid.UUID, actorID *uuid.UUID) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(reqCtx), asyncTimeout)
	defer cancel()
	if err := h.DB.OpenSandboxActiveInterval(ctx, db.OpenSandboxActiveIntervalParams{
		SandboxID: sandboxID,
		TeamID:    teamID,
		ActorID:   actorUUID(actorID),
	}); err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("open sandbox_active_interval failed")
	}
}

// openSandboxIntervalInheritActor opens an interval after a system-initiated
// revert (e.g. reaper's pause-then-rollback) where the original actor was
// lost. Looks up the most recently closed interval's actor and uses it as
// the new open's actor_id; this keeps the sandbox contributing to WAU
// across a brief outage instead of getting dropped by the view's "actor_id
// IS NOT NULL" filter. Falls back to NULL if no prior closed interval
// exists.
//
// Only the reaper revert paths use this. The user-facing handler paths
// always have an explicit actor from the request context, so they call
// openSandboxInterval directly.
func (h *Handlers) openSandboxIntervalInheritActor(reqCtx context.Context, sandboxID, teamID uuid.UUID) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(reqCtx), asyncTimeout)
	defer cancel()
	var actorID *uuid.UUID
	if prior, err := h.DB.GetMostRecentClosedSandboxIntervalActor(ctx, sandboxID); err == nil && prior.Valid {
		a := uuid.UUID(prior.Bytes)
		actorID = &a
	}
	if err := h.DB.OpenSandboxActiveInterval(ctx, db.OpenSandboxActiveIntervalParams{
		SandboxID: sandboxID,
		TeamID:    teamID,
		ActorID:   actorUUID(actorID),
	}); err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("open sandbox_active_interval (inherit) failed")
	}
}

// closeSandboxInterval closes the currently-open interval for a sandbox.
// reason is one of paused / timeout_paused / deleted / failed. Idempotent:
// if no interval is open (e.g. delete-after-pause), the UPDATE matches zero
// rows and the call is a no-op — this is what prevents a long paused
// window from being counted as active time. Cancellation and best-effort
// semantics match openSandboxInterval.
func (h *Handlers) closeSandboxInterval(reqCtx context.Context, sandboxID uuid.UUID, reason string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(reqCtx), asyncTimeout)
	defer cancel()
	if err := h.DB.CloseSandboxActiveInterval(ctx, db.CloseSandboxActiveIntervalParams{
		SandboxID: sandboxID,
		EndReason: reason,
	}); err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Str("reason", reason).Msg("close sandbox_active_interval failed")
	}
}

// loadActiveSandbox fetches a sandbox by ID, verifies team ownership, and
// requires that it is in the `active` state. Non-active sandboxes (paused,
// pausing, failed, etc.) are rejected — callers must resume the sandbox
// explicitly via POST /sandboxes/:id/resume before operating on it.
//
// On any error path this writes the response and returns nil; the caller
// should simply return. On success it returns the loaded sandbox.
func (h *Handlers) loadActiveSandbox(c *gin.Context) *db.Sandbox {
	sandboxID, err := parseSandboxID(c)
	if err != nil {
		return nil
	}
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return nil
	}
	sandbox, err := h.DB.GetSandbox(c.Request.Context(), db.GetSandboxParams{
		ID:     sandboxID,
		TeamID: teamID,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			respondError(c, ErrSandboxNotFound)
		} else {
			log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB GetSandbox failed")
			respondError(c, ErrInternal)
		}
		return nil
	}
	if sandbox.Status != db.SandboxStatusActive {
		respondError(c, ErrInvalidState)
		return nil
	}
	return &sandbox
}

// loadActiveOrResumeSandbox is like loadActiveSandbox but auto-resumes a
// paused sandbox, and waits out the activate settle window on a
// starting/resuming row before giving up. Any other non-active state
// returns 409.
func (h *Handlers) loadActiveOrResumeSandbox(c *gin.Context) *db.Sandbox {
	sandboxID, err := parseSandboxID(c)
	if err != nil {
		return nil
	}
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return nil
	}
	deadline := time.Now().Add(activateSettleWindow)
	for {
		sandbox, err := h.DB.GetSandbox(c.Request.Context(), db.GetSandboxParams{
			ID:     sandboxID,
			TeamID: teamID,
		})
		if err != nil {
			if err == pgx.ErrNoRows {
				respondError(c, ErrSandboxNotFound)
			} else {
				log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB GetSandbox failed")
				respondError(c, ErrInternal)
			}
			return nil
		}
		switch sandbox.Status {
		case db.SandboxStatusActive:
			return &sandbox
		case db.SandboxStatusPaused:
			if !h.resumePausedSandbox(c, &sandbox, teamID) {
				return nil
			}
			sandbox.Status = db.SandboxStatusActive
			return &sandbox
		case db.SandboxStatusStarting, db.SandboxStatusResuming:
			// Likely the fire-and-forget activate write in flight (or a
			// concurrent create/resume finishing); wait for the flip
			// rather than 409 the owner's own follow-up.
			if time.Now().Before(deadline) {
				time.Sleep(activateSettlePoll)
				continue
			}
			respondError(c, ErrInvalidState)
			return nil
		default:
			respondError(c, ErrInvalidState)
			return nil
		}
	}
}

// resumePausedSandbox restores the VM, reapplies network config, and flips
// the sandbox to active. Starts with an atomic paused→resuming DB claim so
// concurrent resumes don't both call VMD; the loser gets 409. On any failure
// after VMD resume succeeds, destroys the VM + reverts to paused.
func (h *Handlers) resumePausedSandbox(c *gin.Context, sandbox *db.Sandbox, teamID uuid.UUID) bool {
	sandboxID := sandbox.ID

	if !sandbox.SnapshotID.Valid {
		log.Error().Str("sandbox_id", sandboxID.String()).Msg("paused sandbox has no snapshot_id")
		respondError(c, ErrInternal)
		return false
	}

	// Serialize the paused→resuming claim with attach/detach via a DB advisory
	// lock (held only for the claim). Both take the same lock and re-read status
	// under it, so across API instances a mutation can't read a stale 'paused' and
	// land a binding this resume won't pick up. Once the claim flips status to
	// 'resuming', those handlers see it under the lock and reject with 409.
	claimResume := func(q *db.Queries) (db.Sandbox, error) {
		if h.Pool != nil {
			if lerr := q.LockSandboxForSecretWrites(c.Request.Context(), sandboxID.String()); lerr != nil {
				return db.Sandbox{}, lerr
			}
		}
		return q.BeginResume(c.Request.Context(), db.BeginResumeParams{ID: sandboxID, TeamID: teamID})
	}
	var (
		claimed db.Sandbox
		err     error
	)
	if h.Pool == nil {
		claimed, err = claimResume(h.DB)
	} else {
		var tx pgx.Tx
		if tx, err = h.Pool.Begin(c.Request.Context()); err == nil {
			defer tx.Rollback(c.Request.Context())
			if claimed, err = claimResume(h.DB.WithTx(tx)); err == nil {
				err = tx.Commit(c.Request.Context())
			}
		}
	}
	if err != nil {
		if err == pgx.ErrNoRows {
			// Someone else is already resuming, or the sandbox is no longer
			// in paused state. Surface as conflict; client retries.
			respondError(c, ErrInvalidState)
			return false
		}
		if isSandboxQuotaErr(err) {
			// Resuming re-enters the active set; the team is already at its limit.
			h.respondQuotaExceeded(c, teamID)
			return false
		}
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB BeginResume failed")
		respondError(c, ErrInternal)
		return false
	}
	*sandbox = claimed

	revertCtx := context.WithoutCancel(c.Request.Context())
	revertToPaused := func() {
		rctx, rcancel := context.WithTimeout(revertCtx, asyncTimeout)
		defer rcancel()
		if err := h.DB.RevertResumeToPaused(rctx, db.RevertResumeToPausedParams{
			ID:     sandboxID,
			TeamID: teamID,
		}); err != nil {
			log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("RevertResumeToPaused failed — sandbox may be stuck in 'resuming'")
		}
	}

	snapshot, err := h.DB.GetSnapshot(c.Request.Context(), db.GetSnapshotParams{
		ID:     sandbox.SnapshotID.Bytes,
		TeamID: teamID,
	})
	if err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB GetSnapshot failed")
		revertToPaused()
		respondError(c, ErrInternal)
		return false
	}

	snapshotPath := snapshot.Path
	memPath := resolveMemPath(snapshot)

	// Overlay-mode sandboxes need basePath for the mount-namespace symlink.
	// Read sandbox.base_path first (pinned at create) so a template rebuild
	// can't shift base.ext4 under us; fall back to template for legacy rows.
	var resumeBasePath string
	if sandbox.BasePath != nil {
		resumeBasePath = *sandbox.BasePath
	} else if sandbox.TemplateID.Valid {
		tpl, tplErr := h.DB.GetTemplateForOwner(c.Request.Context(), db.GetTemplateForOwnerParams{
			ID:     sandbox.TemplateID.Bytes,
			TeamID: teamID,
		})
		if tplErr == nil && tpl.BasePath != nil {
			resumeBasePath = *tpl.BasePath
		}
	}

	vmd, vmdLookupErr := h.vmdForHost(c.Request.Context(), sandbox.HostID)
	if vmdLookupErr != nil {
		log.Error().Err(vmdLookupErr).Str("sandbox_id", sandboxID.String()).Msg("resolve VMD for resume failed")
		revertToPaused()
		respondError(c, ErrInternal)
		return false
	}

	// The snapshot carries the agent's HTTPS_PROXY (with its JWT) and stand-in
	// tokens as they were at pause; the current binding set is re-applied below
	// once the VM is up, so a mutation made while paused takes effect.
	//
	// One clock for the whole boot sequence: ResumeInstance, its deadline
	// retry, and the stateless fallback all draw down the same 2×vmdTimeout
	// budget, so a resume holds the row mid-transition for a bounded window
	// no matter which path it walks.
	bootCtx, bootCancel := context.WithTimeout(c.Request.Context(), 2*vmdTimeout)
	defer bootCancel()
	ipAddress, actualVcpu, actualMemMiB, _, err := retryTransientBoot(bootCtx, sandboxID.String(), func(ctx context.Context) (string, uint32, uint32, error) {
		return vmd.ResumeInstance(ctx, sandboxID.String(), snapshotPath, memPath)
	})
	if err != nil {
		if isVMDNotFound(err) {
			log.Warn().Err(err).Str("sandbox_id", sandboxID.String()).
				Msg("VMD ResumeInstance: VM not in map, falling back to stateless RestoreSnapshot")
			// RestoreSnapshot takes an optional envVars map; we pass nil here
			// because resume is supposed to preserve whatever envs the sandbox
			// already has baked into the snapshot — not inject new ones.
			// Single attempt under whatever remains of the sequence budget:
			// the fallback is already the second recovery layer.
			fctx, fcancel := context.WithTimeout(bootCtx, vmdTimeout)
			ipAddress, actualVcpu, actualMemMiB, err = vmd.RestoreSnapshot(fctx, sandboxID.String(), snapshotPath, memPath, resumeBasePath, "", sandbox.TeamID.String(), ownerIDFromContext(c), nil)
			fcancel()
			if err != nil {
				log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("VMD RestoreSnapshot fallback failed")
				// Deliberately no destroy for a boot that may land late: the
				// row reverts to paused, so a follow-up resume on this ID
				// adopts the live VM (instant resume), and the reconciler
				// reaps the paused-row/active-VM state if no retry comes.
				revertToPaused()
				respondError(c, ErrInternal)
				return false
			}
		} else {
			log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("VMD ResumeInstance failed")
			// Same deliberate no-destroy as the fallback branch above.
			revertToPaused()
			respondError(c, ErrInternal)
			return false
		}
	}

	// Older vmd builds may return 0 for vcpu/mem on both the Resume and
	// Restore paths (ResourceLimits field was added later). Fall back to
	// the sandbox row's existing values so ActivateSandbox doesn't
	// overwrite them with 0 and trip the sandbox_memory_positive CHECK.
	if actualVcpu == 0 {
		actualVcpu = uint32(sandbox.VcpuCount)
	}
	if actualMemMiB == 0 {
		actualMemMiB = uint32(sandbox.MemoryMib)
	}

	// Detach from cancellation so a client disconnect can't leave the sandbox
	// marked paused while the VM is up. Keep the trace/span context.
	postCtx, postCancel := context.WithTimeout(context.WithoutCancel(c.Request.Context()), vmdTimeout)
	defer postCancel()

	var ipAddr *netip.Addr
	if ipAddress != "" {
		if addr, parseErr := netip.ParseAddr(ipAddress); parseErr == nil {
			ipAddr = &addr
		}
	}

	// Once the VM is up, a failed finalize step must NOT destroy it —
	// DestroyInstance deletes the overlay (the sandbox's disk). Re-pause
	// instead: snapshotting preserves the overlay and returns it to a clean,
	// resumable 'paused' state. Prefer leak over loss.
	pauseAndRevert := func() {
		pctx, pcancel := context.WithTimeout(revertCtx, vmdTimeout)
		snapPath, memPath, perr := vmd.PauseInstance(pctx, sandboxID.String(), "")
		pcancel()
		if perr != nil {
			// VM unreachable — nothing to preserve; mark failed rather than
			// wedge in 'resuming' (the CTE also closes any open interval).
			log.Error().Err(perr).Str("sandbox_id", sandboxID.String()).Msg("resume revert: PauseInstance failed, marking sandbox failed")
			h.markSandboxFailedAsync(revertCtx, sandboxID, teamID, sandbox.HostID)
			return
		}
		// Fresh deadline so a slow snapshot above can't starve the DB write.
		// Overlay preserved; flip resuming → paused via FinalizePause.
		fctx, fcancel := context.WithTimeout(revertCtx, vmdTimeout)
		defer fcancel()
		if _, ferr := h.DB.FinalizePause(fctx, db.FinalizePauseParams{
			ID:        sandboxID,
			TeamID:    teamID,
			Path:      snapPath,
			MemPath:   &memPath,
			SizeBytes: 0, // snapshot size isn't tracked for pauses (matches PauseSandbox)
			Trigger:   "resume_revert",
		}); ferr != nil {
			// VM is safely paused; only bookkeeping failed. Best-effort status
			// flip — the reconciler is the backstop.
			log.Error().Err(ferr).Str("sandbox_id", sandboxID.String()).Msg("resume revert: FinalizePause failed, best-effort revert to paused")
			revertToPaused()
		}
	}

	// Apply egress rules before committing to 'active' so "active ⇒ rules
	// applied" holds by construction.
	if err := h.reapplyNetworkConfig(postCtx, vmd, sandboxID.String(), sandbox.NetworkConfig); err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("reapply network config on resume failed")
		pauseAndRevert()
		respondError(c, ErrInternal)
		return false
	}

	// Re-apply the current binding set before committing to 'active', so a secret
	// attached or detached while paused takes effect — the snapshot froze the old
	// JWT. Skipped when there are no bindings, keeping the secret-less resume a
	// single round trip. The fresh IP binds the re-minted JWT.
	sandbox.IpAddress = ipAddr
	if meta, merr := h.loadSecretBindingMeta(postCtx, sandboxID); merr != nil {
		log.Error().Err(merr).Str("sandbox_id", sandboxID.String()).Msg("load secret bindings on resume failed")
		pauseAndRevert()
		respondError(c, ErrInternal)
		return false
	} else if len(meta) > 0 {
		if aerr := h.applySecretBindings(postCtx, *sandbox, meta); aerr != nil {
			log.Error().Err(aerr).Str("sandbox_id", sandboxID.String()).Msg("reapply secret bindings on resume failed")
			pauseAndRevert()
			respondError(c, ErrInternal)
			return false
		}
	}

	// Fire-and-forget: the resuming→active bookkeeping write is off the hot
	// path. BeginResume's claim owns the row and every other transition is
	// status-gated, so a racing pause/resume sees 'resuming' and 409s until
	// this lands. On failure, re-pause in the background (overlay preserved);
	// the client already holds a success response and the next request
	// auto-resumes from the snapshot. Capture actor before the goroutine —
	// gin.Context is recycled after ServeHTTP returns.
	actorID := actorUUID(actorIDFromContext(c))
	h.asyncBookkeeping("activate-sandbox", func() {
		actx, acancel := context.WithTimeout(revertCtx, asyncTimeout)
		defer acancel()
		if err := h.DB.ActivateSandbox(actx, db.ActivateSandboxParams{
			ID:        sandboxID,
			VcpuCount: int32(actualVcpu),
			MemoryMib: int32(actualMemMiB),
			IpAddress: ipAddr,
			TeamID:    teamID,
			ActorID:   actorID,
		}); err != nil {
			log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("async DB ActivateSandbox failed — re-pausing")
			pauseAndRevert()
		}
	})

	sandbox.VcpuCount = int32(actualVcpu)
	sandbox.MemoryMib = int32(actualMemMiB)
	sandbox.IpAddress = ipAddr

	// ActivateSandbox's CTE opens the sandbox_active_interval row (async).
	h.logSandboxActivity(c.Request.Context(), sandboxID, teamID, actorIDFromContext(c), "sandbox", "resumed", "success", &sandbox.Name, nil, nil)
	h.capture(c, "sandbox_resumed", map[string]any{"sandbox_id": sandboxID.String()})
	return true
}

// resolveMemPath returns the memory snapshot path from a Snapshot record.
// Uses the stored mem_path column if set, otherwise falls back to the
// convention of placing mem.snap alongside the vmstate snapshot.
func resolveMemPath(snap db.Snapshot) string {
	if snap.MemPath != nil && *snap.MemPath != "" {
		return *snap.MemPath
	}
	return filepath.Join(filepath.Dir(snap.Path), "mem.snap")
}

// persistedEgressConfig mirrors the jsonb shape stored in sandbox.network_config.
type persistedEgressConfig struct {
	Egress struct {
		AllowedCIDRs   []string `json:"allowed_cidrs"`
		DeniedCIDRs    []string `json:"denied_cidrs"`
		AllowedDomains []string `json:"allowed_domains"`
	} `json:"egress"`
}

// egressConfigJSON splits the request's egress entries into CIDRs and domains
// and marshals the network_config jsonb shape persisted on the sandbox row.
func egressConfigJSON(network *networkConfigRequest) (allowedCIDRs, allowedDomains []string, raw []byte) {
	for _, entry := range network.AllowOut {
		if isIPOrCIDR(entry) {
			allowedCIDRs = append(allowedCIDRs, entry)
		} else {
			allowedDomains = append(allowedDomains, entry)
		}
	}
	raw, _ = json.Marshal(map[string]any{
		"egress": map[string]any{
			"allowed_cidrs":   allowedCIDRs,
			"denied_cidrs":    network.DenyOut,
			"allowed_domains": allowedDomains,
		},
	})
	return allowedCIDRs, allowedDomains, raw
}

// reapplyNetworkConfig reads the sandbox's persisted egress config and pushes
// it to VMD. Called after every snapshot restore (explicit /resume, auto-resume
// via /exec, and CreateSandbox's from-snapshot path) because nftables rules
// and proxy state are fresh after restore.
//
// Silently returns nil if there is no persisted config (default allow-all).
func (h *Handlers) reapplyNetworkConfig(ctx context.Context, vmd VMDClient, sandboxID string, raw []byte) error {
	if len(raw) == 0 {
		return nil
	}

	var cfg persistedEgressConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("parse persisted network_config: %w", err)
	}

	if len(cfg.Egress.AllowedCIDRs) == 0 &&
		len(cfg.Egress.DeniedCIDRs) == 0 &&
		len(cfg.Egress.AllowedDomains) == 0 {
		return nil
	}

	return vmd.UpdateSandboxNetwork(ctx, sandboxID,
		cfg.Egress.AllowedCIDRs,
		cfg.Egress.DeniedCIDRs,
		cfg.Egress.AllowedDomains,
	)
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

func (h *Handlers) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"version": "0.1.0",
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func parseSandboxID(c *gin.Context) (uuid.UUID, error) {
	raw := c.Param("sandbox_id")
	id, err := parsePublicSandboxID(raw)
	if err != nil {
		respondErrorMsg(c, "bad_request",
			fmt.Sprintf("Invalid sandbox_id: %q is not a valid sandbox ID", raw),
			http.StatusBadRequest)
		return uuid.Nil, err
	}
	return id, nil
}

func teamIDFromContext(c *gin.Context) (uuid.UUID, error) {
	raw, _ := c.Get("team_id")
	s, ok := raw.(string)
	if !ok || s == "" {
		respondError(c, ErrUnauthorized)
		return uuid.Nil, fmt.Errorf("missing team_id")
	}
	id, err := uuid.Parse(s)
	if err != nil {
		respondError(c, ErrUnauthorized)
		return uuid.Nil, err
	}
	return id, nil
}

func actorIDFromContext(c *gin.Context) *uuid.UUID {
	raw, ok := c.Get("actor_id")
	if !ok {
		return nil
	}
	id, ok := raw.(uuid.UUID)
	if !ok {
		return nil
	}
	return &id
}

// ownerIDFromContext returns the actor's UUID as a string, or "" when unknown.
func ownerIDFromContext(c *gin.Context) string {
	if a := actorIDFromContext(c); a != nil {
		return a.String()
	}
	return ""
}

// ---------------------------------------------------------------------------
// Sandbox lifecycle
// ---------------------------------------------------------------------------

// ActivateSandbox returns the sandbox payload + a fresh access token,
// transparently resuming the VM if it was paused. Idempotent on active
// sandboxes. Transitional states (pausing, resuming, failed) → 409.
func (h *Handlers) ActivateSandbox(c *gin.Context) {
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}
	if !h.requireTeamSandboxWrite(c, teamID) {
		return
	}

	sandbox := h.loadActiveOrResumeSandbox(c)
	if sandbox == nil {
		return
	}
	c.JSON(http.StatusOK, h.sandboxToResponseWithToken(*sandbox))
}

func (h *Handlers) ResumeSandbox(c *gin.Context) {
	sandboxID, err := parseSandboxID(c)
	if err != nil {
		return
	}

	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}
	if !h.requireTeamSandboxWrite(c, teamID) {
		return
	}

	sandbox, err := h.DB.GetSandbox(c.Request.Context(), db.GetSandboxParams{
		ID:     sandboxID,
		TeamID: teamID,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			respondError(c, ErrSandboxNotFound)
			return
		}
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB GetSandbox failed")
		respondError(c, ErrInternal)
		return
	}
	SetTelemetryHostID(c, sandbox.HostID)

	if sandbox.Status != db.SandboxStatusPaused {
		respondError(c, ErrInvalidState)
		return
	}

	if !h.resumePausedSandbox(c, &sandbox, teamID) {
		return
	}

	resp := gin.H{
		// Public form — clients refresh their stored ID from this response,
		// so a bare UUID here would strand them off the tagged scheme.
		"id":     formatSandboxID(sandboxID),
		"status": string(db.SandboxStatusActive),
	}
	if h.Config != nil && h.Config.SandboxAccessTokenSeed != nil {
		// The token HMAC stays keyed on the bare UUID: the proxy normalizes
		// public IDs before verification.
		resp["access_token"] = auth.ComputeAccessToken(h.Config.SandboxAccessTokenSeed, sandboxID.String())
	}
	c.JSON(http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// Sandbox CRUD
// ---------------------------------------------------------------------------

func (h *Handlers) DeleteSandbox(c *gin.Context) {
	sandboxID, err := parseSandboxID(c)
	if err != nil {
		return
	}

	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}
	if !h.requireTeamSandboxWrite(c, teamID) {
		return
	}

	// Verify sandbox exists and belongs to this team.
	sandbox, err := h.DB.GetSandbox(c.Request.Context(), db.GetSandboxParams{
		ID:     sandboxID,
		TeamID: teamID,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			respondError(c, ErrSandboxNotFound)
			return
		}
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB GetSandbox failed")
		respondError(c, ErrInternal)
		return
	}

	SetTelemetryHostID(c, sandbox.HostID)
	// Claim the sandbox for deletion atomically. The guarded soft-delete fires
	// from a quiescent state (active/paused/failed) or a transitional state whose
	// worker is provably gone (stale), so it serializes against a live resume/pause
	// — this CAS and resume's BeginResume cannot both win the same row — while still
	// letting a crash-wedged sandbox be deleted. The same statement writes the
	// revocation row, so a crash before teardown can't leave a live VM with a valid JWT.
	if _, err := h.DB.DestroySandbox(c.Request.Context(), db.DestroySandboxParams{
		ID:                      sandboxID,
		TeamID:                  teamID,
		RevocationExpiresAt:     time.Now().Add(SecretsJWTLifetime),
		StaleTransitionalBefore: time.Now().Add(-staleTransitionGrace),
	}); err != nil {
		if err == pgx.ErrNoRows {
			// Not claimable from its current state. Re-read to tell a
			// just-completed delete (idempotent) from a transitional state
			// (resuming/pausing/starting) the caller should retry.
			cur, gerr := h.DB.GetSandbox(c.Request.Context(), db.GetSandboxParams{ID: sandboxID, TeamID: teamID})
			switch {
			case gerr == pgx.ErrNoRows:
				c.Status(http.StatusNoContent)
			case gerr != nil:
				log.Error().Err(gerr).Str("sandbox_id", sandboxID.String()).Msg("DB GetSandbox re-read failed")
				respondError(c, ErrInternal)
			default:
				log.Warn().Str("sandbox_id", sandboxID.String()).Str("status", string(cur.Status)).Msg("delete deferred: sandbox is mid-transition")
				respondError(c, ErrInvalidState)
			}
			return
		}
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB DestroySandbox failed")
		respondError(c, ErrInternal)
		return
	}

	h.teardownDestroyedSandbox(c.Request.Context(), sandboxID, sandbox.HostID, sandbox.BasePath, sandbox.TemplateID)

	// DestroySandbox's CTE atomically closed the open sandbox_active_interval row.
	h.logSandboxActivity(c.Request.Context(), sandboxID, teamID, actorIDFromContext(c), "sandbox", "deleted", "success", &sandbox.Name, nil, nil)
	h.capture(c, "sandbox_deleted", map[string]any{"sandbox_id": sandboxID.String()})

	c.Status(http.StatusNoContent)
}

// teardownDestroyedSandbox reclaims host-side state for a sandbox whose
// guarded soft-delete has already committed: the VM (with its run dir and
// netns), pause snapshots, and the per-build artifact dir. Best-effort
// throughout — the vm reconciler backstops anything missed here. Shared by
// user-initiated deletes and the auto-delete reaper so the two paths cannot
// diverge.
func (h *Handlers) teardownDestroyedSandbox(ctx context.Context, sandboxID uuid.UUID, hostID string, basePath *string, templateID pgtype.UUID) {
	// The revocation row is committed with the delete claim; fan it out to the
	// host so the daemon refuses the JWT now. Best-effort — bootstrap re-fans
	// from the persisted row on restart.
	go h.fanoutSandboxRevoke(context.Background(), sandboxID, hostID)

	// Tear down the VM best-effort and unconditionally: a sandbox claimed from a
	// stale transition or a 'failed' state may still hold a VM, run dir, and netns
	// that only DestroyInstance reclaims (an absent VM is an idempotent no-op). A
	// failure here is reconciled by the vm reconciler, so a vmd hiccup must not fail
	// an already-committed delete.
	if vmd, lookupErr := h.vmdForHost(ctx, hostID); lookupErr != nil {
		log.Warn().Err(lookupErr).Str("sandbox_id", sandboxID.String()).Msg("resolve VMD for delete teardown; reconciler will reclaim")
	} else {
		vmdCtx, vmdCancel := context.WithTimeout(ctx, vmdTimeout)
		if derr := vmd.DestroyInstance(vmdCtx, sandboxID.String(), true); derr != nil && !isVMDNotFound(derr) {
			log.Warn().Err(derr).Str("sandbox_id", sandboxID.String()).Msg("VMD DestroyInstance for delete teardown; reconciler will reclaim")
		}
		vmdCancel()
	}

	// Best-effort cleanup of pause snapshots. Failures are logged but
	// don't fail the delete — manual cleanup may be required if vmd was
	// unreachable.
	h.cleanupSandboxSnapshots(ctx, sandboxID, hostID)

	// Best-effort GC of the per-build artifact dir if this sandbox was the
	// last reference and the template has since moved to a newer build.
	h.gcOldBuildArtifacts(ctx, hostID, basePath, templateID)
}

// gcOldBuildArtifacts deletes the per-build dir if the just-destroyed sandbox
// at sandboxBasePath was the last reference and the template has moved on.
// Best-effort.
func (h *Handlers) gcOldBuildArtifacts(reqCtx context.Context, hostID string, sandboxBasePath *string, sandboxTemplateID pgtype.UUID) {
	if sandboxBasePath == nil || !sandboxTemplateID.Valid {
		return
	}
	basePath := *sandboxBasePath
	buildID := filepath.Base(filepath.Dir(basePath))
	if buildID == "" || buildID == "." || buildID == string(filepath.Separator) {
		return
	}
	templateID := uuid.UUID(sandboxTemplateID.Bytes).String()

	gcCtx, cancel := context.WithTimeout(reqCtx, 10*time.Second)
	defer cancel()

	refs, err := h.DB.CountActiveSandboxesAtBasePath(gcCtx, &basePath)
	if err != nil {
		log.Warn().Err(err).Str("base_path", basePath).Msg("gc: CountActiveSandboxesAtBasePath")
		return
	}
	if refs > 0 {
		return
	}
	// Team-blind: sandbox's team may not own the template (system templates),
	// so GetTemplateForOwner would falsely report "not in use" → over-delete.
	tplBase, err := h.DB.GetTemplateBasePath(gcCtx, sandboxTemplateID.Bytes)
	if err != nil {
		log.Warn().Err(err).Str("base_path", basePath).Msg("gc: GetTemplateBasePath")
		return
	}
	if tplBase != nil && *tplBase == basePath {
		return
	}

	vmd, err := h.vmdForHost(gcCtx, hostID)
	if err != nil {
		return
	}
	if err := vmd.DeleteBuildArtifacts(gcCtx, templateID, buildID); err != nil {
		log.Warn().Err(err).Str("template_id", templateID).Str("build_id", buildID).Msg("gc: DeleteBuildArtifacts")
	}
}

// cleanupSandboxSnapshots deletes the on-disk snapshot files via vmd and
// the snapshot DB rows for a destroyed sandbox. Best-effort.
func (h *Handlers) cleanupSandboxSnapshots(reqCtx context.Context, sandboxID uuid.UUID, hostID string) {
	// List snapshot rows first: they feed the per-file fallback below and are
	// cleared at the end.
	snaps, err := h.DB.ListSnapshotsBySandbox(reqCtx, sandboxID)
	if err != nil {
		log.Warn().Err(err).Str("sandbox_id", sandboxID.String()).Msg("list snapshots for cleanup")
	}

	// Remove the whole <SnapshotDir>/<id>/ tree path-based, independent of
	// snapshot DB rows — reclaims pause artifacts even when a row is missing.
	// On an old vmd that predates this RPC (control-plane-deploys-first window),
	// fall back to the per-file delete so cleanup still runs. Best-effort;
	// anything missed is left for out-of-band GC.
	if vmd, verr := h.vmdForHost(reqCtx, hostID); verr != nil {
		log.Warn().Err(verr).Str("sandbox_id", sandboxID.String()).Msg("resolve vmd for snapshot cleanup; files may need GC")
	} else {
		ctx, cancel := context.WithTimeout(reqCtx, vmdTimeout)
		switch delErr := vmd.DeleteSandboxSnapshots(ctx, sandboxID.String()); {
		case delErr == nil || isVMDNotFound(delErr):
		case isVMDUnimplemented(delErr):
			for _, s := range snaps {
				memPath := ""
				if s.MemPath != nil {
					memPath = *s.MemPath
				}
				if e := vmd.DeleteSnapshot(ctx, sandboxID.String(), s.Path, memPath); e != nil && !isVMDNotFound(e) {
					log.Warn().Err(e).Str("sandbox_id", sandboxID.String()).Str("snapshot_id", s.ID.String()).Msg("vmd DeleteSnapshot (fallback) failed")
				}
			}
		default:
			log.Warn().Err(delErr).Str("sandbox_id", sandboxID.String()).Msg("vmd DeleteSandboxSnapshots failed; files may need GC")
		}
		cancel()
	}

	// Clear the snapshot DB rows (their files are gone above).
	for _, s := range snaps {
		if delErr := h.DB.DeleteSnapshot(reqCtx, s.ID); delErr != nil {
			log.Warn().Err(delErr).Str("snapshot_id", s.ID.String()).Msg("DB DeleteSnapshot failed")
		}
	}
}

// ---------------------------------------------------------------------------
// Sandbox Create
// ---------------------------------------------------------------------------

type networkConfigRequest struct {
	AllowOut []string `json:"allow_out,omitempty"` // Allowed CIDRs or domains.
	DenyOut  []string `json:"deny_out,omitempty"`  // Denied CIDRs.
}

type createSandboxRequest struct {
	Name         string                `json:"name" binding:"required,min=1,max=64"`
	FromTemplate *string               `json:"from_template,omitempty"`
	Network      *networkConfigRequest `json:"network,omitempty"`

	// TimeoutSeconds auto-pauses the sandbox after it has been active this
	// long. The window tracks the current active session (re-armed on each
	// resume), not creation time. Nil means no timeout — the sandbox lives
	// until explicitly paused or deleted. Settable at create and via PATCH.
	TimeoutSeconds *int32 `json:"timeout_seconds,omitempty"`

	// AutoDeleteSeconds deletes the sandbox once it has been continuously
	// paused this long. Re-arms on every pause, cancelled by resume; 0 means
	// delete as soon as it pauses; nil (default) keeps paused sandboxes
	// forever. Also settable after creation via PATCH /sandboxes/:id.
	AutoDeleteSeconds *int32 `json:"auto_delete_seconds,omitempty"`

	// Metadata is a flat string→string map of user-supplied tags that get
	// attached to the sandbox at creation. Updatable after creation via
	// PATCH /sandboxes/:id. Filterable on GET /sandboxes via metadata.<key>=<value>
	// query params (jsonb @> containment, so all conditions must match).
	//
	// Strings only — no nested objects, numbers, or arrays. This is
	// deliberate: it keeps URL filters unambiguous (no "is 42 the number
	// or the string?" questions) and matches what every other tagging
	// system in this space does (AWS tags, GCE labels, k8s labels).
	//
	// Limits are enforced by validateMetadata: 64 keys, 256-byte keys,
	// 2 KB values, 16 KB total. Keys starting with `superserve.` or
	// `_superserve` are reserved for platform use and rejected.
	Metadata map[string]string `json:"metadata,omitempty"`

	// EnvVars are environment variables injected into every process inside
	// the sandbox (terminal sessions, exec calls). Not stored in the DB —
	// they live in boxd's memory for the sandbox's lifetime and survive
	// pause/resume via snapshot.
	EnvVars map[string]string `json:"env_vars,omitempty"`

	// Secrets binds team-stored credentials to env-var names; the agent sees a
	// per-binding proxy token, swapped for the real value at egress.
	Secrets map[string]string `json:"secrets,omitempty"`
}

type sandboxResponse struct {
	// ID is the public sandbox ID: a bare UUID today, sb-<region>-<uuid>
	// once SANDBOX_ID_REGION is set on the cell (see publicid.go).
	ID                string     `json:"id"`
	Name              string     `json:"name"`
	Status            string     `json:"status"`
	VcpuCount         int32      `json:"vcpu_count"`
	MemoryMib         int32      `json:"memory_mib"`
	AccessToken       string     `json:"access_token,omitempty"`
	SnapshotID        *uuid.UUID `json:"snapshot_id,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	TimeoutSeconds    *int32     `json:"timeout_seconds,omitempty"`
	AutoDeleteSeconds *int32     `json:"auto_delete_seconds,omitempty"`
	// AutoDeleteAt is the concrete deletion deadline. Present only while the
	// sandbox is paused with an auto-delete window configured, so clients can
	// see exactly when the sandbox will be removed.
	AutoDeleteAt *time.Time             `json:"auto_delete_at,omitempty"`
	Network      *networkConfigRequest  `json:"network,omitempty"`
	Metadata     map[string]string      `json:"metadata"`
	Secrets      []sandboxSecretBinding `json:"secrets,omitempty"`
}

// sandboxSecretBinding mirrors one (env_key → secret) binding on a sandbox.
// `revoked` is true when the underlying secret has been soft-deleted —
// the binding row stays but the daemon refuses to swap on use.
type sandboxSecretBinding struct {
	EnvKey     string `json:"env_key"`
	SecretName string `json:"secret_name"`
	Revoked    bool   `json:"revoked,omitempty"`
}

func (h *Handlers) sandboxToResponse(s db.Sandbox) sandboxResponse {
	resp := sandboxResponse{
		ID:        formatSandboxID(s.ID),
		Name:      s.Name,
		Status:    string(s.Status),
		VcpuCount: s.VcpuCount,
		MemoryMib: s.MemoryMib,
		CreatedAt: s.CreatedAt,
		Metadata:  decodeMetadata(s.Metadata),
	}
	if s.SnapshotID.Valid {
		id := uuid.UUID(s.SnapshotID.Bytes)
		resp.SnapshotID = &id
	}
	if s.TimeoutSeconds != nil {
		resp.TimeoutSeconds = s.TimeoutSeconds
	}
	if s.AutoDeleteSeconds != nil {
		resp.AutoDeleteSeconds = s.AutoDeleteSeconds
	}
	if s.AutoDeleteAt.Valid {
		resp.AutoDeleteAt = &s.AutoDeleteAt.Time
	}
	if len(s.NetworkConfig) > 0 {
		var stored struct {
			Egress struct {
				AllowedCIDRs   []string `json:"allowed_cidrs"`
				DeniedCIDRs    []string `json:"denied_cidrs"`
				AllowedDomains []string `json:"allowed_domains"`
			} `json:"egress"`
		}
		if err := json.Unmarshal(s.NetworkConfig, &stored); err == nil {
			e := stored.Egress
			allowOut := append(e.AllowedCIDRs, e.AllowedDomains...)
			if len(allowOut) > 0 || len(e.DeniedCIDRs) > 0 {
				resp.Network = &networkConfigRequest{
					AllowOut: allowOut,
					DenyOut:  e.DeniedCIDRs,
				}
			}
		}
	}
	return resp
}

// sandboxToResponseWithToken is like sandboxToResponse but also computes and
// attaches the per-sandbox access token. Used on create/get/resume where the
// client needs to authenticate subsequent calls; list responses omit it so
// we don't leak many tokens in one response.
func (h *Handlers) sandboxToResponseWithToken(s db.Sandbox) sandboxResponse {
	resp := h.sandboxToResponse(s)
	if h.Config != nil && h.Config.SandboxAccessTokenSeed != nil {
		resp.AccessToken = auth.ComputeAccessToken(h.Config.SandboxAccessTokenSeed, s.ID.String())
	}
	return resp
}

// decodeMetadata unmarshals the jsonb bytes column into a string→string map.
// On any decode error (which should be impossible because the column is
// constrained to objects we wrote ourselves) we return an empty map rather
// than panicking — losing the tags is bad, but failing the whole list/get
// response would be worse. Callers always get a non-nil map so the JSON
// response renders `"metadata": {}` instead of `null` for sandboxes that
// were created without any tags.
func decodeMetadata(raw []byte) map[string]string {
	out := map[string]string{}
	if len(raw) == 0 {
		return out
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		log.Error().Err(err).Msg("decode sandbox metadata jsonb")
		return map[string]string{}
	}
	return out
}

// ---------------------------------------------------------------------------
// Sandbox List + Get
// ---------------------------------------------------------------------------

// sandboxSortColumns are the columns ListSandboxes accepts for `?sort=`. Each
// maps to a guarded ORDER BY term in ListSandboxesByTeamPaged.
var sandboxSortColumns = []string{"created_at", "name", "status"}

// sandboxStatusFilterValues are the values ListSandboxes accepts for
// `?status=`, sourced from the sqlc-generated sandbox_status constants. An
// unknown value would silently match zero rows in the SQL's text comparison,
// so the handler rejects it with a 400 instead — mirroring the owner filter
// on /templates.
var sandboxStatusFilterValues = []string{
	string(db.SandboxStatusStarting),
	string(db.SandboxStatusActive),
	string(db.SandboxStatusPausing),
	string(db.SandboxStatusPaused),
	string(db.SandboxStatusResuming),
	string(db.SandboxStatusFailed),
	string(db.SandboxStatusDeleted),
}

func (h *Handlers) ListSandboxes(c *gin.Context) {
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}
	if !h.requireTeamSandboxRead(c, teamID) {
		return
	}

	// Parse metadata filters from the query string. Any query param that
	// starts with `metadata.` is treated as a filter clause:
	//
	//   GET /sandboxes?metadata.env=prod&metadata.owner=agent-7
	//
	// Multiple filters AND together (jsonb @> containment semantics): a
	// sandbox matches only if all key/value pairs are present in its
	// metadata. Values are always strings — there's no type coercion,
	// because the storage shape is flat string→string and we want url
	// filters to be unambiguous (`metadata.count=42` matches the string
	// "42", not the number 42).
	filter, err := parseMetadataFilter(c.Request.URL.Query())
	if err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	// Always a valid jsonb value: '{}' matches every row under @> containment,
	// so the single paged query serves both filtered and unfiltered requests.
	metadataJSON := []byte("{}")
	if len(filter) > 0 {
		metadataJSON, _ = json.Marshal(filter) // map[string]string never fails
	}

	// Pagination + sort + optional status/name filters. Omitting `limit`
	// returns the full list in created_at-desc order — the pre-pagination
	// contract that unpaginated SDK/MCP callers still rely on.
	pg, err := parsePageParams(c, sandboxSortColumns, "created_at")
	if err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	statusFilter := nullableStr(c.Query("status"))
	if statusFilter != nil && !slices.Contains(sandboxStatusFilterValues, *statusFilter) {
		respondErrorMsg(c, "bad_request",
			"status must be one of: "+strings.Join(sandboxStatusFilterValues, ", "),
			http.StatusBadRequest)
		return
	}
	nameSearch := searchTerm(c.Query("q"))

	ctx := c.Request.Context()
	sandboxes, err := h.DB.ListSandboxesByTeamPaged(ctx, db.ListSandboxesByTeamPagedParams{
		TeamID:     teamID,
		Metadata:   metadataJSON,
		Status:     statusFilter,
		NameSearch: nameSearch,
		SortBy:     pg.SortBy,
		SortDir:    pg.SortDir,
		RowOffset:  pg.Offset,
		RowLimit:   pg.Limit,
	})
	if err != nil {
		log.Error().Err(err).Msg("DB ListSandboxesByTeamPaged failed")
		respondError(c, ErrInternal)
		return
	}

	total, err := resolveTotal(pg, len(sandboxes), func() (int64, error) {
		return h.DB.CountSandboxesByTeamPaged(ctx, db.CountSandboxesByTeamPagedParams{
			TeamID:     teamID,
			Metadata:   metadataJSON,
			Status:     statusFilter,
			NameSearch: nameSearch,
		})
	})
	if err != nil {
		log.Error().Err(err).Msg("DB CountSandboxesByTeamPaged failed")
		respondError(c, ErrInternal)
		return
	}
	c.Header("X-Total-Count", strconv.FormatInt(total, 10))

	out := make([]sandboxResponse, len(sandboxes))
	for i, s := range sandboxes {
		out[i] = h.sandboxToResponse(s)
	}
	c.JSON(http.StatusOK, out)
}

// parseMetadataFilter walks query params and extracts the metadata.* filter
// pairs into a flat string→string map. Returns an empty map (not nil) when
// the user didn't supply any metadata filters.
//
// The validation cap on the *filter* is the same as on stored metadata
// (validateMetadata), because we marshal the filter to jsonb and pass it
// through @> — a 16 KB filter would be a denial-of-service vector if
// allowed. We reuse validateMetadata so the rules can never drift apart.
func parseMetadataFilter(query map[string][]string) (map[string]string, error) {
	const prefix = "metadata."
	out := map[string]string{}
	for key, values := range query {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		mdKey := strings.TrimPrefix(key, prefix)
		if mdKey == "" {
			return nil, fmt.Errorf("metadata filter key cannot be empty")
		}
		// Repeated `?metadata.k=a&metadata.k=b` is meaningless under
		// containment semantics (a sandbox can have only one value per
		// key), so we reject it loudly instead of picking last-wins.
		if len(values) > 1 {
			return nil, fmt.Errorf("metadata filter %q has multiple values; only one allowed", mdKey)
		}
		out[mdKey] = values[0]
	}
	if err := validateMetadata(out); err != nil {
		return nil, err
	}
	return out, nil
}

func (h *Handlers) GetSandboxByID(c *gin.Context) {
	sandboxID, err := parseSandboxID(c)
	if err != nil {
		return
	}

	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}
	if !h.requireTeamSandboxRead(c, teamID) {
		return
	}

	sandbox, err := h.DB.GetSandbox(c.Request.Context(), db.GetSandboxParams{
		ID:     sandboxID,
		TeamID: teamID,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			respondError(c, ErrSandboxNotFound)
			return
		}
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB GetSandbox failed")
		respondError(c, ErrInternal)
		return
	}

	resp := h.sandboxToResponse(sandbox)
	canWrite, permErr := h.customerTeamPermissionAllowed(c, teamID, "settings:write")
	if permErr != nil {
		log.Error().
			Err(permErr).
			Str("team_id", teamID.String()).
			Str("sandbox_id", sandboxID.String()).
			Msg("RBAC sandbox token permission check failed")
	} else if canWrite {
		resp = h.sandboxToResponseWithToken(sandbox)
	}
	if !isConsoleImpersonation(c) {
		resp.Secrets = h.fetchSandboxSecretBindings(c.Request.Context(), sandboxID)
	}
	c.JSON(http.StatusOK, resp)
}

// fetchSandboxSecretBindings is a best-effort read of the sandbox's secret
// bindings for the detail response. A DB failure is logged but doesn't fail
// the request — the sandbox shape is still useful without the bindings list.
func (h *Handlers) fetchSandboxSecretBindings(ctx context.Context, sandboxID uuid.UUID) []sandboxSecretBinding {
	rows, err := h.DB.ListSandboxSecretBindings(ctx, sandboxID)
	if err != nil {
		log.Warn().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB ListSandboxSecretBindings failed")
		return nil
	}
	if len(rows) == 0 {
		return nil
	}
	out := make([]sandboxSecretBinding, 0, len(rows))
	for _, r := range rows {
		out = append(out, sandboxSecretBinding{
			EnvKey:     r.EnvKey,
			SecretName: r.SecretName,
			Revoked:    r.SecretRevoked,
		})
	}
	return out
}

func (h *Handlers) CreateSandbox(c *gin.Context) {
	tStart := time.Now()
	var req createSandboxRequest
	if err := bindJSONStrict(c, &req); err != nil {
		respondErrorMsg(c, "bad_request", "Request body is not valid JSON or contains unknown fields.", http.StatusBadRequest)
		return
	}
	// Manual field validation — bindJSONStrict uses encoding/json which does
	// not honor gin's `binding:"required,..."` struct tags.
	if req.Name == "" || len(req.Name) > 64 {
		respondErrorMsg(c, "bad_request", "name is required and must be 1-64 characters", http.StatusBadRequest)
		return
	}

	if err := validateTimeoutSeconds(req.TimeoutSeconds); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateAutoDeleteSeconds(req.AutoDeleteSeconds); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}

	// Validate network rules up front so we fail before doing any DB or VMD work.
	if req.Network != nil {
		if err := validateEgressRules(req.Network.AllowOut, req.Network.DenyOut); err != nil {
			respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
			return
		}
	}

	// Validate metadata before any DB or VMD work for the same reason —
	// reject oversized / reserved-prefix tags with a 400 instead of writing
	// a row we'd need to roll back.
	if err := validateMetadata(req.Metadata); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateEnvVars(req.EnvVars); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateSecretsRefs(req.Secrets); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	// env_vars and secrets share the env-var namespace; 400 on collision.
	for k := range req.Secrets {
		if _, dup := req.EnvVars[k]; dup {
			respondErrorMsg(c, "bad_request",
				fmt.Sprintf("env-var key %q appears in both env_vars and secrets; pick one", k),
				http.StatusBadRequest)
			return
		}
	}
	// Marshal once into the canonical jsonb shape. Empty / nil maps are
	// stored as the empty object so the column is never NULL.
	metadataJSON, err := json.Marshal(req.Metadata)
	if err != nil {
		// json.Marshal of map[string]string cannot actually fail, but the
		// linter doesn't know that and the cost of the check is zero.
		log.Error().Err(err).Msg("marshal sandbox metadata")
		respondError(c, ErrInternal)
		return
	}
	if len(req.Metadata) == 0 {
		metadataJSON = []byte(`{}`)
	}

	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}
	if !h.requireTeamSandboxWrite(c, teamID) {
		return
	}

	// Resolve secret references before spinning up the VM so a typo 400s cleanly.
	secretBindings, secretMeta, appErr := h.resolveSecretBindingsForCreate(c.Request.Context(), teamID, req.Secrets)
	if appErr != nil {
		respondError(c, appErr)
		return
	}

	// Default the create to the `superserve/base` template so every sandbox
	// has a consistent baseline image. Callers can opt out by setting
	// from_template to some other name/UUID; today the API always routes
	// through the template/snapshot-restore path.
	if req.FromTemplate == nil {
		defaultTpl := "superserve/base"
		req.FromTemplate = &defaultTpl
	}

	// If from_template is provided, resolve to the template's snapshot paths
	// and reuse the existing snapshot-restore code path.
	var snapshotPath, snapshotMemPath, basePath, deltaPath, deltaDir string
	var templateID pgtype.UUID
	// Template resources — only populated when the create uses from_template.
	// vmd.RestoreSnapshot doesn't return ResourceLimits on older builds (proto
	// gap), so the handler substitutes these at ActivateSandbox time. The
	// snapshot was built with exactly these values, so they're the
	// authoritative shape.
	var templateVcpu, templateMemMiB uint32
	var fromTemplateName, fromTemplateID string
	var tLookupDone time.Time
	if req.FromTemplate != nil {
		tpl, err := h.lookupTemplateForCreate(c, teamID, *req.FromTemplate)
		tLookupDone = time.Now()
		if err != nil {
			return // error already responded
		}
		if tpl.Status != db.TemplateStatusReady {
			respondErrorMsg(c, "conflict",
				fmt.Sprintf("template is not ready (status=%s)", tpl.Status),
				http.StatusConflict)
			return
		}
		if tpl.SnapshotPath == nil || tpl.MemPath == nil {
			log.Error().Str("template_id", tpl.ID.String()).Msg("ready template missing snapshot paths")
			respondError(c, ErrInternal)
			return
		}
		snapshotPath = *tpl.SnapshotPath
		snapshotMemPath = *tpl.MemPath
		if tpl.BasePath != nil {
			basePath = *tpl.BasePath
		}
		if tpl.DeltaPath != nil {
			deltaPath = *tpl.DeltaPath
			deltaDir = filepath.Dir(deltaPath)
		}
		templateID = pgtype.UUID{Bytes: tpl.ID, Valid: true}
		templateVcpu = uint32(tpl.Vcpu)
		templateMemMiB = uint32(tpl.MemoryMib)
		fromTemplateName = tpl.Name
		fromTemplateID = tpl.ID.String()
	}

	// Select a host for this sandbox.
	var hostID string
	if h.Scheduler != nil {
		hostID, err = h.Scheduler.SelectHost(c.Request.Context())
		if err != nil {
			log.Error().Err(err).Msg("scheduler SelectHost failed")
			respondErrorMsg(c, "service_unavailable", "No hosts available", http.StatusServiceUnavailable)
			return
		}
	} else if h.Config != nil && h.Config.DefaultHostID != "" {
		hostID = h.Config.DefaultHostID
	} else {
		hostID = "default"
	}
	SetTelemetryHostID(c, hostID)

	// Resolve the VMD client up front so we don't waste a DB INSERT on
	// a host we can't reach.
	vmd, vmdLookupErr := h.vmdForHost(c.Request.Context(), hostID)
	if vmdLookupErr != nil {
		log.Error().Err(vmdLookupErr).Msg("resolve VMD for create failed")
		respondError(c, ErrInternal)
		return
	}

	// Generate the sandbox ID in Go so the DB INSERT and the VMD call
	// can run in parallel — both need the same ID and neither needs to
	// wait on the other. This hides the ~10-20ms INSERT roundtrip behind
	// VMD's ~100-200ms create latency, shaving that much off the p50.
	sandboxID := uuid.New()

	insertCtx := context.WithoutCancel(c.Request.Context())
	type insertResult struct {
		sandbox db.Sandbox
		err     error
	}
	insertCh := make(chan insertResult, 1)
	// runInsert performs the INSERT against the supplied tx-bound queries.
	// Closure captures sandboxID/teamID/req/templateID/hostID/metadataJSON.
	runInsert := func(q *db.Queries) (db.Sandbox, error) {
		if templateID.Valid {
			// CreateSandboxFromTemplate holds FOR KEY SHARE on the template
			// row, serializing with SoftDeleteTemplateIfUnused's FOR UPDATE
			// so a concurrent template delete is either blocked (we win,
			// INSERT succeeds) or completes before us (we lose, 0 rows back).
			// Pin artifact paths so a later rebuild can't shift them.
			return q.CreateSandboxFromTemplate(insertCtx, db.CreateSandboxFromTemplateParams{
				ID:                sandboxID,
				TeamID:            teamID,
				Name:              req.Name,
				Status:            db.SandboxStatusStarting,
				VcpuCount:         1, // placeholders; real values land via ActivateSandbox
				MemoryMib:         1,
				HostID:            hostID,
				TimeoutSeconds:    req.TimeoutSeconds,
				AutoDeleteSeconds: req.AutoDeleteSeconds,
				Metadata:          metadataJSON,
				ID_2:              uuid.UUID(templateID.Bytes),
				TeamID_2:          teamID,
				TeamID_3:          h.systemTeamID(),
				SnapshotPath:      nullableStr(snapshotPath),
				MemPath:           nullableStr(snapshotMemPath),
				BasePath:          nullableStr(basePath),
				DeltaPath:         nullableStr(deltaPath),
			})
		}
		return q.CreateSandbox(insertCtx, db.CreateSandboxParams{
			ID:                sandboxID,
			TeamID:            teamID,
			Name:              req.Name,
			Status:            db.SandboxStatusStarting,
			VcpuCount:         1,
			MemoryMib:         1,
			HostID:            hostID,
			TimeoutSeconds:    req.TimeoutSeconds,
			AutoDeleteSeconds: req.AutoDeleteSeconds,
			Metadata:          metadataJSON,
			TemplateID:        pgtype.UUID{Valid: false},
			SnapshotPath:      nil,
			MemPath:           nil,
			BasePath:          nil,
			DeltaPath:         nil,
		})
	}
	// insertWithBindings writes the sandbox row and any secret bindings in one
	// statement, so a successful create never leaves a binding unrecorded and
	// the quota admission's uncommitted window stays statement-sized — a
	// transaction spanning multiple round trips would widen it (see the query
	// comments).
	insertWithBindings := func() (db.Sandbox, error) {
		if len(secretBindings) == 0 {
			return runInsert(h.DB)
		}
		secretIDs := make([]uuid.UUID, len(secretBindings))
		envKeys := make([]string, len(secretBindings))
		proxyTokens := make([]string, len(secretBindings))
		for i := range secretBindings {
			secretIDs[i] = secretBindings[i].SecretID
			envKeys[i] = secretBindings[i].EnvKey
			// secretMeta is index-aligned with secretBindings; persist its token.
			proxyTokens[i] = secretMeta[i].ProxyToken
		}
		if templateID.Valid {
			row, err := h.DB.CreateSandboxFromTemplateWithSecrets(insertCtx, db.CreateSandboxFromTemplateWithSecretsParams{
				TemplateID:        uuid.UUID(templateID.Bytes),
				TeamID:            teamID,
				SystemTeamID:      h.systemTeamID(),
				ID:                sandboxID,
				Name:              req.Name,
				Status:            db.SandboxStatusStarting,
				VcpuCount:         1, // placeholders; real values land via ActivateSandbox
				MemoryMib:         1,
				HostID:            hostID,
				TimeoutSeconds:    req.TimeoutSeconds,
				AutoDeleteSeconds: req.AutoDeleteSeconds,
				Metadata:          metadataJSON,
				SnapshotPath:      nullableStr(snapshotPath),
				MemPath:           nullableStr(snapshotMemPath),
				BasePath:          nullableStr(basePath),
				DeltaPath:         nullableStr(deltaPath),
				SecretIds:         secretIDs,
				EnvKeys:           envKeys,
				ProxyTokens:       proxyTokens,
			})
			return db.Sandbox(row), err
		}
		row, err := h.DB.CreateSandboxWithSecrets(insertCtx, db.CreateSandboxWithSecretsParams{
			ID:                sandboxID,
			TeamID:            teamID,
			Name:              req.Name,
			Status:            db.SandboxStatusStarting,
			VcpuCount:         1,
			MemoryMib:         1,
			HostID:            hostID,
			TimeoutSeconds:    req.TimeoutSeconds,
			AutoDeleteSeconds: req.AutoDeleteSeconds,
			Metadata:          metadataJSON,
			TemplateID:        pgtype.UUID{Valid: false},
			SecretIds:         secretIDs,
			EnvKeys:           envKeys,
			ProxyTokens:       proxyTokens,
		})
		return db.Sandbox(row), err
	}

	var tInsertStart, tInsertEnd time.Time
	go func() {
		tInsertStart = time.Now()
		// Quota is enforced by the sandbox_quota_on_insert trigger.
		sb, err := insertWithBindings()
		tInsertEnd = time.Now()
		insertCh <- insertResult{sandbox: sb, err: err}
	}()

	// Boot the VM synchronously — the client gets a response only after
	// the sandbox is fully running and ready to use. The boot is still
	// scoped to the request context so that if the client hangs up, it is
	// cancelled and VMD cleans up.
	envVarsToShip := mergeEnvVarsWithSecrets(req.EnvVars, secretMeta)

	// Phase 1: RestoreSnapshot boots the VM with the caller's env vars and
	// returns its source IP. For sandboxes with secrets, a follow-up
	// InjectSandboxEnv pushes the env again together with the JWT minted
	// against the now-known source IP.
	tVmdStart := time.Now()
	ipAddress, actualVcpu, actualMemMiB, vmdRetried, vmdErr := retryTransientBoot(c.Request.Context(), sandboxID.String(), func(ctx context.Context) (string, uint32, uint32, error) {
		return vmd.RestoreSnapshot(ctx, sandboxID.String(), snapshotPath, snapshotMemPath, basePath, deltaDir, teamID.String(), ownerIDFromContext(c), req.EnvVars)
	})
	tVmdEnd := time.Now()

	// Wait for the parallel INSERT to complete — its result determines
	// how we handle a VMD failure (mark row failed vs. nothing to mark).
	insertRes := <-insertCh
	tInsertReceive := time.Now()
	sandbox := insertRes.sandbox
	dbErr := insertRes.err

	// 0 rows from CreateSandboxFromTemplate = template deleted mid-create.
	templateRace := templateID.Valid && errors.Is(dbErr, pgx.ErrNoRows)

	// Per-team sandbox count cap; raised by sandbox_quota_on_insert trigger.
	quotaExceeded := isSandboxQuotaErr(dbErr)

	switch {
	case dbErr != nil && vmdErr != nil:
		// Both failed — nothing persisted, nothing to clean up.
		log.Error().Err(dbErr).AnErr("vmd_err", vmdErr).Msg("CreateSandbox: DB and VMD both failed")
		if templateRace {
			respondErrorMsg(c, "not_found", "Template not found", http.StatusNotFound)
			return
		}
		if quotaExceeded {
			h.respondQuotaExceeded(c, teamID)
			return
		}
		respondError(c, ErrInternal)
		return
	case dbErr != nil:
		// DB insert failed but VMD succeeded — destroy the orphan VM so
		// it doesn't linger on the host. Use a detached context so client
		// disconnect doesn't leak the VM.
		log.Error().Err(dbErr).Str("sandbox_id", sandboxID.String()).Msg("CreateSandbox: INSERT failed, destroying orphan VM")
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(c.Request.Context()), vmdTimeout)
		_ = vmd.DestroyInstance(cleanupCtx, sandboxID.String(), true)
		cleanupCancel()
		if templateRace {
			respondErrorMsg(c, "not_found", "Template not found", http.StatusNotFound)
			return
		}
		if quotaExceeded {
			h.respondQuotaExceeded(c, teamID)
			return
		}
		respondError(c, ErrInternal)
		return
	case vmdErr != nil:
		// VMD failed but DB row exists — mark it failed so the reaper
		// doesn't leave it stuck in "starting". The request middleware
		// records the create failure metric from the HTTP status, so avoid
		// emitting a second request-scoped transition here.
		log.Error().Err(vmdErr).Str("sandbox_id", sandbox.ID.String()).Msg("VMD create/resume failed")
		// A cancelled attempt can still complete on the host just after the
		// deadline; best-effort destroy so a booted VM can't idle against a
		// failed row until the reconciler sweeps it.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(c.Request.Context()), vmdTimeout)
		_ = vmd.DestroyInstance(cleanupCtx, sandboxID.String(), true)
		cleanupCancel()
		failCtx, failCancel := context.WithTimeout(context.WithoutCancel(c.Request.Context()), asyncTimeout)
		defer failCancel()
		if err := h.DB.UpdateSandboxStatus(failCtx, db.UpdateSandboxStatusParams{
			ID:     sandbox.ID,
			Status: db.SandboxStatusFailed,
			TeamID: teamID,
		}); err != nil {
			log.Error().Err(err).Str("sandbox_id", sandbox.ID.String()).Msg("mark failed after VMD create failure")
		} // Bindings are written before RestoreSnapshot, so a restore failure
		// leaves them; clear them or this dead sandbox still shows as bound.
		_ = h.DB.DeleteSandboxSecrets(failCtx, sandbox.ID)
		// FailedPrecondition from vmd = snapshot/mem file missing on host.
		// Surfaces on the from_template restore path; map to 503 so the
		// user understands this is ops-side, not a bad request.
		if isVMDFileMissing(vmdErr) {
			respondError(c, ErrHostStateMissing)
			return
		}
		respondError(c, ErrInternal)
		return
	}

	// Phase 2: with the source IP known, mint the per-sandbox secrets JWT
	// (when secrets are configured) and push env vars to the running boxd.
	// If injection fails, tear the VM down and mark the row failed — a
	// sandbox that boots without its env vars is unusable. (Hostname-only
	// creates run the same call inside the activation goroutine instead;
	// a failure there fails the row before it ever goes active.)
	postCtx, postCancel := context.WithTimeout(context.WithoutCancel(c.Request.Context()), vmdTimeout)
	defer postCancel()

	// Persist egress rules before injecting the env, so the secrets proxy's live
	// rule fetch sees them before the agent can issue a proxied request. The
	// nftables push happens later (it needs the booted VM); the DB write does not.
	if req.Network != nil && (len(req.Network.AllowOut) > 0 || len(req.Network.DenyOut) > 0) {
		_, _, networkConfig := egressConfigJSON(req.Network)
		if err := h.DB.UpdateSandboxNetworkConfig(postCtx, db.UpdateSandboxNetworkConfigParams{
			ID:            sandbox.ID,
			NetworkConfig: networkConfig,
			TeamID:        teamID,
		}); err != nil {
			log.Warn().Err(err).Str("sandbox_id", sandboxID.String()).Msg("persist network_config before env inject failed")
		}
	}

	var secretsJWT string
	if len(secretMeta) > 0 {
		jwt, jerr := h.mintSecretsJWT(sandboxID.String(), teamID.String(), ipAddress, secretMeta)
		if jerr != nil {
			log.Error().Err(jerr).Str("sandbox_id", sandboxID.String()).Msg("mint secrets JWT")
			h.failSandboxAfterBoot(postCtx, vmd, sandbox.ID, teamID, sandboxID.String(), hostID)
			respondError(c, ErrInternal)
			return
		}
		secretsJWT = jwt
	}
	// When the inject would carry nothing but the hostname stamp (the payload
	// is exactly env vars + JWT + hostname — a new always-shipped field must
	// join this condition), it moves off the response path: the stamp runs in
	// the activation goroutine below, ordered before the status flip.
	// The deeper form — vmd stamping the hostname itself during
	// RestoreSnapshot, where the round trip is on-host — would remove this
	// branch entirely; it needs a cross-version vmd rollout to adopt.
	stampAsync := len(envVarsToShip) == 0 && secretsJWT == ""
	if !stampAsync {
		if injErr := vmd.InjectSandboxEnv(postCtx, sandboxID.String(), envVarsToShip, secretsJWT); injErr != nil {
			// A vmd without this RPC already applied these env vars during
			// RestoreSnapshot; tolerate its absence only when no JWT needs this path.
			if secretsJWT == "" && isVMDUnimplemented(injErr) {
				log.Warn().Str("sandbox_id", sandboxID.String()).Msg("vmd lacks InjectSandboxEnv; env applied during restore")
			} else {
				log.Error().Err(injErr).Str("sandbox_id", sandboxID.String()).Msg("VMD InjectSandboxEnv failed")
				h.failSandboxAfterBoot(postCtx, vmd, sandbox.ID, teamID, sandboxID.String(), hostID)
				respondError(c, ErrInternal)
				return
			}
		}
	}

	// Prime the secrets proxy's egress-rules cache so the agent's first proxied
	// request hits a warm cache (covers a control-plane blip right after create).
	// Best-effort; the on-demand fetch + TTL is the fallback.
	if len(secretMeta) > 0 {
		go func() {
			pctx, pcancel := context.WithTimeout(context.Background(), vmdTimeout)
			defer pcancel()
			if err := vmd.InvalidateSandboxRules(pctx, sandboxID.String()); err != nil {
				log.Warn().Err(err).Str("sandbox_id", sandboxID.String()).Msg("prime egress rules cache failed (fetch fallback)")
			}
		}()
	}

	// Single atomic transition: starting → active with real resources
	// and IP. VMD's response is the source of truth for vcpu/memory
	// when present.
	//
	// Defense-in-depth: if vmd returns 0 for vcpu/memory (e.g. old vmd
	// without ResourceLimits in RestoreSnapshotResponse), fall back to
	// the template's values. The template's shape IS the snapshot's shape.
	if actualVcpu == 0 && templateVcpu > 0 {
		actualVcpu = templateVcpu
	}
	if actualMemMiB == 0 && templateMemMiB > 0 {
		actualMemMiB = templateMemMiB
	}

	var ipAddr *netip.Addr
	if ipAddress != "" {
		if addr, parseErr := netip.ParseAddr(ipAddress); parseErr == nil {
			ipAddr = &addr
		}
	}
	sandbox.Status = db.SandboxStatusActive
	sandbox.VcpuCount = int32(actualVcpu)
	sandbox.MemoryMib = int32(actualMemMiB)
	sandbox.IpAddress = ipAddr

	// Fire-and-forget: the starting→active bookkeeping write is off the hot
	// path. The create INSERT owns the row and every other transition is
	// status-gated, so a racing pause/exec sees 'starting' and 409s until
	// this lands. Capture actor before the goroutine — gin.Context is
	// recycled after ServeHTTP returns. The CTE inside ActivateSandbox uses
	// it to open the matching sandbox_active_interval row in the same
	// statement. postCtx is cancelled when the handler returns, so the
	// goroutine derives its own detached deadline.
	actorID := actorIDFromContext(c)
	activateCtx := context.WithoutCancel(c.Request.Context())
	h.asyncBookkeeping("activate-sandbox", func() {
		if stampAsync {
			// The hostname stamp runs here, BEFORE the row goes active:
			// pause and destroy are status-gated on 'active', so this
			// ordering keeps the sync path's invariant that nothing can
			// freeze or tear down a guest mid-stamp — and a snapshot can
			// never capture the template hostname, which matters because
			// the stateless-resume fallback never re-stamps. The deadline
			// matches the sync path's budget.
			sctx, scancel := context.WithTimeout(activateCtx, vmdTimeout)
			tStamp := time.Now()
			stampErr := vmd.InjectSandboxEnv(sctx, sandboxID.String(), envVarsToShip, secretsJWT)
			scancel()
			switch {
			case stampErr == nil, isVMDUnimplemented(stampErr):
			default:
				// The stamp's payload is cosmetic but its transport is not:
				// a POST into the guest just failed — the same signal the
				// synchronous path treats as an unusable sandbox. Fail the
				// row instead of activating a sandbox whose guest is dead.
				// NotFound lands here too: destroy is gated on 'active', so
				// pre-activation the VM can only be gone abnormally — and
				// ActivateSandbox has no status guard, so proceeding could
				// resurrect a row another path just marked failed.
				log.Error().Err(stampErr).Str("sandbox_id", sandboxID.String()).
					Int64("stamp_ms", time.Since(tStamp).Milliseconds()).
					Msg("post-boot guest init failed; failing sandbox instead of activating")
				fctx, fcancel := context.WithTimeout(activateCtx, vmdTimeout)
				defer fcancel()
				h.failSandboxAfterBoot(fctx, vmd, sandbox.ID, teamID, sandboxID.String(), hostID)
				return
			}
		}
		actx, acancel := context.WithTimeout(activateCtx, asyncTimeout)
		defer acancel()
		if err := h.DB.ActivateSandbox(actx, db.ActivateSandboxParams{
			ID:        sandbox.ID,
			VcpuCount: int32(actualVcpu),
			MemoryMib: int32(actualMemMiB),
			IpAddress: ipAddr,
			TeamID:    teamID,
			ActorID:   actorUUID(actorID),
		}); err != nil {
			log.Error().Err(err).Str("sandbox_id", sandbox.ID.String()).Msg("async DB ActivateSandbox failed")
		}
	})

	// Network rules stay blocking: a 201 must imply "egress rules applied",
	// so the client can't reach the sandbox before its policy is in place.
	if req.Network != nil && (len(req.Network.AllowOut) > 0 || len(req.Network.DenyOut) > 0) {
		// network_config was persisted above (before env injection); this
		// only pushes the nftables rules, which need the booted VM.
		allowedCIDRs, allowedDomains, _ := egressConfigJSON(req.Network)
		if err := vmd.UpdateSandboxNetwork(postCtx, sandbox.ID.String(), allowedCIDRs, req.Network.DenyOut, allowedDomains); err != nil {
			log.Error().Err(err).Str("sandbox_id", sandbox.ID.String()).Msg("failed to apply network rules at creation")
		}
	}
	tPostDone := time.Now()

	var createdMeta []byte
	if fromTemplateName != "" {
		createdMeta, _ = json.Marshal(map[string]string{
			"from_template": fromTemplateName,
			"template_id":   fromTemplateID,
		})
	}
	// ActivateSandbox's CTE opens the sandbox_active_interval row (async).
	h.logSandboxActivity(c.Request.Context(), sandbox.ID, teamID, actorID, "sandbox", "started", "success", &sandbox.Name, nil, createdMeta)
	h.capture(c, "sandbox_created", map[string]any{
		"sandbox_id":  sandbox.ID.String(),
		"template_id": fromTemplateID,
	})

	sandbox.Status = db.SandboxStatusActive
	resp := h.sandboxToResponseWithToken(sandbox)
	if req.Network != nil && (len(req.Network.AllowOut) > 0 || len(req.Network.DenyOut) > 0) {
		resp.Network = req.Network
	}
	log.Info().
		Str("sandbox_id", sandbox.ID.String()).
		Int64("auth_ms", c.GetInt64("auth_ms")).
		Int64("lookup_ms", tLookupDone.Sub(tStart).Milliseconds()).
		Int64("sched_ms", tVmdStart.Sub(tLookupDone).Milliseconds()).
		Int64("vmd_ms", tVmdEnd.Sub(tVmdStart).Milliseconds()).
		Bool("vmd_retried", vmdRetried).
		Int64("insert_ms", tInsertEnd.Sub(tInsertStart).Milliseconds()).
		Int64("insert_wait_after_vmd_ms", tInsertReceive.Sub(tVmdEnd).Milliseconds()).
		Int64("post_ms", tPostDone.Sub(tInsertReceive).Milliseconds()).
		Int64("total_ms", tPostDone.Sub(tStart).Milliseconds()).
		Msg("CreateSandbox phases")
	c.JSON(http.StatusCreated, resp)
}

// ---------------------------------------------------------------------------
// Sandbox Pause
// ---------------------------------------------------------------------------

// pauseWithRetry pauses a VM, retrying once on a non-NotFound failure. A
// timed-out pause may have actually completed on the host, so reverting the
// row to active would drift it against a paused VM; PauseVM is idempotent, so
// the retry returns the recorded snapshot and the row converges to paused.
// NotFound is terminal — the VM is genuinely gone.
func pauseWithRetry(reqCtx context.Context, vmd vmdclient.Client, id string) (snapshotPath, memPath string, err error) {
	ctx, cancel := context.WithTimeout(reqCtx, vmdTimeout)
	snapshotPath, memPath, err = vmd.PauseInstance(ctx, id, "")
	cancel()
	if err == nil || isVMDNotFound(err) {
		return snapshotPath, memPath, err
	}
	// Detach from the request ctx: the client's deadline may already have
	// fired, but the reconciliation to a consistent state must still run.
	rctx, rcancel := context.WithTimeout(context.WithoutCancel(reqCtx), vmdTimeout)
	defer rcancel()
	return vmd.PauseInstance(rctx, id, "")
}

func (h *Handlers) PauseSandbox(c *gin.Context) {
	sandboxID, err := parseSandboxID(c)
	if err != nil {
		return
	}

	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}
	if !h.requireTeamSandboxWrite(c, teamID) {
		return
	}

	// Atomic ownership + state check + transition to 'pausing'. Collapses
	// GetSandbox + UpdateStatus into a single DB roundtrip on the happy
	// path. An empty result means the sandbox either doesn't exist, isn't
	// ours, or isn't currently active — we do a cheap existence check to
	// return the right error code (404 vs 409).
	sandbox, err := h.DB.BeginPause(c.Request.Context(), db.BeginPauseParams{
		ID:     sandboxID,
		TeamID: teamID,
	})
	if err != nil {
		if err != pgx.ErrNoRows {
			log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB BeginPause failed")
			respondError(c, ErrInternal)
			return
		}
		// Disambiguate: missing row (404) vs wrong state (409).
		exists, existsErr := h.DB.SandboxExists(c.Request.Context(), db.SandboxExistsParams{
			ID:     sandboxID,
			TeamID: teamID,
		})
		if existsErr != nil {
			log.Error().Err(existsErr).Str("sandbox_id", sandboxID.String()).Msg("DB SandboxExists (pause fallback) failed")
			respondError(c, ErrInternal)
			return
		}
		if !exists {
			respondError(c, ErrSandboxNotFound)
			return
		}
		respondError(c, ErrInvalidState)
		return
	}
	SetTelemetryHostID(c, sandbox.HostID)

	// BeginPause's CTE atomically closed the open active interval together
	// with the status transition; nothing to do here. If the pause
	// subsequently fails, the revert paths reopen a new interval.

	// Resolve the VMD client for this sandbox's host.
	vmd, vmdLookupErr := h.vmdForHost(c.Request.Context(), sandbox.HostID)
	if vmdLookupErr != nil {
		log.Error().Err(vmdLookupErr).Str("sandbox_id", sandboxID.String()).Msg("resolve VMD for pause failed")
		respondError(c, ErrInternal)
		return
	}

	// Call VMD to pause and snapshot the VM.
	snapshotPath, memPath, err := pauseWithRetry(c.Request.Context(), vmd, sandboxID.String())
	if err != nil {
		// VMD says the VM doesn't exist — it crashed or was removed out-of-band.
		// Mark the sandbox failed and return 410 Gone. No revert — the VM is
		// already dead, "active" was a lie.
		if isVMDNotFound(err) {
			log.Warn().Err(err).Str("sandbox_id", sandboxID.String()).Msg("VMD PauseInstance: VM unavailable, marking sandbox failed")
			h.markSandboxFailedAsync(c.Request.Context(), sandboxID, teamID, sandbox.HostID)
			respondError(c, ErrSandboxGone)
			return
		}

		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("VMD PauseInstance failed")
		// Revert status to active asynchronously. Detach cancellation so
		// the revert survives client disconnect, but keep trace context
		// so the revert is linked to the original pause request.
		revertCtx := context.WithoutCancel(c.Request.Context())
		actorID := actorIDFromContext(c)
		go func() {
			ctx, cancel := context.WithTimeout(revertCtx, asyncTimeout)
			defer cancel()
			if revertErr := h.DB.UpdateSandboxStatus(ctx, db.UpdateSandboxStatusParams{
				ID:     sandboxID,
				Status: db.SandboxStatusActive,
				TeamID: teamID,
			}); revertErr != nil {
				log.Error().Err(revertErr).Str("sandbox_id", sandboxID.String()).Msg("async revert to active failed")
				return
			}
			// Reopen the interval we closed at BeginPause — sandbox is
			// back to 'active' and should resume being counted as such.
			if openErr := h.DB.OpenSandboxActiveInterval(ctx, db.OpenSandboxActiveIntervalParams{
				SandboxID: sandboxID,
				TeamID:    teamID,
				ActorID:   actorUUID(actorID),
			}); openErr != nil {
				log.Error().Err(openErr).Str("sandbox_id", sandboxID.String()).Msg("async reopen interval after revert failed")
			}
		}()
		respondError(c, ErrInternal)
		return
	}

	log.Debug().
		Str("sandbox_id", sandboxID.String()).
		Str("snapshot_path", snapshotPath).
		Str("mem_path", memPath).
		Msg("VMD pause complete")

	// Past this point the snapshot already exists on disk — the pause has
	// physically happened, so the bookkeeping (snapshot row upsert + status
	// flip pausing → paused in a single CTE) is fire-and-forget. BeginPause's
	// gate write owns the row and every other transition is status-gated, so
	// a racing resume sees 'pausing' and 409s until this lands. Detached from
	// cancellation so a client disconnect cannot orphan the bookkeeping;
	// trace/span context preserved. The upsert replaces the old "insert a new
	// row + delete the previous" flow, so there's no explicit prev-snapshot
	// cleanup to schedule here.
	finalizeCtx := context.WithoutCancel(c.Request.Context())
	h.asyncBookkeeping("finalize-pause", func() {
		fctx, fcancel := context.WithTimeout(finalizeCtx, asyncTimeout)
		defer fcancel()
		if _, err := h.DB.FinalizePause(fctx, db.FinalizePauseParams{
			ID:        sandboxID,
			TeamID:    teamID,
			Path:      snapshotPath,
			MemPath:   &memPath,
			SizeBytes: 0,
			Trigger:   "pause",
		}); err != nil {
			// ErrNoRows means the sandbox was soft-deleted between BeginPause
			// and FinalizePause (a rare race with DeleteSandbox). The VM is
			// already stopped and its snapshot files are on disk — nothing to
			// finalize for a sandbox that no longer exists.
			if err == pgx.ErrNoRows {
				log.Warn().Str("sandbox_id", sandboxID.String()).Msg("FinalizePause: sandbox deleted mid-pause")
				return
			}
			log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("async DB FinalizePause failed — sandbox may be stuck in 'pausing'")
		}
	})

	// Interval was already closed at BeginPause; FinalizePause is the
	// end of the VMD pause work, not the moment the sandbox left active.
	h.logSandboxActivity(c.Request.Context(), sandboxID, teamID, actorIDFromContext(c), "sandbox", "paused", "success", &sandbox.Name, nil, nil)
	h.capture(c, "sandbox_paused", map[string]any{"sandbox_id": sandboxID.String()})

	c.Status(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Sandbox Files
// ---------------------------------------------------------------------------

// hasDotDotSegment reports whether any slash-separated component of p is exactly
// "..". A plain strings.Contains(p, "..") is too aggressive — it rejects
// legitimate names like "hello..world" — while the real concern is a ".." path
// segment that could traverse upward.
func hasDotDotSegment(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

// ListSandboxFiles returns a one-level listing of a directory inside the
// sandbox: GET /sandboxes/:sandbox_id/files?path=/abs/dir. Listing is metadata,
// so it goes through the control plane (boxd FilesystemService.ListDir via vmd)
// rather than the data-plane /files byte-transfer endpoint. That makes it work
// on every sandbox regardless of boxd version — the backward-compatible path
// for sandboxes whose boxd predates the data-plane ?format=json handler. Paused
// sandboxes are resumed transparently, the same as exec.
func (h *Handlers) ListSandboxFiles(c *gin.Context) {
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}
	if !h.requireTeamSandboxWrite(c, teamID) {
		return
	}

	sandbox := h.loadActiveOrResumeSandbox(c)
	if sandbox == nil {
		return
	}

	path := c.Query("path")
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") || hasDotDotSegment(path) {
		respondErrorMsg(c, "bad_request", "path must be absolute and free of '..' segments.", http.StatusBadRequest)
		return
	}

	vmd, vmdLookupErr := h.vmdForHost(c.Request.Context(), sandbox.HostID)
	if vmdLookupErr != nil {
		log.Error().Err(vmdLookupErr).Str("sandbox_id", sandbox.ID.String()).Msg("resolve VMD for list-dir failed")
		respondError(c, ErrInternal)
		return
	}

	entries, err := vmd.ListDir(c.Request.Context(), sandbox.ID.String(), path)
	if err != nil {
		// A missing directory (boxd NotFound) is a 404, never a gone VM: boxd
		// replying at all means the VM is alive, so we must not mark it failed.
		if isDirNotFound(err) {
			respondErrorMsg(c, "not_found", "Folder not found.", http.StatusNotFound)
			return
		}
		if isVMDInvalidArgument(err) {
			respondErrorMsg(c, "bad_request", "Path is not a listable directory.", http.StatusBadRequest)
			return
		}
		log.Error().Err(err).Str("sandbox_id", sandbox.ID.String()).Msg("VMD ListDir failed")
		respondError(c, ErrInternal)
		return
	}

	out := make([]gin.H, 0, len(entries))
	for _, e := range entries {
		out = append(out, gin.H{
			"name":          e.Name,
			"is_dir":        e.IsDir,
			"size":          e.Size,
			"modified_unix": e.ModifiedUnix,
		})
	}
	c.JSON(http.StatusOK, gin.H{"entries": out})
}

// ---------------------------------------------------------------------------
// Sandbox Patch
// ---------------------------------------------------------------------------

// patchSandboxRequest is the body for PATCH /sandboxes/:id. Each top-level
// field is optional; only fields that are present in the request body are
// applied. Nested objects (like Network) are full replacements when present —
// to clear deny_out, send {"network": {"allow_out": [...], "deny_out": []}},
// not {"network": {"allow_out": [...]}} (which would replace deny_out with
// nil and effectively clear it anyway, but be explicit).
//
// At least one top-level field must be set, otherwise the request is rejected
// with 400. This guards against clients sending empty bodies by mistake and
// silently no-opping.
//
// Patchable fields: `network`, `metadata`, and `auto_delete_seconds`. Adding
// more in the future is additive — declare a new pointer field and dispatch on
// its non-nil-ness (or optionalInt32 when JSON null must mean "clear", which a
// plain pointer can't distinguish from "absent").
type patchSandboxRequest struct {
	Network           *networkConfigRequest `json:"network,omitempty"`
	Metadata          map[string]string     `json:"metadata,omitempty"`
	AutoDeleteSeconds optionalInt32         `json:"auto_delete_seconds,omitempty"`
	TimeoutSeconds    optionalInt32         `json:"timeout_seconds,omitempty"`
}

// optionalInt32 is a tri-state JSON field: absent (Set=false), explicit null
// (Set=true, Value=nil), or a number (Set=true, Value=&n). UnmarshalJSON only
// runs when the key is present, which is what distinguishes absent from null.
type optionalInt32 struct {
	Set   bool
	Value *int32
}

func (o *optionalInt32) UnmarshalJSON(b []byte) error {
	o.Set = true
	if string(b) == "null" {
		return nil
	}
	return json.Unmarshal(b, &o.Value)
}

// PatchSandbox applies a partial update to a sandbox.
//   - network: replaces egress rules; sandbox must be active.
//   - metadata: replaces metadata tags; can be patched in any non-deleted state.
//   - auto_delete_seconds: sets/clears the paused-GC window; any non-deleted
//     state. On an already-paused sandbox the deadline is armed from now, so
//     the caller always gets the full window they asked for.
//   - timeout_seconds: sets/clears the auto-pause timeout; any non-deleted
//     state. Evaluated against the current active session on the next reaper
//     tick, so lowering it below elapsed session time pauses promptly.
func (h *Handlers) PatchSandbox(c *gin.Context) {
	sandboxID, err := parseSandboxID(c)
	if err != nil {
		return
	}

	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}
	if !h.requireTeamSandboxWrite(c, teamID) {
		return
	}

	var body patchSandboxRequest
	if err := bindJSONStrict(c, &body); err != nil {
		respondErrorMsg(c, "bad_request", "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Reject empty patches.
	if body.Network == nil && body.Metadata == nil && !body.AutoDeleteSeconds.Set && !body.TimeoutSeconds.Set {
		respondErrorMsg(c, "bad_request", "patch body must include at least one field (network, metadata, auto_delete_seconds, timeout_seconds)", http.StatusBadRequest)
		return
	}

	if body.AutoDeleteSeconds.Set {
		if err := validateAutoDeleteSeconds(body.AutoDeleteSeconds.Value); err != nil {
			respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
			return
		}
	}
	if body.TimeoutSeconds.Set {
		if err := validateTimeoutSeconds(body.TimeoutSeconds.Value); err != nil {
			respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
			return
		}
	}

	if body.Network != nil {
		if err := validateEgressRules(body.Network.AllowOut, body.Network.DenyOut); err != nil {
			respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
			return
		}
	}

	if body.Metadata != nil {
		if err := validateMetadata(body.Metadata); err != nil {
			respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
			return
		}
	}

	// Verify sandbox exists, belongs to this team, and is active.
	sandbox, err := h.DB.GetSandbox(c.Request.Context(), db.GetSandboxParams{
		ID:     sandboxID,
		TeamID: teamID,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			respondError(c, ErrSandboxNotFound)
			return
		}
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB GetSandbox failed")
		respondError(c, ErrInternal)
		return
	}

	// Network updates require an active sandbox (rules are applied live to the VM).
	if body.Network != nil && sandbox.Status != db.SandboxStatusActive {
		respondErrorMsg(c, "conflict", "Sandbox must be active to update network config", http.StatusConflict)
		return
	}

	if body.Network != nil {
		// Separate CIDRs and domains from allow_out.
		var allowedCIDRs, allowedDomains []string
		for _, entry := range body.Network.AllowOut {
			if isIPOrCIDR(entry) {
				allowedCIDRs = append(allowedCIDRs, entry)
			} else {
				allowedDomains = append(allowedDomains, entry)
			}
		}

		// Resolve the VMD client for this sandbox's host.
		vmd, vmdLookupErr := h.vmdForHost(c.Request.Context(), sandbox.HostID)
		if vmdLookupErr != nil {
			log.Error().Err(vmdLookupErr).Str("sandbox_id", sandboxID.String()).Msg("resolve VMD for patch failed")
			respondError(c, ErrInternal)
			return
		}

		// Apply rules to the running VM via VMD.
		vmdCtx, vmdCancel := context.WithTimeout(c.Request.Context(), vmdTimeout)
		defer vmdCancel()
		if err := vmd.UpdateSandboxNetwork(vmdCtx, sandboxID.String(), allowedCIDRs, body.Network.DenyOut, allowedDomains); err != nil {
			log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("VMD UpdateSandboxNetwork failed")
			respondError(c, ErrInternal)
			return
		}

		// Persist config to DB so it survives pause/resume.
		networkConfig, _ := json.Marshal(map[string]any{
			"egress": map[string]any{
				"allowed_cidrs":   allowedCIDRs,
				"denied_cidrs":    body.Network.DenyOut,
				"allowed_domains": allowedDomains,
			},
		})
		if err := h.DB.UpdateSandboxNetworkConfig(c.Request.Context(), db.UpdateSandboxNetworkConfigParams{
			ID:            sandboxID,
			NetworkConfig: networkConfig,
			TeamID:        teamID,
		}); err != nil {
			log.Warn().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB UpdateSandboxNetworkConfig failed (rules applied, persistence failed)")
		}

		h.logSandboxActivity(c.Request.Context(), sandbox.ID, teamID, actorIDFromContext(c), "network", "updated", "success", &sandbox.Name, nil, networkConfig)
		h.capture(c, "sandbox_network_updated", map[string]any{"sandbox_id": sandboxID.String()})

		// Push the egress-rules invalidation so the secrets proxy re-fetches the
		// new rules immediately; the daemon's cache TTL is the fallback if this
		// best-effort push fails. Detached context — the gin.Context is recycled
		// once the handler returns.
		go func() {
			ictx, icancel := context.WithTimeout(context.Background(), vmdTimeout)
			defer icancel()
			if err := vmd.InvalidateSandboxRules(ictx, sandboxID.String()); err != nil {
				log.Warn().Err(err).Str("sandbox_id", sandboxID.String()).Msg("PATCH: invalidate sandbox rules failed (TTL fallback)")
			}
		}()
	}

	if body.Metadata != nil {
		metadataJSON, err := json.Marshal(body.Metadata)
		if err != nil {
			log.Error().Err(err).Msg("marshal patch metadata")
			respondError(c, ErrInternal)
			return
		}
		if err := h.DB.UpdateSandboxMetadata(c.Request.Context(), db.UpdateSandboxMetadataParams{
			ID:       sandboxID,
			Metadata: metadataJSON,
			TeamID:   teamID,
		}); err != nil {
			log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB UpdateSandboxMetadata failed")
			respondError(c, ErrInternal)
			return
		}

		h.logSandboxActivity(c.Request.Context(), sandbox.ID, teamID, actorIDFromContext(c), "sandbox", "metadata_updated", "success", &sandbox.Name, nil, nil)
	}

	if body.AutoDeleteSeconds.Set {
		if !h.applyRowsAffectedPatch(c, sandbox, teamID, "auto_delete_updated", func() (int64, error) {
			return h.DB.UpdateSandboxAutoDelete(c.Request.Context(), db.UpdateSandboxAutoDeleteParams{
				ID:                sandboxID,
				AutoDeleteSeconds: body.AutoDeleteSeconds.Value,
				TeamID:            teamID,
			})
		}) {
			return
		}
	}

	if body.TimeoutSeconds.Set {
		if !h.applyRowsAffectedPatch(c, sandbox, teamID, "timeout_updated", func() (int64, error) {
			return h.DB.UpdateSandboxTimeout(c.Request.Context(), db.UpdateSandboxTimeoutParams{
				ID:             sandboxID,
				TimeoutSeconds: body.TimeoutSeconds.Value,
				TeamID:         teamID,
			})
		}) {
			return
		}
	}

	c.Status(http.StatusNoContent)
}

// applyRowsAffectedPatch runs a rows-affected sandbox update and maps the
// result: 500 on error, 404 on 0 rows (sandbox deleted between the read and the
// update), activity log on success. Returns false if a response was written.
func (h *Handlers) applyRowsAffectedPatch(c *gin.Context, sandbox db.Sandbox, teamID uuid.UUID, action string, exec func() (int64, error)) bool {
	rows, err := exec()
	if err != nil {
		log.Error().Err(err).Str("sandbox_id", sandbox.ID.String()).Str("patch", action).Msg("DB sandbox patch failed")
		respondError(c, ErrInternal)
		return false
	}
	if rows == 0 {
		respondError(c, ErrSandboxNotFound)
		return false
	}
	h.logSandboxActivity(c.Request.Context(), sandbox.ID, teamID, actorIDFromContext(c), "sandbox", action, "success", &sandbox.Name, nil, nil)
	return true
}

// maxAutoDeleteSeconds caps the auto-delete window at 30 days — generous for
// any delayed-cleanup flow while keeping the deadline arithmetic within sane
// bounds.
const maxAutoDeleteSeconds int32 = 30 * 24 * 3600

// maxTimeoutSeconds caps the auto-pause timeout at 7 days — a safety ceiling
// so runaway "I set timeout=huge and forgot" sandboxes cannot stay active
// forever, while still supporting genuinely long-running workloads.
const maxTimeoutSeconds int32 = 7 * 24 * 3600

// validateTimeoutSeconds bounds-checks a timeout_seconds value from create or
// patch. Nil is valid — it means no auto-pause. Zero is rejected: "pause
// immediately" is not a meaningful timeout.
func validateTimeoutSeconds(v *int32) error {
	if v != nil && (*v < 1 || *v > maxTimeoutSeconds) {
		return fmt.Errorf("timeout_seconds must be between 1 and %d (7 days), or null to disable", maxTimeoutSeconds)
	}
	return nil
}

// validateAutoDeleteSeconds bounds-checks an auto_delete_seconds value from
// create or patch. Nil is valid — it means auto-delete is disabled. Zero is
// valid and means "delete as soon as the sandbox pauses".
func validateAutoDeleteSeconds(v *int32) error {
	if v != nil && (*v < 0 || *v > maxAutoDeleteSeconds) {
		return fmt.Errorf("auto_delete_seconds must be between 0 and %d (30 days), or null to disable", maxAutoDeleteSeconds)
	}
	return nil
}

// bindJSONStrict decodes the request body into v and rejects unknown fields.
//
// This is stricter than gin's c.ShouldBindJSON which silently ignores fields
// not present in the target struct. Strict binding is important for fields
// we intentionally removed (e.g. vcpu_count, memory_mib) so old clients get
// a clear 400 error instead of silently losing their request data.
//
// Returns nil on success, or an error suitable for a 400 Bad Request.
func bindJSONStrict(c *gin.Context, v any) error {
	if c.Request.Body == nil {
		return fmt.Errorf("request body is empty")
	}
	dec := json.NewDecoder(c.Request.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	// Reject trailing garbage / multiple JSON objects.
	if dec.More() {
		return fmt.Errorf("unexpected trailing data after JSON object")
	}
	return nil
}

// nullableStr maps "" → nil and any other string → &s. Used for nullable
// text columns so we don't store empty strings in the DB.
func nullableStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// isIPOrCIDR returns true if s is a valid IP address or CIDR prefix.
// Used to distinguish CIDR entries from domain names in allow/deny lists.
func isIPOrCIDR(s string) bool {
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	return false
}

// validateEgressRules enforces the rules shared between CreateSandbox and
// PatchSandbox:
//
//   - deny_out entries MUST be valid IPv4 CIDRs or IP addresses (domains
//     are not supported in deny lists — there's no way to enforce a domain
//     deny at the IP layer, and mixing silently fails).
//   - allow_out entries can be either IPv4 CIDRs/IPs or domain names.
//   - IPv6 entries are rejected everywhere. Sandboxes are IPv4-only and
//     all IPv6 egress is dropped wholesale by the nftables firewall; we
//     reject v6 in the API instead of silently ignoring it so users get
//     a clear error.
//
// Limits on user-supplied metadata. These are deliberately conservative —
// metadata is meant for tags ("env=prod", "owner=agent-7"), not for shipping
// arbitrary blobs through the sandbox API. Tighter limits also keep the
// jsonb @> filter cheap and bound the cost of the GIN index.
const (
	metadataMaxKeys       = 64    // distinct key/value pairs per sandbox
	metadataMaxKeyLen     = 256   // bytes per key
	metadataMaxValueLen   = 2048  // bytes per value (2 KB)
	metadataMaxTotalBytes = 16384 // total serialized jsonb size (16 KB)
)

// metadataReservedPrefixes are key prefixes the platform reserves for its
// own use. Today nothing actually emits these, but reserving them now means
// we can introduce internal tags later (e.g., `superserve.billing.tier`)
// without having to migrate user data out of the way. The check is
// case-insensitive so users can't sneak through with `Superserve.foo`.
var metadataReservedPrefixes = []string{"superserve.", "_superserve"}

// validateMetadata enforces all the size and naming rules on a user-supplied
// metadata map. Returns nil on success or a 400-appropriate error.
//
// nil and empty maps are both fine — they yield an empty jsonb object in
// the database. The caller is responsible for marshalling.
//
// Important: this validation is the *only* place where reserved prefixes
// are enforced, so any new code that writes to sandbox.metadata must route
// through here (or add its own check). Today the only writer is
// CreateSandbox.
func validateMetadata(md map[string]string) error {
	if len(md) == 0 {
		return nil
	}
	if len(md) > metadataMaxKeys {
		return fmt.Errorf("metadata has %d keys, max is %d", len(md), metadataMaxKeys)
	}

	totalBytes := 0
	for k, v := range md {
		if k == "" {
			return fmt.Errorf("metadata keys cannot be empty")
		}
		if len(k) > metadataMaxKeyLen {
			return fmt.Errorf("metadata key %q is %d bytes, max is %d", k, len(k), metadataMaxKeyLen)
		}
		if len(v) > metadataMaxValueLen {
			return fmt.Errorf("metadata value for key %q is %d bytes, max is %d", k, len(v), metadataMaxValueLen)
		}
		lower := strings.ToLower(k)
		for _, prefix := range metadataReservedPrefixes {
			if strings.HasPrefix(lower, prefix) {
				return fmt.Errorf("metadata key %q uses reserved prefix %q", k, prefix)
			}
		}
		totalBytes += len(k) + len(v)
		if totalBytes > metadataMaxTotalBytes {
			return fmt.Errorf("metadata exceeds %d bytes total", metadataMaxTotalBytes)
		}
	}
	return nil
}

// Env var validation limits. Same key count cap as metadata; values are
// larger (API keys, connection strings) so 8 KB per value, 64 KB total.
const (
	envVarsMaxKeys       = 64
	envVarsMaxKeyLen     = 256
	envVarsMaxValueLen   = 8192  // 8 KB — API keys, tokens, DSNs
	envVarsMaxTotalBytes = 65536 // 64 KB
)

func validateEnvVars(env map[string]string) error {
	if len(env) == 0 {
		return nil
	}
	if len(env) > envVarsMaxKeys {
		return fmt.Errorf("env_vars has %d keys, max is %d", len(env), envVarsMaxKeys)
	}
	totalBytes := 0
	for k, v := range env {
		if k == "" {
			return fmt.Errorf("env_vars keys cannot be empty")
		}
		for _, c := range k {
			if c == '=' || c == 0 {
				return fmt.Errorf("env_vars key %q contains invalid character", k)
			}
		}
		if len(k) > envVarsMaxKeyLen {
			return fmt.Errorf("env_vars key %q is %d bytes, max is %d", k, len(k), envVarsMaxKeyLen)
		}
		if len(v) > envVarsMaxValueLen {
			return fmt.Errorf("env_vars value for key %q is %d bytes, max is %d", k, len(v), envVarsMaxValueLen)
		}
		totalBytes += len(k) + len(v)
		if totalBytes > envVarsMaxTotalBytes {
			return fmt.Errorf("env_vars exceeds %d bytes total", envVarsMaxTotalBytes)
		}
	}
	return nil
}

// Returns nil on success or a 400-appropriate error message.
func validateEgressRules(allowOut, denyOut []string) error {
	for _, entry := range denyOut {
		if !isIPOrCIDR(entry) {
			return fmt.Errorf("deny_out only supports CIDRs, got %q", entry)
		}
		if isIPv6(entry) {
			return fmt.Errorf("IPv6 is not supported, got %q in deny_out", entry)
		}
	}
	for _, entry := range allowOut {
		if isIPOrCIDR(entry) && isIPv6(entry) {
			return fmt.Errorf("IPv6 is not supported, got %q in allow_out", entry)
		}
	}
	return nil
}

// isIPv6 returns true if s is a valid IPv6 address or IPv6 CIDR.
// Assumes the caller has already confirmed via isIPOrCIDR that s parses.
func isIPv6(s string) bool {
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.Is6() && !addr.Is4In6()
	}
	if prefix, err := netip.ParsePrefix(s); err == nil {
		return prefix.Addr().Is6() && !prefix.Addr().Is4In6()
	}
	return false
}
