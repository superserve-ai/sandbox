package api

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
)

// Secret-binding mutations are serialized per sandbox so concurrent changes can't
// re-mint over a stale binding set. Striped to bound memory; an occasional shared
// stripe just serializes two unrelated sandboxes.
const sandboxSecretLockStripes = 256

var sandboxSecretLocks [sandboxSecretLockStripes]sync.Mutex

func lockSandboxSecrets(sandboxID uuid.UUID) func() {
	mu := &sandboxSecretLocks[binary.LittleEndian.Uint64(sandboxID[:8])%sandboxSecretLockStripes]
	mu.Lock()
	return mu.Unlock
}

// Sentinels so the attach insert (run inside a transaction) can map validation
// outcomes back to HTTP statuses after the transaction closes.
var (
	errBindingExists        = errors.New("env key already bound on sandbox")
	errBindingCapReached    = errors.New("sandbox binding cap reached")
	errSandboxMidTransition = errors.New("sandbox not in a mutable state")
	errSnapshotInFlight     = errors.New("a snapshot of the sandbox is being captured")
)

// refuseDuringCapture keeps the guest a capture images at the bindings its
// row records: the row is written under the sandbox's secret-write lock,
// which the caller holds, and while it is creating the sweep may capture
// again, so no binding may change until it settles or is deleted.
func refuseDuringCapture(ctx context.Context, q *db.Queries, sandboxID uuid.UUID) error {
	inFlight, err := q.SandboxSnapshotCaptureInFlight(ctx, sandboxID)
	if err != nil {
		return err
	}
	if inFlight {
		return errSnapshotInFlight
	}
	return nil
}

// detachedKeysKept bounds a sandbox's detached keys. Past it the oldest
// key's revoked token may survive into a fork, where it is inert.
const detachedKeysKept = 64

// recordDetachedKey remembers a key detached from the sandbox until its
// guest is known to have dropped it.
func recordDetachedKey(ctx context.Context, q *db.Queries, sandboxID uuid.UUID, envKey string) error {
	if err := q.RecordDetachedSecretKey(ctx, db.RecordDetachedSecretKeyParams{SandboxID: sandboxID, EnvKey: envKey}); err != nil {
		return err
	}
	return q.PruneDetachedSecretKeys(ctx, db.PruneDetachedSecretKeysParams{SandboxID: sandboxID, Keep: detachedKeysKept})
}

// undoAttach takes back a binding whose guest update failed, under the
// secret-write lock like any binding change. It is not refused during a
// capture: any snapshot taken since the attach began may have recorded the
// binding, settled or not, and has it withdrawn, as do sandboxes already
// created from one, so no fork keeps it.
// boxd may have applied the env before the error, so the token is revoked
// and the key recorded as detached.
func (h *Handlers) undoAttach(ctx context.Context, sandboxID, secretID uuid.UUID, envKey, token string, since time.Time) error {
	undo := func(q *db.Queries) error {
		if h.Pool != nil {
			if err := q.LockSandboxForSecretWrites(ctx, sandboxID.String()); err != nil {
				return err
			}
		}
		if _, err := q.DeleteSandboxSecretBinding(ctx, db.DeleteSandboxSecretBindingParams{SandboxID: sandboxID, EnvKey: envKey}); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err := recordDetachedKey(ctx, q, sandboxID, envKey); err != nil {
			return err
		}
		if err := q.InsertRevokedProxyToken(ctx, db.InsertRevokedProxyTokenParams{
			SandboxID:  sandboxID,
			ProxyToken: token,
			ExpiresAt:  time.Now().Add(SecretsJWTLifetime),
		}); err != nil {
			return err
		}
		// The snapshots first: the update waits out any fork still inserting
		// from one, so the forks' read below sees that fork too.
		if err := q.WithdrawBindingFromSnapshots(ctx, db.WithdrawBindingFromSnapshotsParams{
			SandboxID: sandboxID, EnvKey: envKey, SecretID: secretID, Since: since,
		}); err != nil {
			return err
		}
		forks, err := q.WithdrawBindingFromForks(ctx, db.WithdrawBindingFromForksParams{
			SandboxID: sandboxID, Since: since, EnvKey: envKey, SecretID: secretID,
		})
		if err != nil {
			return err
		}
		for _, f := range forks {
			if f.ProxyToken == nil || *f.ProxyToken == "" {
				continue
			}
			if err := q.InsertRevokedProxyToken(ctx, db.InsertRevokedProxyTokenParams{
				SandboxID: f.SandboxID, ProxyToken: *f.ProxyToken, ExpiresAt: time.Now().Add(SecretsJWTLifetime),
			}); err != nil {
				return err
			}
		}
		return nil
	}
	if h.Pool == nil {
		return undo(h.DB)
	}
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := undo(h.DB.WithTx(tx)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func respondSnapshotInFlight(c *gin.Context) {
	c.Header("Retry-After", "5")
	respondErrorMsg(c, "snapshot_in_progress", "a snapshot of this sandbox is being taken; retry once it is ready or failed, or delete it", http.StatusConflict)
}

type attachSecretRequest struct {
	EnvKey     string `json:"env_key"`
	SecretName string `json:"secret_name"`
}

// AttachSandboxSecret binds a stored secret to an existing sandbox under an env var.
// Takes effect for processes started after the call. POST /sandboxes/{id}/secrets.
func (h *Handlers) AttachSandboxSecret(c *gin.Context) {
	if !h.requireEncryptor(c) {
		return
	}
	// A binding can only be honored once it's minted into a JWT (now if active, on
	// resume if paused). Reject up front when no signer is configured rather than
	// bank a paused binding that would later fail to mint.
	if h.Signer == nil {
		log.Error().Msg("secret attach requested but no secrets signer configured")
		respondError(c, ErrInternal)
		return
	}
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

	var req attachSecretRequest
	if err := bindJSONStrict(c, &req); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateSecretsRefs(map[string]string{req.EnvKey: req.SecretName}); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}

	unlock := lockSandboxSecrets(sandboxID)
	defer unlock()

	ctx := c.Request.Context()
	sandbox, err := h.DB.GetSandbox(ctx, db.GetSandboxParams{ID: sandboxID, TeamID: teamID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondErrorMsg(c, "not_found", "Sandbox not found", http.StatusNotFound)
			return
		}
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB GetSandbox during secret attach")
		respondError(c, ErrInternal)
		return
	}
	switch sandbox.Status {
	case db.SandboxStatusActive, db.SandboxStatusPaused:
	default:
		respondErrorMsg(c, "conflict", "sandbox is not in a state that accepts secret changes", http.StatusConflict)
		return
	}

	secret, err := h.DB.GetSecretByName(ctx, db.GetSecretByNameParams{TeamID: teamID, Name: req.SecretName})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondErrorMsg(c, "bad_request", fmt.Sprintf("secret %q does not exist for this team", req.SecretName), http.StatusBadRequest)
			return
		}
		log.Error().Err(err).Str("name", req.SecretName).Msg("DB GetSecretByName during attach")
		respondError(c, ErrInternal)
		return
	}
	token, err := mintProxyToken(secret.ProviderShortcut)
	if err != nil {
		log.Error().Err(err).Msg("mintProxyToken during attach")
		respondError(c, ErrInternal)
		return
	}

	// Check the cap and insert under a transaction-scoped advisory lock so two
	// attaches to the same sandbox on different API instances can't both pass the
	// cap and exceed it — which would later wedge re-minting. The in-process lock
	// only covers one instance. Env-key collisions are caught by the PK.
	var liveSandbox db.Sandbox
	// When the binding became visible, at the latest: a snapshot older than
	// this cannot have recorded it.
	var attachStarted time.Time
	insertBinding := func(q *db.Queries) error {
		if h.Pool != nil {
			if lerr := q.LockSandboxForSecretWrites(ctx, sandboxID.String()); lerr != nil {
				return lerr
			}
			started, lerr := q.TransactionStartedAt(ctx)
			if lerr != nil {
				return lerr
			}
			attachStarted = started
		}
		// Re-read status under the lock: a resume on another instance may have
		// flipped it since the early read. The live status decides whether we
		// inject now, so an attach can't skip injection on a stale 'paused'.
		sb, lerr := q.GetSandbox(ctx, db.GetSandboxParams{ID: sandboxID, TeamID: teamID})
		if lerr != nil {
			return lerr
		}
		switch sb.Status {
		case db.SandboxStatusActive, db.SandboxStatusPaused:
		default:
			return errSandboxMidTransition
		}
		liveSandbox = sb
		if lerr := refuseDuringCapture(ctx, q, sandboxID); lerr != nil {
			return lerr
		}
		existing, lerr := q.ListSandboxSecretBindings(ctx, sandboxID)
		if lerr != nil {
			return lerr
		}
		for _, b := range existing {
			if b.EnvKey == req.EnvKey {
				return errBindingExists
			}
		}
		if len(existing) >= SecretsBindingsCap {
			return errBindingCapReached
		}
		// 0 rows means a destroy committed between the read above and this
		// write. Bail before the JWT is minted: the revocation gate already
		// read had_secret_bindings, so a credential issued now would not be
		// revoked.
		bound, lerr := q.AddSandboxSecret(ctx, db.AddSandboxSecretParams{
			SandboxID:  sandboxID,
			SecretID:   secret.ID,
			EnvKey:     req.EnvKey,
			ProxyToken: &token,
		})
		if lerr != nil {
			return lerr
		}
		if bound == 0 {
			return errSandboxMidTransition
		}
		return q.ForgetDetachedSecretKey(ctx, db.ForgetDetachedSecretKeyParams{SandboxID: sandboxID, EnvKey: req.EnvKey})
	}

	if h.Pool == nil {
		err = insertBinding(h.DB)
	} else {
		var tx pgx.Tx
		if tx, err = h.Pool.Begin(ctx); err == nil {
			defer tx.Rollback(ctx)
			if err = insertBinding(h.DB.WithTx(tx)); err == nil {
				err = tx.Commit(ctx)
			}
		}
	}
	switch {
	case errors.Is(err, errSnapshotInFlight):
		respondSnapshotInFlight(c)
		return
	case errors.Is(err, errBindingExists):
		respondErrorMsg(c, "conflict", fmt.Sprintf("env-var key %q is already bound on this sandbox", req.EnvKey), http.StatusConflict)
		return
	case errors.Is(err, errBindingCapReached):
		respondErrorMsg(c, "bad_request", fmt.Sprintf("sandbox already has the max %d secret bindings", SecretsBindingsCap), http.StatusBadRequest)
		return
	case errors.Is(err, errSandboxMidTransition):
		respondErrorMsg(c, "conflict", "sandbox is not in a state that accepts secret changes", http.StatusConflict)
		return
	case err != nil:
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("insert sandbox secret binding")
		respondError(c, ErrInternal)
		return
	}

	// A running sandbox is updated now; a paused one picks it up on resume. The
	// status read under the lock is authoritative. Fail closed: roll back the row
	// if the proxy JWT can't be re-minted/injected.
	if liveSandbox.Status == db.SandboxStatusActive {
		meta, lerr := h.loadSecretBindingMeta(ctx, sandboxID)
		if lerr == nil {
			lerr = h.applySecretBindings(ctx, liveSandbox, meta)
		}
		if lerr != nil {
			log.Error().Err(lerr).Str("sandbox_id", sandboxID.String()).Msg("apply secret bindings on attach")
			// Detached context so a client disconnect can't fail both the apply and
			// its rollback, leaving the row behind after a 500.
			rbCtx, rbCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer rbCancel()
			if rerr := h.undoAttach(rbCtx, sandboxID, secret.ID, req.EnvKey, token, attachStarted); rerr != nil {
				log.Error().Err(rerr).Str("sandbox_id", sandboxID.String()).Msg("undo a failed secret attach")
			}
			respondError(c, ErrInternal)
			return
		}
	}

	h.logSandboxActivity(ctx, sandboxID, teamID, actorIDFromContext(c), "secret", "attached", "success", &sandbox.Name, nil, nil)
	c.JSON(http.StatusCreated, gin.H{"env_key": req.EnvKey, "secret_name": req.SecretName})
}

// DetachSandboxSecret removes a secret binding from an existing sandbox.
// DELETE /sandboxes/{id}/secrets/{env_key}.
//
// Not gated on the encryptor: revocation must stay available even when the
// encryptor is down, and detach touches no secret material.
func (h *Handlers) DetachSandboxSecret(c *gin.Context) {
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
	envKey := c.Param("env_key")
	if envKey == "" {
		respondErrorMsg(c, "bad_request", "env_key is required", http.StatusBadRequest)
		return
	}

	unlock := lockSandboxSecrets(sandboxID)
	defer unlock()

	ctx := c.Request.Context()
	sandbox, err := h.DB.GetSandbox(ctx, db.GetSandboxParams{ID: sandboxID, TeamID: teamID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondErrorMsg(c, "not_found", "Sandbox not found", http.StatusNotFound)
			return
		}
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB GetSandbox during secret detach")
		respondError(c, ErrInternal)
		return
	}
	switch sandbox.Status {
	case db.SandboxStatusActive, db.SandboxStatusPaused:
	default:
		respondErrorMsg(c, "conflict", "sandbox is not in a state that accepts secret changes", http.StatusConflict)
		return
	}

	// Delete the binding and revoke its token in one transaction, on a detached
	// context so a client disconnect can't half-commit. A 204 therefore guarantees
	// the token is recorded as revoked, independent of the re-mint below.
	mutCtx, mutCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer mutCancel()

	deleteAndRevoke := func(q *db.Queries) error {
		// A snapshot records the bindings under this lock, so this detach
		// lands before its row or after it, never between.
		if h.Pool != nil {
			if lerr := q.LockSandboxForSecretWrites(mutCtx, sandboxID.String()); lerr != nil {
				return lerr
			}
		}
		if lerr := refuseDuringCapture(mutCtx, q, sandboxID); lerr != nil {
			return lerr
		}
		deleted, derr := q.DeleteSandboxSecretBinding(mutCtx, db.DeleteSandboxSecretBindingParams{SandboxID: sandboxID, EnvKey: envKey})
		if derr != nil {
			return derr
		}
		if derr := recordDetachedKey(mutCtx, q, sandboxID, envKey); derr != nil {
			return derr
		}
		// A binding stored before tokens were persisted has no stored token to
		// record here.
		if deleted.ProxyToken == nil || *deleted.ProxyToken == "" {
			return nil
		}
		return q.InsertRevokedProxyToken(mutCtx, db.InsertRevokedProxyTokenParams{
			SandboxID:  sandboxID,
			ProxyToken: *deleted.ProxyToken,
			ExpiresAt:  time.Now().Add(SecretsJWTLifetime),
		})
	}

	if h.Pool == nil {
		// No pool (DBTX-mocked unit tests): run the two writes directly.
		err = deleteAndRevoke(h.DB)
	} else {
		var tx pgx.Tx
		if tx, err = h.Pool.Begin(mutCtx); err == nil {
			defer tx.Rollback(mutCtx)
			if err = deleteAndRevoke(h.DB.WithTx(tx)); err == nil {
				err = tx.Commit(mutCtx)
			}
		}
	}
	if err != nil {
		if errors.Is(err, errSnapshotInFlight) {
			respondSnapshotInFlight(c)
			return
		}
		if errors.Is(err, pgx.ErrNoRows) {
			respondErrorMsg(c, "not_found", fmt.Sprintf("no secret bound under env-var key %q on this sandbox", envKey), http.StatusNotFound)
			return
		}
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("detach secret binding")
		respondError(c, ErrInternal)
		return
	}

	// Re-mint the reduced set for a running sandbox, clearing the detached key
	// from its guest; a paused one re-mints on resume. Best-effort — the
	// revocation above already enforces the detach, so a re-mint failure is
	// not fatal. Once the guest has dropped the key it need not be remembered.
	if sandbox.Status == db.SandboxStatusActive {
		if meta, lerr := h.loadSecretBindingMeta(ctx, sandboxID); lerr != nil {
			log.Warn().Err(lerr).Str("sandbox_id", sandboxID.String()).Msg("load secret bindings after detach")
		} else if aerr := h.applySecretBindings(ctx, sandbox, meta, envKey); aerr != nil {
			log.Warn().Err(aerr).Str("sandbox_id", sandboxID.String()).Msg("re-mint secret bindings after detach")
		} else if ferr := h.DB.ForgetDetachedSecretKey(mutCtx, db.ForgetDetachedSecretKeyParams{SandboxID: sandboxID, EnvKey: envKey}); ferr != nil {
			log.Warn().Err(ferr).Str("sandbox_id", sandboxID.String()).Msg("forget a detached key the guest dropped")
		}
	}

	h.logSandboxActivity(ctx, sandboxID, teamID, actorIDFromContext(c), "secret", "detached", "success", &sandbox.Name, nil, nil)
	c.Status(http.StatusNoContent)
}
