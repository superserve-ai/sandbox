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
)

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
	insertBinding := func(q *db.Queries) error {
		if h.Pool != nil {
			if lerr := q.LockSandboxForSecretWrites(ctx, sandboxID.String()); lerr != nil {
				return lerr
			}
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
		return q.AddSandboxSecret(ctx, db.AddSandboxSecretParams{
			SandboxID:  sandboxID,
			SecretID:   secret.ID,
			EnvKey:     req.EnvKey,
			ProxyToken: &token,
		})
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
			_, _ = h.DB.DeleteSandboxSecretBinding(rbCtx, db.DeleteSandboxSecretBindingParams{SandboxID: sandboxID, EnvKey: req.EnvKey})
			// boxd may have committed the env/JWT before the apply errored, so revoke
			// the token too — the binding's credential must not outlive its row.
			_ = h.DB.InsertRevokedProxyToken(rbCtx, db.InsertRevokedProxyTokenParams{
				SandboxID:  sandboxID,
				ProxyToken: token,
				ExpiresAt:  time.Now().Add(SecretsJWTLifetime),
			})
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
		deleted, derr := q.DeleteSandboxSecretBinding(mutCtx, db.DeleteSandboxSecretBindingParams{SandboxID: sandboxID, EnvKey: envKey})
		if derr != nil {
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
		if errors.Is(err, pgx.ErrNoRows) {
			respondErrorMsg(c, "not_found", fmt.Sprintf("no secret bound under env-var key %q on this sandbox", envKey), http.StatusNotFound)
			return
		}
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("detach secret binding")
		respondError(c, ErrInternal)
		return
	}

	// Re-mint the reduced set for a running sandbox; a paused one re-mints on
	// resume. Best-effort — the revocation above already enforces the detach, so a
	// re-mint failure is not fatal.
	if sandbox.Status == db.SandboxStatusActive {
		if meta, lerr := h.loadSecretBindingMeta(ctx, sandboxID); lerr != nil {
			log.Warn().Err(lerr).Str("sandbox_id", sandboxID.String()).Msg("load secret bindings after detach")
		} else if aerr := h.applySecretBindings(ctx, sandbox, meta); aerr != nil {
			log.Warn().Err(aerr).Str("sandbox_id", sandboxID.String()).Msg("re-mint secret bindings after detach")
		}
	}

	h.logSandboxActivity(ctx, sandboxID, teamID, actorIDFromContext(c), "secret", "detached", "success", &sandbox.Name, nil, nil)
	c.Status(http.StatusNoContent)
}
