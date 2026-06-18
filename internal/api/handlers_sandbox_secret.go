package api

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"sync"

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

	existing, err := h.DB.ListSandboxSecretBindings(ctx, sandboxID)
	if err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB ListSandboxSecretBindings during attach")
		respondError(c, ErrInternal)
		return
	}
	for _, b := range existing {
		if b.EnvKey == req.EnvKey {
			respondErrorMsg(c, "conflict", fmt.Sprintf("env-var key %q is already bound on this sandbox", req.EnvKey), http.StatusConflict)
			return
		}
	}
	if len(existing) >= SecretsBindingsCap {
		respondErrorMsg(c, "bad_request", fmt.Sprintf("sandbox already has the max %d secret bindings", SecretsBindingsCap), http.StatusBadRequest)
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

	if err := h.DB.AddSandboxSecret(ctx, db.AddSandboxSecretParams{
		SandboxID:  sandboxID,
		SecretID:   secret.ID,
		EnvKey:     req.EnvKey,
		ProxyToken: &token,
	}); err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("insert sandbox secret binding")
		respondError(c, ErrInternal)
		return
	}

	// A running sandbox is updated now; a paused one picks it up on resume. Fail
	// closed: roll back the row if the proxy JWT can't be re-minted/injected.
	if sandbox.Status == db.SandboxStatusActive {
		meta, lerr := h.loadSecretBindingMeta(ctx, sandboxID)
		if lerr == nil {
			lerr = h.applySecretBindings(ctx, sandbox, meta)
		}
		if lerr != nil {
			log.Error().Err(lerr).Str("sandbox_id", sandboxID.String()).Msg("apply secret bindings on attach")
			_, _ = h.DB.DeleteSandboxSecretBinding(ctx, db.DeleteSandboxSecretBindingParams{SandboxID: sandboxID, EnvKey: req.EnvKey})
			respondError(c, ErrInternal)
			return
		}
	}

	h.logSandboxActivity(ctx, sandboxID, teamID, actorIDFromContext(c), "secret", "attached", "success", &sandbox.Name, nil, nil)
	c.JSON(http.StatusCreated, gin.H{"env_key": req.EnvKey, "secret_name": req.SecretName})
}

// DetachSandboxSecret removes a secret binding from an existing sandbox.
// DELETE /sandboxes/{id}/secrets/{env_key}.
func (h *Handlers) DetachSandboxSecret(c *gin.Context) {
	if !h.requireEncryptor(c) {
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

	deleted, err := h.DB.DeleteSandboxSecretBinding(ctx, db.DeleteSandboxSecretBindingParams{SandboxID: sandboxID, EnvKey: envKey})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondErrorMsg(c, "not_found", fmt.Sprintf("no secret bound under env-var key %q on this sandbox", envKey), http.StatusNotFound)
			return
		}
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("delete sandbox secret binding")
		respondError(c, ErrInternal)
		return
	}

	// A running sandbox is updated now; a paused one picks it up on resume. Fail
	// closed: restore the row if the reduced set can't be re-minted/injected.
	if sandbox.Status == db.SandboxStatusActive {
		meta, lerr := h.loadSecretBindingMeta(ctx, sandboxID)
		if lerr == nil {
			lerr = h.applySecretBindings(ctx, sandbox, meta)
		}
		if lerr != nil {
			log.Error().Err(lerr).Str("sandbox_id", sandboxID.String()).Msg("apply secret bindings on detach")
			_ = h.DB.AddSandboxSecret(ctx, db.AddSandboxSecretParams{
				SandboxID:  sandboxID,
				SecretID:   deleted.SecretID,
				EnvKey:     envKey,
				ProxyToken: deleted.ProxyToken,
			})
			respondError(c, ErrInternal)
			return
		}
	}

	h.logSandboxActivity(ctx, sandboxID, teamID, actorIDFromContext(c), "secret", "detached", "success", &sandbox.Name, nil, nil)
	c.Status(http.StatusNoContent)
}
