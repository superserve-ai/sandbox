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
	"github.com/jackc/pgx/v5/pgxpool"
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

// holdSecretWrites takes the sandbox's secret-write lock for as long as one
// connection is held rather than one transaction: an attach keeps it
// through its guest update and any undo, so nothing that records bindings,
// a capture or a detach, sees a binding whose attach may yet be undone.
// release unlocks, or discards the connection when it cannot, so the lock
// never returns to the pool with it.
func (h *Handlers) holdSecretWrites(ctx context.Context, sandboxID uuid.UUID) (*pgxpool.Conn, func(), error) {
	conn, err := h.Pool.Acquire(ctx)
	if err != nil {
		return nil, nil, err
	}
	if err := db.New(conn).HoldSandboxSecretWrites(ctx, sandboxID.String()); err != nil {
		// The lock may have been taken before the error: never pooled again.
		cctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = conn.Conn().Close(cctx)
		cancel()
		conn.Release()
		return nil, nil, err
	}
	release := func() {
		uctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if ok, err := db.New(conn).ReleaseSandboxSecretWrites(uctx, sandboxID.String()); err != nil || !ok {
			_ = conn.Conn().Close(uctx)
		}
		conn.Release()
	}
	return conn, release, nil
}

// secretWrites is one secret mutation's hold on the sandbox's secret-write
// lock, its guest update included. Its queries run on the held connection
// and nothing else touches the database until release: a second pooled
// connection taken while holding one could wait on a pool the request
// helps drain. Without a pool (unit tests) nothing is held.
type secretWrites struct {
	q       *db.Queries
	held    *pgxpool.Conn
	release func()
}

func (h *Handlers) beginSecretWrites(ctx context.Context, sandboxID uuid.UUID) (*secretWrites, error) {
	w := &secretWrites{q: h.DB, release: func() {}}
	if h.Pool == nil {
		return w, nil
	}
	conn, rel, err := h.holdSecretWrites(ctx, sandboxID)
	if err != nil {
		return nil, err
	}
	var once sync.Once
	w.held, w.q, w.release = conn, db.New(conn), func() { once.Do(rel) }
	return w, nil
}

// inTx runs fn in one transaction on the held connection.
func (w *secretWrites) inTx(ctx context.Context, fn func(*db.Queries) error) error {
	if w.held == nil {
		return fn(w.q)
	}
	tx, err := w.held.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := fn(db.New(tx)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// undoAttach takes back a binding whose guest update failed, with the
// attach's hold still in place, so no capture has recorded it. boxd may
// have applied the env before the error, so the token is revoked and the
// key recorded as detached.
func undoAttach(ctx context.Context, q *db.Queries, sandboxID uuid.UUID, envKey, token string) error {
	if _, err := q.DeleteSandboxSecretBinding(ctx, db.DeleteSandboxSecretBindingParams{SandboxID: sandboxID, EnvKey: envKey}); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err := recordDetachedKey(ctx, q, sandboxID, envKey); err != nil {
		return err
	}
	return q.InsertRevokedProxyToken(ctx, db.InsertRevokedProxyTokenParams{
		SandboxID:  sandboxID,
		ProxyToken: token,
		ExpiresAt:  time.Now().Add(SecretsJWTLifetime),
	})
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

	// Check the cap and insert under the sandbox's secret-write lock so two
	// attaches to the same sandbox on different API instances can't both pass the
	// cap and exceed it — which would later wedge re-minting. The in-process lock
	// only covers one instance. Env-key collisions are caught by the PK. The lock
	// is held through the guest update below (see holdSecretWrites).
	// Everything under the hold runs on the held connection, and the hold ends
	// before anything else touches the database: a second pooled connection
	// taken while holding one could wait on a pool this request helps drain.
	// Resolved before the hold: resolving can itself need the database.
	vmd, vmdErr := h.vmdForHost(ctx, sandbox.HostID)
	w, err := h.beginSecretWrites(ctx, sandboxID)
	if err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("hold the secret-write lock for attach")
		respondError(c, ErrInternal)
		return
	}
	defer w.release()
	var liveSandbox db.Sandbox
	insertBinding := func(q *db.Queries) error {
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

	err = w.inTx(ctx, insertBinding)
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
		meta, _, lerr := loadSecretBindingState(ctx, w.q, sandboxID)
		if lerr == nil {
			lerr = vmdErr
		}
		if lerr == nil {
			lerr = h.applySecretBindingsVia(ctx, vmd, liveSandbox, meta)
		}
		if lerr != nil {
			log.Error().Err(lerr).Str("sandbox_id", sandboxID.String()).Msg("apply secret bindings on attach")
			// Detached context so a client disconnect can't fail both the apply and
			// its rollback, leaving the row behind after a 500.
			rbCtx, rbCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer rbCancel()
			if rerr := w.inTx(rbCtx, func(q *db.Queries) error { return undoAttach(rbCtx, q, sandboxID, req.EnvKey, token) }); rerr != nil {
				log.Error().Err(rerr).Str("sandbox_id", sandboxID.String()).Msg("undo a failed secret attach")
			}
			w.release()
			respondError(c, ErrInternal)
			return
		}
	}
	w.release()

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

	// Held through the guest update and the detached key's cleanup below, so
	// no other change to the sandbox's secrets lands between them.
	vmd, vmdErr := h.vmdForHost(ctx, sandbox.HostID)
	w, err := h.beginSecretWrites(ctx, sandboxID)
	if err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("hold the secret-write lock for detach")
		respondError(c, ErrInternal)
		return
	}
	defer w.release()

	deleteAndRevoke := func(q *db.Queries) error {
		// Re-read under the lock: a resume may have moved the sandbox on, and
		// whether the guest is updated below follows the status now.
		live, lerr := q.GetSandbox(mutCtx, db.GetSandboxParams{ID: sandboxID, TeamID: teamID})
		if lerr != nil {
			return lerr
		}
		switch live.Status {
		case db.SandboxStatusActive, db.SandboxStatusPaused:
		default:
			return errSandboxMidTransition
		}
		sandbox = live
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

	err = w.inTx(mutCtx, deleteAndRevoke)
	if err != nil {
		if errors.Is(err, errSnapshotInFlight) {
			respondSnapshotInFlight(c)
			return
		}
		if errors.Is(err, errSandboxMidTransition) {
			respondErrorMsg(c, "conflict", "sandbox is not in a state that accepts secret changes", http.StatusConflict)
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
		if meta, _, lerr := loadSecretBindingState(ctx, w.q, sandboxID); lerr != nil {
			log.Warn().Err(lerr).Str("sandbox_id", sandboxID.String()).Msg("load secret bindings after detach")
		} else if vmdErr != nil {
			log.Warn().Err(vmdErr).Str("sandbox_id", sandboxID.String()).Msg("resolve vmd to re-mint secret bindings after detach")
		} else if aerr := h.applySecretBindingsVia(ctx, vmd, sandbox, meta, envKey); aerr != nil {
			log.Warn().Err(aerr).Str("sandbox_id", sandboxID.String()).Msg("re-mint secret bindings after detach")
		} else if ferr := w.q.ForgetDetachedSecretKey(mutCtx, db.ForgetDetachedSecretKeyParams{SandboxID: sandboxID, EnvKey: envKey}); ferr != nil {
			log.Warn().Err(ferr).Str("sandbox_id", sandboxID.String()).Msg("forget a detached key the guest dropped")
		}
	}
	w.release()

	h.logSandboxActivity(ctx, sandboxID, teamID, actorIDFromContext(c), "secret", "detached", "success", &sandbox.Name, nil, nil)
	c.Status(http.StatusNoContent)
}
