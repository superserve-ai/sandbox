package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/auth"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

// Preview URL access is deny-by-default on a private sandbox: a port is
// reachable only after it is explicitly published, and every preview token is
// scoped to one published port with its own rotation lifecycle. This file owns
// that publication surface — publish/unpublish/list, plus per-port mint and
// rotate.
//
// Two boundaries the security model rests on:
//   - Minting a token requires sandbox WRITE, not read. A token is a live
//     data-plane credential (it reaches the app inside the sandbox), so
//     read-only access must never be able to create one.
//   - A token can only be minted for an already-published port. There are no
//     sandbox-wide tokens.

const (
	// maxPreviewTokenExpirySeconds caps signed-link lifetimes at 7 days.
	maxPreviewTokenExpirySeconds = 7 * 24 * 60 * 60

	// Preview ports mirror the edge proxy's routable range (privileged ports
	// are refused there).
	minPreviewPort = 1024
	maxPreviewPort = 65535
)

// loadPreviewPorts returns a sandbox's published ports as port → per-port
// policy (token version + access mode), the shape carried to vmd and enforced
// at the proxy. Nil when nothing is published. Used by the read path (list)
// and by the resume path that seeds a restored record.
func (h *Handlers) loadPreviewPorts(ctx context.Context, sandboxID uuid.UUID) (map[int32]vmdclient.PortPolicy, error) {
	rows, err := h.DB.ListPublishedPorts(ctx, sandboxID)
	if err != nil {
		return nil, err
	}
	return portsFromRows(rows), nil
}

func portsFromRows(rows []db.ListPublishedPortsRow) map[int32]vmdclient.PortPolicy {
	if len(rows) == 0 {
		return nil
	}
	out := make(map[int32]vmdclient.PortPolicy, len(rows))
	for _, r := range rows {
		out[r.Port] = vmdclient.PortPolicy{Version: int64(r.TokenVersion), Access: r.Access}
	}
	return out
}

// applyPreviewMutation runs a preview-policy change atomically. In a single
// transaction it bumps the sandbox's policy revision — a row-level write lock
// that serializes concurrent preview mutations on the same sandbox — then runs
// the caller's mutation and reads back the resulting published-port set. The
// returned (revision, ports) pair is therefore a consistent snapshot, and the
// monotonically increasing revision lets vmd reject any push that arrives out
// of order. Returns ErrSandboxNotFound when the sandbox row is gone; a mutation
// that itself returns pgx.ErrNoRows (e.g. rotating an unpublished port) rolls
// the whole transaction back, so the revision bump has no effect.
func (h *Handlers) applyPreviewMutation(ctx context.Context, sandboxID, teamID uuid.UUID, mutate func(q *db.Queries) error) (int64, map[int32]vmdclient.PortPolicy, error) {
	run := func(q *db.Queries) (int64, map[int32]vmdclient.PortPolicy, error) {
		rev, err := q.BumpPreviewPolicyRevision(ctx, db.BumpPreviewPolicyRevisionParams{ID: sandboxID, TeamID: teamID})
		if err != nil {
			if err == pgx.ErrNoRows {
				return 0, nil, ErrSandboxNotFound
			}
			return 0, nil, err
		}
		if err := mutate(q); err != nil {
			return 0, nil, err
		}
		rows, err := q.ListPublishedPorts(ctx, sandboxID)
		if err != nil {
			return 0, nil, err
		}
		return rev, portsFromRows(rows), nil
	}

	// No pool (DBTX-mocked unit tests): run directly. Real serialization comes
	// from the transaction + row lock, which the mock doesn't model, but unit
	// tests exercise one request at a time.
	if h.Pool == nil {
		return run(h.DB)
	}
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return 0, nil, err
	}
	defer tx.Rollback(ctx)
	rev, ports, err := run(h.DB.WithTx(tx))
	if err != nil {
		return 0, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, nil, err
	}
	return rev, ports, nil
}

// pushPreviewPolicy sends the sandbox's preview_access + full published-port
// set, tagged with the policy revision, to its host's vmd so the edge proxy
// enforces the change now rather than at the next restore. vmd ignores a
// revision <= the one it already holds, making the push order-independent.
// gRPC NotFound (no record on the host — e.g. a paused sandbox) is not an
// error: the next restore seeds the policy from the DB. Any other failure is
// returned so the caller can 500 rather than report a change that was not
// applied.
func (h *Handlers) pushPreviewPolicy(ctx context.Context, sandbox db.Sandbox, ports map[int32]vmdclient.PortPolicy, revision int64) error {
	vmd, err := h.vmdForHost(ctx, sandbox.HostID)
	if err != nil {
		return fmt.Errorf("resolve vmd: %w", err)
	}
	vmdCtx, cancel := context.WithTimeout(ctx, vmdTimeout)
	defer cancel()
	if err := vmd.UpdateSandboxPreviewPolicy(vmdCtx, sandbox.ID.String(), sandbox.PreviewAccess, ports, revision); err != nil && status.Code(err) != codes.NotFound {
		return err
	}
	return nil
}

// parsePreviewPort reads and validates the :port path parameter.
func parsePreviewPort(c *gin.Context) (int32, bool) {
	raw := c.Param("port")
	n, err := strconv.Atoi(raw)
	if err != nil || n < minPreviewPort || n > maxPreviewPort {
		respondErrorMsg(c, "bad_request",
			fmt.Sprintf("port must be an integer in [%d, %d]", minPreviewPort, maxPreviewPort),
			http.StatusBadRequest)
		return 0, false
	}
	return int32(n), true
}

type publishedPortResponse struct {
	Port         int32  `json:"port"`
	TokenVersion int32  `json:"token_version"`
	Access       string `json:"access"`
}

type listPreviewPortsResponse struct {
	PreviewAccess string                  `json:"preview_access"`
	Ports         []publishedPortResponse `json:"ports"`
}

// ListSandboxPreviewPorts handles GET /sandboxes/:sandbox_id/preview-ports.
// Read-only: returns the published set and the sandbox's policy, never tokens.
func (h *Handlers) ListSandboxPreviewPorts(c *gin.Context) {
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
	sandbox, ok := h.getTeamSandbox(c, sandboxID, teamID)
	if !ok {
		return
	}
	rows, err := h.DB.ListPublishedPorts(c.Request.Context(), sandboxID)
	if err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB ListPublishedPorts failed")
		respondError(c, ErrInternal)
		return
	}
	ports := make([]publishedPortResponse, 0, len(rows))
	for _, r := range rows {
		ports = append(ports, publishedPortResponse{Port: r.Port, TokenVersion: r.TokenVersion, Access: r.Access})
	}
	c.JSON(http.StatusOK, listPreviewPortsResponse{PreviewAccess: sandbox.PreviewAccess, Ports: ports})
}

type publishPortRequest struct {
	Port int32 `json:"port"`
	// Access is the per-port mode. Omitted → the sandbox-level policy for a
	// public sandbox, private otherwise.
	Access *string `json:"access,omitempty"`
}

// PublishSandboxPreviewPort handles POST /sandboxes/:sandbox_id/preview-ports.
// Idempotent publish (re-publishing keeps the existing token version so live
// tokens survive). Requires write; pushes the new set to the host.
func (h *Handlers) PublishSandboxPreviewPort(c *gin.Context) {
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
	var body publishPortRequest
	if err := bindJSONStrict(c, &body); err != nil {
		respondErrorMsg(c, "bad_request", "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if body.Port < minPreviewPort || body.Port > maxPreviewPort {
		respondErrorMsg(c, "bad_request",
			fmt.Sprintf("port must be an integer in [%d, %d]", minPreviewPort, maxPreviewPort),
			http.StatusBadRequest)
		return
	}
	if err := validatePortAccess(body.Access); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}

	sandbox, ok := h.getTeamSandbox(c, sandboxID, teamID)
	if !ok {
		return
	}

	access := defaultPortAccess(sandbox.PreviewAccess)
	if body.Access != nil {
		access = *body.Access
	}

	// Publishing (or re-publishing with a different mode) expands or changes
	// the reachable surface — an enablement operation, so both rollout gates
	// apply: the team's flags and the host's advertised enforcement. Neither
	// is consulted again for revocation (unpublish/rotate).
	flags := []string{flagPreviewPortPublication}
	if access == auth.PreviewAccessPrivate {
		flags = append(flags, flagPreviewPortPrivateAccess)
	}
	if !h.requirePreviewFlags(c, teamID, flags...) {
		return
	}
	if !h.requireHostPreviewCapabilities(c, sandbox.HostID, access == auth.PreviewAccessPrivate) {
		return
	}

	var row db.PublishPortRow
	rev, ports, err := h.applyPreviewMutation(c.Request.Context(), sandboxID, teamID, func(q *db.Queries) error {
		var e error
		row, e = q.PublishPort(c.Request.Context(), db.PublishPortParams{SandboxID: sandboxID, Port: body.Port, Access: access})
		return e
	})
	if !h.handlePreviewMutationResult(c, sandboxID, "PublishPort", err) {
		return
	}
	if !h.pushAfterMutation(c, sandbox, ports, rev) {
		return
	}

	detail, _ := json.Marshal(map[string]any{"port": body.Port})
	h.logSandboxActivity(c.Request.Context(), sandbox.ID, teamID, actorIDFromContext(c), "sandbox", "preview_port_published", "success", &sandbox.Name, nil, detail)
	h.capture(c, "sandbox_preview_port_published", map[string]any{"sandbox_id": sandboxID.String(), "port": body.Port})

	c.JSON(http.StatusOK, publishedPortResponse{Port: row.Port, TokenVersion: row.TokenVersion, Access: row.Access})
}

// UnpublishSandboxPreviewPort handles
// DELETE /sandboxes/:sandbox_id/preview-ports/:port. After this the port is no
// longer routable (deny-by-default) and its outstanding tokens are useless.
//
// Unpublish is a revocation, so it is idempotent and retry-safe. The DB
// deletion and the policy-revision bump are one transaction; the resulting
// allowlist is then pushed to the host tagged with the new revision:
//   - Host push fails → 500. The DB is ahead of the host, but a retry
//     re-bumps the revision and re-pushes, and vmd applies it because the
//     revision is higher. Enforcement converges.
//   - A repeat DELETE (row already gone, or never published) still bumps and
//     re-pushes the current allowlist, so a stale host copy is always
//     repaired and the response is 204 — never 404 without re-syncing.
//   - Concurrency can't reopen the port: a stale lower-revision push from a
//     racing publish/rotate is ignored by vmd.
func (h *Handlers) UnpublishSandboxPreviewPort(c *gin.Context) {
	sandboxID, err := parseSandboxID(c)
	if err != nil {
		return
	}
	port, ok := parsePreviewPort(c)
	if !ok {
		return
	}
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}
	if !h.requireTeamSandboxWrite(c, teamID) {
		return
	}
	sandbox, ok := h.getTeamSandbox(c, sandboxID, teamID)
	if !ok {
		return
	}

	var deleted int64
	rev, ports, err := h.applyPreviewMutation(c.Request.Context(), sandboxID, teamID, func(q *db.Queries) error {
		var e error
		deleted, e = q.UnpublishPort(c.Request.Context(), db.UnpublishPortParams{SandboxID: sandboxID, Port: port})
		return e
	})
	if !h.handlePreviewMutationResult(c, sandboxID, "UnpublishPort", err) {
		return
	}
	if !h.pushAfterMutation(c, sandbox, ports, rev) {
		return
	}

	if deleted > 0 {
		detail, _ := json.Marshal(map[string]any{"port": port})
		h.logSandboxActivity(c.Request.Context(), sandbox.ID, teamID, actorIDFromContext(c), "sandbox", "preview_port_unpublished", "success", &sandbox.Name, nil, detail)
		h.capture(c, "sandbox_preview_port_unpublished", map[string]any{"sandbox_id": sandboxID.String(), "port": port})
	}

	c.Status(http.StatusNoContent)
}

// handlePreviewMutationResult maps applyPreviewMutation's error to a response.
// Returns true when the caller may proceed (no error).
func (h *Handlers) handlePreviewMutationResult(c *gin.Context, sandboxID uuid.UUID, op string, err error) bool {
	if err == nil {
		return true
	}
	if err == ErrSandboxNotFound {
		respondError(c, ErrSandboxNotFound)
		return false
	}
	log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Str("op", op).Msg("preview mutation failed")
	respondError(c, ErrInternal)
	return false
}

// pushAfterMutation pushes the post-mutation allowlist to the host, writing the
// 500 itself on failure. Returns false when it has already responded.
func (h *Handlers) pushAfterMutation(c *gin.Context, sandbox db.Sandbox, ports map[int32]vmdclient.PortPolicy, revision int64) bool {
	if err := h.pushPreviewPolicy(c.Request.Context(), sandbox, ports, revision); err != nil {
		log.Error().Err(err).Str("sandbox_id", sandbox.ID.String()).Msg("push preview policy to host failed — retry to converge enforcement")
		respondError(c, ErrInternal)
		return false
	}
	return true
}

type previewTokenResponse struct {
	Token        string `json:"token"`
	Port         int32  `json:"port"`
	Header       string `json:"header"`
	QueryParam   string `json:"query_param"`
	TokenVersion int32  `json:"token_version"`
	// ExpiresAt is present only for expiring tokens.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// Access is THIS port's mode — the one that decides whether the token is
	// required ("private") or informational ("public").
	Access string `json:"access"`
	// PreviewAccess is the sandbox-level default for newly published ports,
	// kept for callers that predate per-port modes.
	PreviewAccess string `json:"preview_access"`
}

type mintPreviewTokenRequest struct {
	// ExpiresInSeconds bounds the token lifetime (1..604800). Omitted/0 mints
	// a token that lives until the port's version is rotated.
	ExpiresInSeconds int64 `json:"expires_in_seconds,omitempty"`
}

// MintSandboxPreviewToken handles
// POST /sandboxes/:sandbox_id/preview-ports/:port/token. Requires WRITE — a
// token is a live data-plane credential. The port must already be published.
func (h *Handlers) MintSandboxPreviewToken(c *gin.Context) {
	sandboxID, err := parseSandboxID(c)
	if err != nil {
		return
	}
	port, ok := parsePreviewPort(c)
	if !ok {
		return
	}
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}
	if !h.requireTeamSandboxWrite(c, teamID) {
		return
	}
	var req mintPreviewTokenRequest
	if c.Request.ContentLength != 0 {
		if err := bindJSONStrict(c, &req); err != nil {
			respondErrorMsg(c, "bad_request", "Invalid request body: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	if req.ExpiresInSeconds < 0 || req.ExpiresInSeconds > maxPreviewTokenExpirySeconds {
		respondErrorMsg(c, "bad_request",
			fmt.Sprintf("expires_in_seconds must be omitted or in [1, %d]", maxPreviewTokenExpirySeconds),
			http.StatusBadRequest)
		return
	}

	sandbox, ok := h.getTeamSandbox(c, sandboxID, teamID)
	if !ok {
		return
	}

	pub, err := h.DB.GetPublishedPort(c.Request.Context(), db.GetPublishedPortParams{SandboxID: sandboxID, Port: port})
	if err != nil {
		if err == pgx.ErrNoRows {
			respondErrorMsg(c, "not_found", "Preview port not published; publish it before minting a token", http.StatusNotFound)
			return
		}
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Int32("port", port).Msg("DB GetPublishedPort failed")
		respondError(c, ErrInternal)
		return
	}

	resp, appErr := h.buildPreviewTokenResponse(sandbox, pub.Port, pub.TokenVersion, pub.Access, req.ExpiresInSeconds)
	if appErr != nil {
		respondError(c, appErr)
		return
	}

	detail, _ := json.Marshal(map[string]any{"port": port, "expires_in_seconds": req.ExpiresInSeconds})
	h.logSandboxActivity(c.Request.Context(), sandbox.ID, teamID, actorIDFromContext(c), "sandbox", "preview_token_minted", "success", &sandbox.Name, nil, detail)
	h.capture(c, "sandbox_preview_token_minted", map[string]any{"sandbox_id": sandboxID.String(), "port": port})

	c.JSON(http.StatusOK, resp)
}

// RotateSandboxPreviewToken handles
// POST /sandboxes/:sandbox_id/preview-ports/:port/token/rotate. Advances only
// this port's generation — every other published port's tokens stay valid —
// pushes the new version to the host, and returns a fresh token for the port.
func (h *Handlers) RotateSandboxPreviewToken(c *gin.Context) {
	sandboxID, err := parseSandboxID(c)
	if err != nil {
		return
	}
	port, ok := parsePreviewPort(c)
	if !ok {
		return
	}
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}
	if !h.requireTeamSandboxWrite(c, teamID) {
		return
	}
	sandbox, ok := h.getTeamSandbox(c, sandboxID, teamID)
	if !ok {
		return
	}

	// The version bump and the revision bump are one transaction; rotating an
	// unpublished port returns pgx.ErrNoRows, which rolls the whole thing back
	// (no revision side effect) and maps to 404.
	var bumped db.BumpPublishedPortVersionRow
	rev, ports, err := h.applyPreviewMutation(c.Request.Context(), sandboxID, teamID, func(q *db.Queries) error {
		var e error
		bumped, e = q.BumpPublishedPortVersion(c.Request.Context(), db.BumpPublishedPortVersionParams{SandboxID: sandboxID, Port: port})
		return e
	})
	if err == pgx.ErrNoRows {
		respondErrorMsg(c, "not_found", "Preview port not published", http.StatusNotFound)
		return
	}
	if !h.handlePreviewMutationResult(c, sandboxID, "BumpPublishedPortVersion", err) {
		return
	}

	// Push the new generation so the proxy stops accepting old tokens now, not
	// at the next restore. A hard failure is a 500: the rotation is not
	// complete until the host has the new version (retry converges).
	if !h.pushAfterMutation(c, sandbox, ports, rev) {
		return
	}

	resp, appErr := h.buildPreviewTokenResponse(sandbox, bumped.Port, bumped.TokenVersion, bumped.Access, 0)
	if appErr != nil {
		respondError(c, appErr)
		return
	}

	detail, _ := json.Marshal(map[string]any{"port": port, "token_version": bumped.TokenVersion})
	h.logSandboxActivity(c.Request.Context(), sandbox.ID, teamID, actorIDFromContext(c), "sandbox", "preview_token_rotated", "success", &sandbox.Name, nil, detail)
	h.capture(c, "sandbox_preview_token_rotated", map[string]any{"sandbox_id": sandboxID.String(), "port": port})

	c.JSON(http.StatusOK, resp)
}

// getTeamSandbox loads a team-scoped sandbox row, writing the 404/500
// response itself when the lookup fails.
func (h *Handlers) getTeamSandbox(c *gin.Context, sandboxID, teamID uuid.UUID) (db.Sandbox, bool) {
	sandbox, err := h.DB.GetSandbox(c.Request.Context(), db.GetSandboxParams{
		ID:     sandboxID,
		TeamID: teamID,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			respondError(c, ErrSandboxNotFound)
			return db.Sandbox{}, false
		}
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB GetSandbox failed")
		respondError(c, ErrInternal)
		return db.Sandbox{}, false
	}
	return sandbox, true
}

// buildPreviewTokenResponse mints a token for one published port against its
// current version. Tokens are keyed on the bare UUID — the identity the proxy
// derives from the request host after stripping any region prefix.
func (h *Handlers) buildPreviewTokenResponse(sandbox db.Sandbox, port, tokenVersion int32, portAccess string, expiresInSeconds int64) (previewTokenResponse, *AppError) {
	if h.Config == nil || h.Config.SandboxAccessTokenSeed == nil {
		log.Error().Msg("preview token requested but SANDBOX_ACCESS_TOKEN_SEED is not configured")
		return previewTokenResponse{}, ErrInternal
	}

	claims := auth.PreviewClaims{
		SandboxID: sandbox.ID.String(),
		Port:      int(port),
		Version:   int64(tokenVersion),
	}
	var expiresAt *time.Time
	if expiresInSeconds > 0 {
		t := time.Now().Add(time.Duration(expiresInSeconds) * time.Second).UTC()
		claims.ExpiresAt = t.Unix()
		expiresAt = &t
	}
	token, err := auth.ComputePreviewToken(h.Config.SandboxAccessTokenSeed, claims)
	if err != nil {
		log.Error().Err(err).Str("sandbox_id", sandbox.ID.String()).Msg("mint preview token failed")
		return previewTokenResponse{}, ErrInternal
	}

	return previewTokenResponse{
		Token:         token,
		Port:          port,
		Header:        auth.PreviewTokenHeader,
		QueryParam:    auth.PreviewTokenQueryParam,
		TokenVersion:  tokenVersion,
		ExpiresAt:     expiresAt,
		Access:        portAccess,
		PreviewAccess: sandbox.PreviewAccess,
	}, nil
}
