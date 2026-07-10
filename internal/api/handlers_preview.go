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

// loadPreviewPorts returns a sandbox's published ports as port → token
// version, the shape carried to vmd and enforced at the proxy. Nil when
// nothing is published.
func (h *Handlers) loadPreviewPorts(ctx context.Context, sandboxID uuid.UUID) (map[int32]int64, error) {
	rows, err := h.DB.ListPublishedPorts(ctx, sandboxID)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	out := make(map[int32]int64, len(rows))
	for _, r := range rows {
		out[r.Port] = int64(r.TokenVersion)
	}
	return out, nil
}

// pushPreviewPolicy sends the sandbox's current preview_access + full
// published-port set to its host's vmd, so the edge proxy enforces the change
// now rather than at the next restore. gRPC NotFound (no record on the host —
// e.g. a paused sandbox) is not an error: the next restore seeds the policy
// from the DB. Any other failure is returned so the caller can 500 rather than
// report a security change that was not applied.
func (h *Handlers) pushPreviewPolicy(ctx context.Context, sandbox db.Sandbox, ports map[int32]int64) error {
	vmd, err := h.vmdForHost(ctx, sandbox.HostID)
	if err != nil {
		return fmt.Errorf("resolve vmd: %w", err)
	}
	vmdCtx, cancel := context.WithTimeout(ctx, vmdTimeout)
	defer cancel()
	if err := vmd.UpdateSandboxPreviewPolicy(vmdCtx, sandbox.ID.String(), sandbox.PreviewAccess, ports); err != nil && status.Code(err) != codes.NotFound {
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
	Port         int32 `json:"port"`
	TokenVersion int32 `json:"token_version"`
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
		ports = append(ports, publishedPortResponse{Port: r.Port, TokenVersion: r.TokenVersion})
	}
	c.JSON(http.StatusOK, listPreviewPortsResponse{PreviewAccess: sandbox.PreviewAccess, Ports: ports})
}

type publishPortRequest struct {
	Port int32 `json:"port"`
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

	sandbox, ok := h.getTeamSandbox(c, sandboxID, teamID)
	if !ok {
		return
	}

	row, err := h.DB.PublishPort(c.Request.Context(), db.PublishPortParams{SandboxID: sandboxID, Port: body.Port})
	if err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Int32("port", body.Port).Msg("DB PublishPort failed")
		respondError(c, ErrInternal)
		return
	}

	if !h.syncPreviewPortsToHost(c, sandbox) {
		return
	}

	detail, _ := json.Marshal(map[string]any{"port": body.Port})
	h.logSandboxActivity(c.Request.Context(), sandbox.ID, teamID, actorIDFromContext(c), "sandbox", "preview_port_published", "success", &sandbox.Name, nil, detail)
	h.capture(c, "sandbox_preview_port_published", map[string]any{"sandbox_id": sandboxID.String(), "port": body.Port})

	c.JSON(http.StatusOK, publishedPortResponse{Port: row.Port, TokenVersion: row.TokenVersion})
}

// UnpublishSandboxPreviewPort handles
// DELETE /sandboxes/:sandbox_id/preview-ports/:port. After this the port is no
// longer routable (deny-by-default) and its outstanding tokens are useless.
//
// Unpublish is a revocation, so it must be retry-safe: the host's enforcement
// copy is updated BEFORE the DB row is removed, and the operation is
// idempotent. Ordering rationale:
//   - Host push fails → 500 with nothing changed (DB still says published,
//     host still routes it — consistent; retry redoes both).
//   - Push succeeds, DB delete fails → the host is stricter than the DB
//     (port 404s even though the row exists) — fail closed; retry repairs.
//   - Row already absent (a retry, or a never-published port) → the intended
//     allowlist is pushed anyway, repairing any stale host state, and the
//     response is 204. A repeat DELETE can never strand a routable port the
//     DB no longer knows about.
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

	// Compute the intended post-unpublish allowlist from the DB's current set.
	current, err := h.loadPreviewPorts(c.Request.Context(), sandboxID)
	if err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("load published ports for unpublish failed")
		respondError(c, ErrInternal)
		return
	}
	_, wasPublished := current[port]
	intended := make(map[int32]int64, len(current))
	for p, v := range current {
		if p != port {
			intended[p] = v
		}
	}

	// Enforcement first: the port must stop routing before the DB forgets it
	// was ever published.
	if err := h.pushPreviewPolicy(c.Request.Context(), sandbox, intended); err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Int32("port", port).Msg("push preview policy for unpublish failed — nothing changed; retry")
		respondError(c, ErrInternal)
		return
	}

	// Then intent: remove the row. Zero rows is fine — that's the idempotent
	// retry/repair path, and the push above already corrected the host.
	if _, err := h.DB.UnpublishPort(c.Request.Context(), db.UnpublishPortParams{SandboxID: sandboxID, Port: port}); err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Int32("port", port).Msg("DB UnpublishPort failed (host already stopped routing the port — retry to finish)")
		respondError(c, ErrInternal)
		return
	}

	if wasPublished {
		detail, _ := json.Marshal(map[string]any{"port": port})
		h.logSandboxActivity(c.Request.Context(), sandbox.ID, teamID, actorIDFromContext(c), "sandbox", "preview_port_unpublished", "success", &sandbox.Name, nil, detail)
		h.capture(c, "sandbox_preview_port_unpublished", map[string]any{"sandbox_id": sandboxID.String(), "port": port})
	}

	c.Status(http.StatusNoContent)
}

type previewTokenResponse struct {
	Token        string `json:"token"`
	Port         int32  `json:"port"`
	Header       string `json:"header"`
	QueryParam   string `json:"query_param"`
	TokenVersion int32  `json:"token_version"`
	// ExpiresAt is present only for expiring tokens.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// PreviewAccess lets callers tell when a token isn't required yet ("public").
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

	resp, appErr := h.buildPreviewTokenResponse(sandbox, pub.Port, pub.TokenVersion, req.ExpiresInSeconds)
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

	bumped, err := h.DB.BumpPublishedPortVersion(c.Request.Context(), db.BumpPublishedPortVersionParams{SandboxID: sandboxID, Port: port})
	if err != nil {
		if err == pgx.ErrNoRows {
			respondErrorMsg(c, "not_found", "Preview port not published", http.StatusNotFound)
			return
		}
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Int32("port", port).Msg("DB BumpPublishedPortVersion failed")
		respondError(c, ErrInternal)
		return
	}

	// Push the new generation so the proxy stops accepting old tokens now, not
	// at the next restore. A hard failure is a 500: the rotation is not
	// complete until the host has the new version.
	if !h.syncPreviewPortsToHost(c, sandbox) {
		return
	}

	resp, appErr := h.buildPreviewTokenResponse(sandbox, bumped.Port, bumped.TokenVersion, 0)
	if appErr != nil {
		respondError(c, appErr)
		return
	}

	detail, _ := json.Marshal(map[string]any{"port": port, "token_version": bumped.TokenVersion})
	h.logSandboxActivity(c.Request.Context(), sandbox.ID, teamID, actorIDFromContext(c), "sandbox", "preview_token_rotated", "success", &sandbox.Name, nil, detail)
	h.capture(c, "sandbox_preview_token_rotated", map[string]any{"sandbox_id": sandboxID.String(), "port": port})

	c.JSON(http.StatusOK, resp)
}

// syncPreviewPortsToHost loads the sandbox's current published set and pushes
// it (with the sandbox's policy) to the host's vmd, writing the 500 response
// itself on failure. Returns false when it has already responded.
func (h *Handlers) syncPreviewPortsToHost(c *gin.Context, sandbox db.Sandbox) bool {
	ports, err := h.loadPreviewPorts(c.Request.Context(), sandbox.ID)
	if err != nil {
		log.Error().Err(err).Str("sandbox_id", sandbox.ID.String()).Msg("load published ports for host sync failed")
		respondError(c, ErrInternal)
		return false
	}
	if err := h.pushPreviewPolicy(c.Request.Context(), sandbox, ports); err != nil {
		log.Error().Err(err).Str("sandbox_id", sandbox.ID.String()).Msg("push preview policy to host failed")
		respondError(c, ErrInternal)
		return false
	}
	return true
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
func (h *Handlers) buildPreviewTokenResponse(sandbox db.Sandbox, port, tokenVersion int32, expiresInSeconds int64) (previewTokenResponse, *AppError) {
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
		PreviewAccess: sandbox.PreviewAccess,
	}, nil
}
