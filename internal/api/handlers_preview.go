package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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

// Preview token endpoints.
//
// The token is deliberately NOT part of any sandbox GET response: handing a
// data-plane credential out on a read is how restricted/read-only modes
// spring leaks. Callers mint explicitly, and the response carries the
// carrier names so clients never hardcode them.

const (
	// maxPreviewTokenExpirySeconds caps signed-link lifetimes at 7 days.
	// Tokens minted without an expiry live until the version rotates.
	maxPreviewTokenExpirySeconds = 7 * 24 * 60 * 60

	// minPreviewTokenPort mirrors the edge proxy's privileged-port floor —
	// minting a token for a port the proxy refuses to route is a caller bug
	// worth a 400, not a token that can never work.
	minPreviewTokenPort = 1024
	maxPreviewTokenPort = 65535
)

type mintPreviewTokenRequest struct {
	// Port scopes the token to one preview port; omitted/0 means any port.
	Port int `json:"port,omitempty"`
	// ExpiresInSeconds bounds the token lifetime (1..604800). Omitted/0
	// mints a standard token that lives until rotation.
	ExpiresInSeconds int64 `json:"expires_in_seconds,omitempty"`
}

type previewTokenResponse struct {
	Token string `json:"token"`
	// Header is the request header machine clients present the token in.
	Header string `json:"header"`
	// QueryParam is the URL parameter for browser bootstrap links; the edge
	// proxy exchanges it for a host-scoped cookie and strips it from the URL.
	QueryParam string `json:"query_param"`
	// ExpiresAt is present only for expiring tokens.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// PreviewAccess is the sandbox's current policy, so callers can tell
	// when a token isn't actually required yet ("public").
	PreviewAccess string `json:"preview_access"`
	// PreviewTokenVersion is the generation this token was minted against.
	PreviewTokenVersion int32 `json:"preview_token_version"`
}

// MintSandboxPreviewToken handles POST /sandboxes/:sandbox_id/preview-token.
// The body is optional; an empty body mints a sandbox-wide, non-expiring
// token (revocable via the rotate endpoint).
func (h *Handlers) MintSandboxPreviewToken(c *gin.Context) {
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

	var req mintPreviewTokenRequest
	if c.Request.ContentLength != 0 {
		if err := bindJSONStrict(c, &req); err != nil {
			respondErrorMsg(c, "bad_request", "Invalid request body: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	if req.Port != 0 && (req.Port < minPreviewTokenPort || req.Port > maxPreviewTokenPort) {
		respondErrorMsg(c, "bad_request",
			fmt.Sprintf("port must be omitted or in [%d, %d]", minPreviewTokenPort, maxPreviewTokenPort),
			http.StatusBadRequest)
		return
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

	resp, appErr := h.buildPreviewTokenResponse(sandbox, req.Port, req.ExpiresInSeconds)
	if appErr != nil {
		respondError(c, appErr)
		return
	}
	c.JSON(http.StatusOK, resp)
}

// RotateSandboxPreviewToken handles
// POST /sandboxes/:sandbox_id/preview-token/rotate. It advances the token
// generation — revoking every outstanding preview token — pushes the new
// version to the host record, and returns a fresh sandbox-wide token.
//
// Order: DB first (the bump is atomic and is what future mints and restores
// read), host record second. If the host push fails the handler returns 500
// — the rotation is not complete, previously issued tokens may still be
// accepted until a retry succeeds — rather than pretending the old tokens
// are dead.
func (h *Handlers) RotateSandboxPreviewToken(c *gin.Context) {
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

	sandbox, ok := h.getTeamSandbox(c, sandboxID, teamID)
	if !ok {
		return
	}

	newVersion, err := h.DB.BumpSandboxPreviewTokenVersion(c.Request.Context(), db.BumpSandboxPreviewTokenVersionParams{
		ID:     sandboxID,
		TeamID: teamID,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			respondError(c, ErrSandboxNotFound)
			return
		}
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB BumpSandboxPreviewTokenVersion failed")
		respondError(c, ErrInternal)
		return
	}

	// Push the new generation to the host record so the edge proxy stops
	// accepting old tokens now, not at the next restore. NotFound = no
	// record on the host; the next restore carries the bumped version.
	vmd, vmdErr := h.vmdForHost(c.Request.Context(), sandbox.HostID)
	if vmdErr != nil {
		log.Error().Err(vmdErr).Str("sandbox_id", sandboxID.String()).Msg("resolve VMD for preview-token rotate failed")
		respondError(c, ErrInternal)
		return
	}
	vmdCtx, vmdCancel := context.WithTimeout(c.Request.Context(), vmdTimeout)
	defer vmdCancel()
	if err := vmd.UpdateSandboxPreviewPolicy(vmdCtx, sandboxID.String(), sandbox.PreviewAccess, int64(newVersion)); err != nil && status.Code(err) != codes.NotFound {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("VMD UpdateSandboxPreviewPolicy failed after version bump — outstanding tokens remain valid until a retry succeeds")
		respondError(c, ErrInternal)
		return
	}

	sandbox.PreviewTokenVersion = newVersion
	resp, appErr := h.buildPreviewTokenResponse(sandbox, 0, 0)
	if appErr != nil {
		respondError(c, appErr)
		return
	}

	detail, _ := json.Marshal(map[string]any{"preview_token_version": newVersion})
	h.logSandboxActivity(c.Request.Context(), sandbox.ID, teamID, actorIDFromContext(c), "sandbox", "preview_token_rotated", "success", &sandbox.Name, nil, detail)
	h.capture(c, "sandbox_preview_token_rotated", map[string]any{"sandbox_id": sandboxID.String()})

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

// buildPreviewTokenResponse mints a token against the row's current version.
// Tokens are keyed on the bare UUID — the same identity the proxy derives
// from the request host after stripping any region prefix.
func (h *Handlers) buildPreviewTokenResponse(sandbox db.Sandbox, port int, expiresInSeconds int64) (previewTokenResponse, *AppError) {
	if h.Config == nil || h.Config.SandboxAccessTokenSeed == nil {
		log.Error().Msg("preview token requested but SANDBOX_ACCESS_TOKEN_SEED is not configured")
		return previewTokenResponse{}, ErrInternal
	}

	claims := auth.PreviewClaims{
		SandboxID: sandbox.ID.String(),
		Version:   int64(sandbox.PreviewTokenVersion),
		Port:      port,
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
		Token:               token,
		Header:              auth.PreviewTokenHeader,
		QueryParam:          auth.PreviewTokenQueryParam,
		ExpiresAt:           expiresAt,
		PreviewAccess:       sandbox.PreviewAccess,
		PreviewTokenVersion: sandbox.PreviewTokenVersion,
	}, nil
}
