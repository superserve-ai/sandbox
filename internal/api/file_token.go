package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/auth"
)

// fileTokenResponse is the payload returned to callers of the file-token
// mint endpoint.
//
//   - token:      the signed capability. Opaque; clients should not try
//     to parse or introspect it.
//   - url:        fully-formed https:// URL pointing at the edge proxy's
//     /files endpoint for this sandbox. Does NOT contain the token —
//     callers attach it themselves as either `Authorization: Bearer …`
//     or `?token=…`, and append `?path=…` for the target file path.
//   - expires_at: ISO-8601 expiry (default TTL 60s). Short by design so
//     a leaked token is nearly worthless even before single-use enforcement.
//
// We deliberately do not pre-compose the final upload or download URL
// here: callers need to append a path, and baking either the path or the
// token into the URL on the server side would either (a) require a
// round-trip per file, or (b) ship the token into request logs. Neither
// is acceptable. The client is responsible for the final URL assembly.
type fileTokenResponse struct {
	Token     string    `json:"token"`
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
}

// IssueFileToken mints a short-lived signed token that grants the caller
// HTTP upload (POST) and download (GET) access to a sandbox's /files
// endpoint on the edge proxy. The data plane never touches the control
// plane for file bytes; all the control plane does is mint this
// capability and hand it back.
//
// Flow:
//  1. Caller hits POST /sandboxes/:id/file-token with their API key.
//  2. We verify the sandbox belongs to the caller's team and is active.
//     Paused/idle sandboxes are refused with 409 — the data-plane
//     bridge has no auto-wake path, so minting a token against a
//     dormant VM would hand out a dud capability.
//  3. We mint a 60-second token bound to (sandbox_id, team_id, scope=files).
//  4. We return the token plus the edge proxy URL the caller should hit.
//
// Single-use is enforced at the verifier (edge proxy) via the shared
// nonce cache, so even if the token leaks inside its 60s TTL it cannot
// be replayed once the legitimate upload/download has consumed it. In
// practice a single token corresponds to a single file transfer — if
// the caller needs multiple transfers, mint multiple tokens. Minting is
// cheap (Ed25519 signature, no DB writes beyond the initial sandbox
// lookup) so this is not a performance concern.
func (h *Handlers) IssueFileToken(c *gin.Context) {
	sandbox, teamID, ok := h.loadActiveSandboxForMint(c)
	if !ok {
		return
	}

	now := time.Now()
	token, err := h.Signer.Mint(now, sandbox.ID.String(), teamID.String(), auth.ScopeFiles)
	if err != nil {
		log.Error().Err(err).Str("sandbox_id", sandbox.ID.String()).Msg("file token mint failed")
		respondError(c, ErrInternal)
		return
	}

	// The URL is the stable "base" for this sandbox's /files endpoint.
	// Callers append `?path=/abs/file.txt` to address a specific file
	// and attach the token as either an Authorization header or a
	// `&token=…` query parameter (the latter unlocks <a href> downloads
	// that can't set headers). The boxd port is the fixed constant
	// 49983 — hardcoding it here rather than plumbing it through config
	// keeps the mint endpoint contract stable for SDK authors.
	url := fmt.Sprintf("https://49983-%s.%s/files",
		sandbox.ID.String(), h.Config.EdgeProxyDomain)

	c.JSON(http.StatusOK, fileTokenResponse{
		Token:     token,
		URL:       url,
		ExpiresAt: now.Add(auth.DefaultTTL),
	})
}
