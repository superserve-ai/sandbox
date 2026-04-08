package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/auth"
	"github.com/superserve-ai/sandbox/internal/db"
)

// terminalTokenResponse is what the browser receives.
//
//   - token:      the signed capability. Opaque to the client.
//   - url:        fully-formed wss:// URL the browser opens. Does NOT
//     contain the token — see the note in IssueTerminalToken for why.
//   - subprotocol: the main WebSocket subprotocol the server expects and
//     will echo back. The client should pass
//     [subprotocol, "token." + token] as the protocols arg to
//     `new WebSocket(url, protocols)`. The server parses the token from
//     the `token.` entry and acknowledges only the subprotocol entry.
//   - expires_at: ISO-8601 expiry (default TTL 60s). Defensive — the WS
//     upgrade should happen immediately so the TTL never matters in
//     practice.
type terminalTokenResponse struct {
	Token       string    `json:"token"`
	URL         string    `json:"url"`
	Subprotocol string    `json:"subprotocol"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// TerminalSubprotocol is the fixed subprotocol identifier browsers must
// offer as their first WebSocket subprotocol when connecting to
// /terminal. Kept in sync with internal/proxy.terminalProtocol. Exported
// as a constant so the OpenAPI response example stays correct and tests
// can assert on it.
const TerminalSubprotocol = "superserve.terminal.v1"

// IssueTerminalToken mints a short-lived signed token that grants the caller
// a WebSocket-upgraded PTY session to the named sandbox via the edge proxy.
//
// Why this lives on the control plane (not the edge proxy):
//
// The control plane is the only service that knows whether a caller may
// access a given sandbox (API key → team → sandbox membership). Putting
// minting here keeps that auth knowledge in one place and lets the edge
// proxy stay stateless and DB-free on the data path. The edge proxy will
// verify the token signature locally and skip any DB call.
//
// The flow is:
//  1. Caller hits POST /sandboxes/:id/terminal-token with their API key.
//  2. We check sandbox exists, belongs to caller's team, and is in a
//     state where a terminal makes sense (active or idle — paused/idle
//     gets auto-woken when the WS connects, but failed/starting/etc do not).
//  3. We mint a 60-second token bound to (sandbox_id, team_id, scope=terminal).
//  4. We return the token plus a fully-formed wss:// URL.
//
// The token is single-use at the verifier (edge proxy maintains an LRU
// nonce dedupe), so even if it leaks within the 60s TTL it cannot be
// replayed once the legitimate browser has consumed it.
func (h *Handlers) IssueTerminalToken(c *gin.Context) {
	sandboxID, err := parseSandboxID(c)
	if err != nil {
		return
	}

	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}

	// Verify sandbox exists, belongs to this team, and is active. Only
	// `active` is allowed — the edge proxy bridge does not auto-wake,
	// so issuing a token to an idle sandbox would mint a capability that
	// cannot be used. Callers must resume first, then mint.
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

	if sandbox.Status != db.SandboxStatusActive {
		respondErrorMsg(c, "conflict",
			fmt.Sprintf("sandbox is %s, resume it before opening a terminal", sandbox.Status),
			http.StatusConflict)
		return
	}

	now := time.Now()
	token, err := h.TerminalSign.Mint(now, sandboxID.String(), teamID.String(), auth.ScopeTerminal)
	if err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("terminal token mint failed")
		respondError(c, ErrInternal)
		return
	}

	// Construct the wss URL the browser should connect to. The token is
	// NOT embedded in the URL — it goes in the Sec-WebSocket-Protocol
	// header at connect time. Browsers cannot set arbitrary headers on
	// WebSocket upgrade, but they CAN pass subprotocols via
	// `new WebSocket(url, protocols)`. The frontend must include
	// `["superserve.terminal.v1", "token." + token]` in that array; the
	// proxy picks the first (echoes it back) and validates the second.
	//
	// Putting the token in the URL would leak it to LB access logs,
	// browser history, any Referer header on sub-resources, and any
	// request-logging middleware. Subprotocol headers are not logged.
	url := fmt.Sprintf("wss://%s.%s/terminal", sandboxID.String(), h.Config.EdgeProxyDomain)

	c.JSON(http.StatusOK, terminalTokenResponse{
		Token:       token,
		URL:         url,
		Subprotocol: TerminalSubprotocol,
		ExpiresAt:   now.Add(auth.DefaultTTL),
	})
}
