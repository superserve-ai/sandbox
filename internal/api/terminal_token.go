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

// terminalTokenResponse is what the browser receives. The fields are kept
// minimal so the frontend can act without parsing or constructing URLs:
//
//   - token: opaque, paste straight into the WebSocket URL.
//   - url:   fully-formed wss:// URL the browser opens directly. Includes
//     the token as a query param because browser WebSocket APIs cannot set
//     custom headers on the upgrade request.
//   - expires_at: ISO-8601 expiry, so the frontend can pre-fetch a fresh
//     token before the current one expires (mostly defensive — TTL is 60s
//     and the WS upgrade happens immediately).
type terminalTokenResponse struct {
	Token     string    `json:"token"`
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
}

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

	// Verify sandbox exists, belongs to this team, and is in a usable
	// state. We deliberately allow `idle` here because the WS bridge will
	// wake the sandbox on connect — issuing a token to a paused sandbox
	// is the natural UX (the user clicked "open terminal" on a paused
	// box). We do NOT issue tokens for transient states (starting,
	// pausing) or terminal states (failed, deleted) — those are bugs
	// waiting to happen at the bridge layer.
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

	switch sandbox.Status {
	case db.SandboxStatusActive, db.SandboxStatusIdle:
		// OK — terminal can be opened directly (active) or after the
		// edge proxy triggers an auto-wake (idle).
	default:
		respondErrorMsg(c, "conflict",
			fmt.Sprintf("sandbox is %s, terminal not available", sandbox.Status),
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

	// Construct the wss URL the browser should connect to. We hand back
	// a fully-formed URL so the frontend doesn't have to know our host
	// scheme — that lets us migrate the URL pattern later (e.g. moving
	// from `{id}.sandbox.superserve.ai` to a regional sub-domain) without
	// touching the frontend.
	url := fmt.Sprintf("wss://%s.%s/terminal?t=%s", sandboxID.String(), h.Config.EdgeProxyDomain, token)

	c.JSON(http.StatusOK, terminalTokenResponse{
		Token:     token,
		URL:       url,
		ExpiresAt: now.Add(auth.DefaultTTL),
	})
}
