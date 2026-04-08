package api

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
)

// loadActiveSandboxForMint is the shared preamble for every token-mint
// endpoint on the control plane (terminal, files, and any future scoped
// capability). It runs the identical authorization chain each one needs:
//
//  1. Parse the sandbox ID from the URL.
//  2. Extract the authenticated team ID from the request context (set
//     by APIKeyAuth middleware).
//  3. Load the sandbox by (id, team) — this double-checks that the
//     caller owns the sandbox, not just that the sandbox exists.
//  4. Require status == active. Data-plane tokens are capabilities that
//     only make sense against a live VM; issuing one against an idle or
//     paused sandbox would hand the caller a dud (the edge proxy's
//     resolver check would reject the subsequent data-plane call). Fail
//     early with a 409 so clients know to resume first.
//
// On any failure this helper writes the appropriate error response and
// returns ok=false; the caller should simply return. On success it
// returns the loaded sandbox row and its team ID so the handler can mint
// its scope-specific token and build its scope-specific response URL.
//
// Kept as a method on *Handlers (rather than a free function) so it has
// cheap access to h.DB without a separate parameter.
func (h *Handlers) loadActiveSandboxForMint(c *gin.Context) (sandbox db.Sandbox, teamID uuid.UUID, ok bool) {
	sandboxID, err := parseSandboxID(c)
	if err != nil {
		return db.Sandbox{}, uuid.Nil, false
	}

	teamID, err = teamIDFromContext(c)
	if err != nil {
		return db.Sandbox{}, uuid.Nil, false
	}

	sandbox, err = h.DB.GetSandbox(c.Request.Context(), db.GetSandboxParams{
		ID:     sandboxID,
		TeamID: teamID,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			respondError(c, ErrSandboxNotFound)
			return db.Sandbox{}, uuid.Nil, false
		}
		log.Error().Err(err).
			Str("sandbox_id", sandboxID.String()).
			Msg("DB GetSandbox failed")
		respondError(c, ErrInternal)
		return db.Sandbox{}, uuid.Nil, false
	}

	if sandbox.Status != db.SandboxStatusActive {
		respondErrorMsg(c, "conflict",
			fmt.Sprintf("sandbox is %s, resume it before minting a token", sandbox.Status),
			http.StatusConflict)
		return db.Sandbox{}, uuid.Nil, false
	}

	return sandbox, teamID, true
}
