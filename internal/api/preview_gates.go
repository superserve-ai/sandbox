package api

import (
	"fmt"
	"net/http"
	"slices"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/auth"
	"github.com/superserve-ai/sandbox/internal/db"
)

// Rollout gates for the preview-URL model. Two independent controls, both of
// which gate ENABLEMENT only — neither ever weakens enforcement:
//
//   - Feature flags decide whether a team may opt sandboxes/ports INTO the
//     model (strict policies, publishing, private ports). Once a port is
//     recorded, the proxy enforces its mode regardless of flag state, and
//     revocation (unpublish, rotate) always works — turning a flag off must
//     never strand a customer with credentials they cannot revoke.
//
//   - Host capabilities decide whether the sandbox's assigned host can
//     actually enforce what is being enabled. vmd advertises them on every
//     heartbeat; a host that has not advertised a capability (old binary,
//     partially deployed fleet, or a host row we cannot find) fails the API
//     call instead of recording a policy nothing enforces.
const (
	flagPreviewPortPublication   = "preview_port_publication_enabled"
	flagPreviewPortPrivateAccess = "preview_port_private_access_enabled"
)

// requirePreviewFlags writes a 403 and returns false unless every listed flag
// is enabled for the team (team override first, then the global flag, default
// off — see feature_enabled()).
func (h *Handlers) requirePreviewFlags(c *gin.Context, teamID uuid.UUID, keys ...string) bool {
	for _, key := range keys {
		enabled, err := h.DB.IsFeatureEnabledForTeam(c.Request.Context(), db.IsFeatureEnabledForTeamParams{
			Key:    key,
			TeamID: pgtype.UUID{Bytes: teamID, Valid: true},
		})
		if err != nil {
			log.Error().Err(err).Str("team_id", teamID.String()).Str("flag", key).Msg("DB IsFeatureEnabledForTeam failed")
			respondError(c, ErrInternal)
			return false
		}
		if !enabled {
			respondErrorMsg(c, "forbidden",
				fmt.Sprintf("Preview feature %q is not enabled for this team", key),
				http.StatusForbidden)
			return false
		}
	}
	return true
}

// requireHostPreviewCapabilities writes a 409 and returns false unless the
// host advertises enforcement of the published-port allowlist — and, when
// needTokens is set, per-port token verification. A missing host row fails
// closed: a host we cannot verify cannot be assumed to enforce anything.
func (h *Handlers) requireHostPreviewCapabilities(c *gin.Context, hostID string, needTokens bool) bool {
	need := []string{auth.HostCapabilityPreviewPorts}
	if needTokens {
		need = append(need, auth.HostCapabilityPreviewPortTokens)
	}
	host, err := h.DB.GetHost(c.Request.Context(), hostID)
	if err != nil && err != pgx.ErrNoRows {
		log.Error().Err(err).Str("host_id", hostID).Msg("DB GetHost failed")
		respondError(c, ErrInternal)
		return false
	}
	for _, capability := range need {
		if err == pgx.ErrNoRows || !slices.Contains(host.Capabilities, capability) {
			respondErrorMsg(c, "conflict",
				fmt.Sprintf("The sandbox's host does not enforce %q; retry after the fleet is upgraded", capability),
				http.StatusConflict)
			return false
		}
	}
	return true
}

// defaultPortAccess is the access mode a newly published port gets when the
// caller does not specify one: the sandbox-level policy for a public sandbox,
// private for everything else. Defaulting a legacy sandbox's publishes to
// private means a later move to a strict policy can never silently expose a
// port that was published as preparation.
func defaultPortAccess(sandboxAccess string) string {
	if sandboxAccess == auth.PreviewAccessPublic {
		return auth.PreviewAccessPublic
	}
	return auth.PreviewAccessPrivate
}

// validatePortAccess rejects anything but the two per-port modes. nil is
// valid — the sandbox default applies.
func validatePortAccess(v *string) error {
	if v == nil || *v == auth.PreviewAccessPublic || *v == auth.PreviewAccessPrivate {
		return nil
	}
	return fmt.Errorf("access must be %q or %q", auth.PreviewAccessPublic, auth.PreviewAccessPrivate)
}
