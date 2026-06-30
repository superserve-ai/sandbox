package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/authz"
)

type teamManagementCapabilities struct {
	CanViewRoleAssignments bool `json:"can_view_role_assignments"`
	CanInviteMembers       bool `json:"can_invite_members"`
	CanDeactivateMembers   bool `json:"can_deactivate_members"`
	CanAssignRoles         bool `json:"can_assign_roles"`
	CanRevokeRoles         bool `json:"can_revoke_roles"`
}

func (c teamManagementCapabilities) hasMutationControls() bool {
	return c.CanInviteMembers || c.CanDeactivateMembers || c.CanAssignRoles || c.CanRevokeRoles
}

func (h *Handlers) customerPermissionAllowed(c *gin.Context, _ uuid.UUID, teamID uuid.UUID, permission string) (bool, error) {
	return h.customerTeamPermissionAllowed(c, teamID, permission)
}

func (h *Handlers) customerManagementCapabilities(c *gin.Context, actorID, teamID uuid.UUID) (teamManagementCapabilities, error) {
	rolesRead, err := h.customerPermissionAllowed(c, actorID, teamID, "roles:read")
	if err != nil {
		return teamManagementCapabilities{}, err
	}
	usersWrite, err := h.customerPermissionAllowed(c, actorID, teamID, "users:write")
	if err != nil {
		return teamManagementCapabilities{}, err
	}
	rolesWrite, err := h.customerPermissionAllowed(c, actorID, teamID, "roles:write")
	if err != nil {
		return teamManagementCapabilities{}, err
	}
	return teamManagementCapabilities{
		CanViewRoleAssignments: rolesRead,
		CanInviteMembers:       usersWrite,
		CanDeactivateMembers:   usersWrite,
		CanAssignRoles:         rolesWrite,
		CanRevokeRoles:         rolesWrite,
	}, nil
}

func (h *Handlers) listTeamRoleNames(c *gin.Context) ([]string, error) {
	rows, err := h.Pool.Query(c.Request.Context(), `
		SELECT name
		FROM roles
		WHERE scope_type = 'team'
		ORDER BY CASE name
			WHEN 'team_owner' THEN 1
			WHEN 'team_admin' THEN 2
			WHEN 'user_admin' THEN 3
			WHEN 'billing_admin' THEN 4
			WHEN 'viewer' THEN 5
			ELSE 99
		END, name ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	roles := make([]string, 0)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		roles = append(roles, name)
	}
	return roles, rows.Err()
}

func (h *Handlers) listTeamMembersForManagement(c *gin.Context, teamID uuid.UUID) ([]teamMemberResponse, error) {
	rows, err := h.Pool.Query(c.Request.Context(), `
		SELECT
			tm.user_id,
			p.email,
			p.full_name,
			tm.status,
			tm.created_at,
			tm.updated_at,
			COALESCE(
				array_agg(DISTINCT r.name) FILTER (WHERE ura.revoked_at IS NULL AND r.scope_type = 'team'),
				'{}'::text[]
			) AS role_names
		FROM team_memberships tm
		JOIN profile p
		  ON p.id = tm.user_id
		LEFT JOIN user_role_assignments ura
		  ON ura.team_id = tm.team_id
		 AND ura.user_id = tm.user_id
		 AND ura.scope_type = 'team'
		LEFT JOIN roles r
		  ON r.id = ura.role_id
		WHERE tm.team_id = $1
		GROUP BY tm.id, p.id
		ORDER BY p.email ASC
	`, teamID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	members := make([]teamMemberResponse, 0)
	for rows.Next() {
		var row teamMemberResponse
		if err := rows.Scan(&row.UserID, &row.Email, &row.FullName, &row.Status, &row.CreatedAt, &row.UpdatedAt, &row.Roles); err != nil {
			return nil, err
		}
		members = append(members, row)
	}
	return members, rows.Err()
}

func (h *Handlers) listTeamAssignmentsForManagement(c *gin.Context, teamID uuid.UUID) ([]roleAssignmentResponse, error) {
	rows, err := h.Pool.Query(c.Request.Context(), `
		SELECT
			ura.id,
			ura.user_id,
			p.email,
			r.name,
			ura.scope_type,
			ura.team_id,
			ura.granted_by,
			ura.granted_at,
			ura.revoked_at,
			ura.created_at,
			ura.updated_at
		FROM user_role_assignments ura
		JOIN roles r
		  ON r.id = ura.role_id
		JOIN profile p
		  ON p.id = ura.user_id
		WHERE ura.team_id = $1
		  AND ura.scope_type = 'team'
		ORDER BY ura.revoked_at IS NULL DESC, ura.granted_at DESC, ura.created_at DESC
	`, teamID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	assignments := make([]roleAssignmentResponse, 0)
	for rows.Next() {
		var row roleAssignmentResponse
		var grantedBy pgtype.UUID
		if err := rows.Scan(
			&row.AssignmentID,
			&row.UserID,
			&row.Email,
			&row.RoleName,
			&row.ScopeType,
			&row.TeamID,
			&grantedBy,
			&row.GrantedAt,
			&row.RevokedAt,
			&row.CreatedAt,
			&row.UpdatedAt,
		); err != nil {
			return nil, err
		}
		row.GrantedBy = uuidPGTypeString(grantedBy)
		assignments = append(assignments, row)
	}
	return assignments, rows.Err()
}

// GetTeamManagement returns the customer UI's read model for team member and
// role management. Mutations remain enforced by the Phase 2 endpoints; these
// capability flags are hints so the UI can hide controls for read-only actors.
func (h *Handlers) GetTeamManagement(c *gin.Context) {
	teamID, err := customerTeamID(c)
	if err != nil {
		return
	}
	actorID, err := customerActorID(c)
	if err != nil {
		return
	}
	usersRead, err := h.customerPermissionAllowed(c, actorID, teamID, "users:read")
	if err != nil {
		if errors.Is(err, authz.ErrPermissionDenied) || errors.Is(err, authz.ErrScopeMismatch) {
			respondError(c, ErrForbidden)
			return
		}
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("RBAC management users:read check failed")
		respondError(c, ErrInternal)
		return
	}
	if !usersRead {
		respondError(c, ErrForbidden)
		return
	}
	if h.Pool == nil {
		respondError(c, ErrInternal)
		return
	}

	caps, err := h.customerManagementCapabilities(c, actorID, teamID)
	if err != nil {
		if errors.Is(err, authz.ErrPermissionDenied) || errors.Is(err, authz.ErrScopeMismatch) {
			respondError(c, ErrForbidden)
			return
		}
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("RBAC management capability check failed")
		respondError(c, ErrInternal)
		return
	}

	members, err := h.listTeamMembersForManagement(c, teamID)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("RBAC management members query failed")
		respondError(c, ErrInternal)
		return
	}
	if !caps.CanViewRoleAssignments {
		for i := range members {
			members[i].Roles = nil
		}
	}

	assignments := make([]roleAssignmentResponse, 0)
	if caps.CanViewRoleAssignments {
		assignments, err = h.listTeamAssignmentsForManagement(c, teamID)
		if err != nil {
			log.Error().Err(err).Str("team_id", teamID.String()).Msg("RBAC management assignments query failed")
			respondError(c, ErrInternal)
			return
		}
	}

	resp := gin.H{
		"team_id":      teamID.String(),
		"members":      members,
		"assignments":  assignments,
		"capabilities": caps,
	}
	if caps.hasMutationControls() {
		options := gin.H{"member_statuses": []string{"active", "invited"}}
		if caps.CanAssignRoles || caps.CanRevokeRoles {
			roleNames, err := h.listTeamRoleNames(c)
			if err != nil {
				log.Error().Err(err).Str("team_id", teamID.String()).Msg("RBAC management role catalog query failed")
				respondError(c, ErrInternal)
				return
			}
			options["assignable_roles"] = roleNames
		}
		resp["mutation_options"] = options
	}

	c.JSON(http.StatusOK, resp)
}
