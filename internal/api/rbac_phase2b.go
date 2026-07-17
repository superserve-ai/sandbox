package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/authz"
	"github.com/superserve-ai/sandbox/internal/db"
)

const internalActorHeader = "X-Actor-User-Id"

var errMembershipNotActive = errors.New("membership is not active")

type teamMembershipPayload struct {
	UserID string `json:"user_id"`
	Status string `json:"status,omitempty"`
}

type teamRolePayload struct {
	UserID   string `json:"user_id"`
	RoleName string `json:"role_name"`
}

type platformRecoveryPayload struct {
	UserID string `json:"user_id"`
}

type teamMemberResponse struct {
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
	FullName  *string   `json:"full_name,omitempty"`
	Status    string    `json:"status"`
	Roles     []string  `json:"roles,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type roleAssignmentResponse struct {
	AssignmentID string     `json:"assignment_id"`
	UserID       string     `json:"user_id"`
	Email        string     `json:"email"`
	RoleName     string     `json:"role_name"`
	ScopeType    string     `json:"scope_type"`
	TeamID       string     `json:"team_id"`
	GrantedBy    *string    `json:"granted_by,omitempty"`
	GrantedAt    time.Time  `json:"granted_at"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

type membershipRecord struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TeamID    uuid.UUID
	Status    string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type roleAssignmentRecord struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	RoleID    uuid.UUID
	RoleName  string
	TeamID    uuid.UUID
	GrantedBy pgtype.UUID
	GrantedAt time.Time
	RevokedAt *time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (h *Handlers) rbacService() *authz.Service {
	return h.authzService()
}

func parseUUIDParam(c *gin.Context, name string) (uuid.UUID, error) {
	raw := strings.TrimSpace(c.Param(name))
	if raw == "" {
		respondErrorMsg(c, "bad_request", fmt.Sprintf("%s is required", name), http.StatusBadRequest)
		return uuid.Nil, fmt.Errorf("missing %s", name)
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		respondErrorMsg(c, "bad_request", fmt.Sprintf("%s is not a valid UUID", name), http.StatusBadRequest)
		return uuid.Nil, err
	}
	return id, nil
}

func customerTeamID(c *gin.Context) (uuid.UUID, error) {
	pathTeamID, err := parseUUIDParam(c, "team_id")
	if err != nil {
		return uuid.Nil, err
	}
	ctxTeamID, err := teamIDFromContext(c)
	if err != nil {
		return uuid.Nil, err
	}
	if ctxTeamID != pathTeamID {
		respondError(c, ErrForbidden)
		return uuid.Nil, fmt.Errorf("team mismatch")
	}
	return pathTeamID, nil
}

func internalTeamID(c *gin.Context) (uuid.UUID, error) {
	return parseUUIDParam(c, "team_id")
}

func customerActorID(c *gin.Context) (uuid.UUID, error) {
	if actor := actorIDFromContext(c); actor != nil {
		return *actor, nil
	}
	respondError(c, ErrUnauthorized)
	return uuid.Nil, fmt.Errorf("missing api key actor id")
}

func internalActorID(c *gin.Context) (uuid.UUID, error) {
	if actor := actorIDFromContext(c); actor != nil {
		return *actor, nil
	}
	raw := strings.TrimSpace(c.GetHeader(internalActorHeader))
	if raw == "" {
		respondError(c, ErrUnauthorized)
		return uuid.Nil, fmt.Errorf("missing actor id")
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		respondErrorMsg(c, "bad_request", "X-Actor-User-Id is not a valid UUID", http.StatusBadRequest)
		return uuid.Nil, err
	}
	return id, nil
}

func requestActorID(c *gin.Context, platform bool) (uuid.UUID, error) {
	if platform {
		return internalActorID(c)
	}
	return customerActorID(c)
}

func (h *Handlers) withRBACMutation(ctx context.Context, teamID uuid.UUID, fn func(q db.DBTX, svc *authz.Service) error) error {
	if h == nil {
		return fmt.Errorf("handlers not configured")
	}
	if h.Pool == nil {
		return fmt.Errorf("rbac store is not configured")
	}
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := fn(tx, authz.New(tx)); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	// Drop this instance's cached grants for the team; other instances converge
	// within the cache TTL (see teamPermCacheTTL for the revocation contract).
	if svc := h.authzService(); svc != nil {
		svc.InvalidateTeam(teamID)
	}
	return nil
}

func lockTeamMutation(ctx context.Context, q db.DBTX, teamID uuid.UUID) error {
	_, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, teamID.String())
	return err
}

func ensureTeamExists(ctx context.Context, q db.DBTX, teamID uuid.UUID) error {
	var exists bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM team WHERE id = $1)`, teamID).Scan(&exists)
	if err != nil {
		return err
	}
	if !exists {
		return pgx.ErrNoRows
	}
	return nil
}

func ensureProfileExists(ctx context.Context, q db.DBTX, userID uuid.UUID) error {
	var exists bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM profile WHERE id = $1)`, userID).Scan(&exists)
	if err != nil {
		return err
	}
	if !exists {
		return pgx.ErrNoRows
	}
	return nil
}

func lookupRoleID(ctx context.Context, q db.DBTX, roleName, scopeType string) (uuid.UUID, error) {
	var roleID uuid.UUID
	err := q.QueryRow(ctx, `
		SELECT id
		FROM roles
		WHERE name = $1
		  AND scope_type = $2
	`, roleName, scopeType).Scan(&roleID)
	if err != nil {
		return uuid.Nil, err
	}
	return roleID, nil
}

func loadMembership(ctx context.Context, q db.DBTX, teamID, userID uuid.UUID) (membershipRecord, error) {
	var rec membershipRecord
	err := q.QueryRow(ctx, `
		SELECT id, team_id, user_id, status, created_at, updated_at
		FROM team_memberships
		WHERE team_id = $1
		  AND user_id = $2
		ORDER BY updated_at DESC, created_at DESC
		LIMIT 1
		FOR UPDATE
	`, teamID, userID).Scan(&rec.ID, &rec.TeamID, &rec.UserID, &rec.Status, &rec.CreatedAt, &rec.UpdatedAt)
	if err != nil {
		return membershipRecord{}, err
	}
	return rec, nil
}

func upsertMembership(ctx context.Context, q db.DBTX, teamID, userID uuid.UUID, status string) (membershipRecord, bool, error) {
	rec, err := loadMembership(ctx, q, teamID, userID)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return membershipRecord{}, false, err
		}
		now := time.Now().UTC()
		var id uuid.UUID
		if err := q.QueryRow(ctx, `
			INSERT INTO team_memberships (team_id, user_id, status, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $4)
			RETURNING id
		`, teamID, userID, status, now).Scan(&id); err != nil {
			return membershipRecord{}, false, err
		}
		return membershipRecord{
			ID:        id,
			TeamID:    teamID,
			UserID:    userID,
			Status:    status,
			CreatedAt: now,
			UpdatedAt: now,
		}, true, nil
	}

	now := time.Now().UTC()
	if _, err := q.Exec(ctx, `
		UPDATE team_memberships
		SET status = $2,
		    updated_at = $3
		WHERE id = $1
	`, rec.ID, status, now); err != nil {
		return membershipRecord{}, false, err
	}
	rec.Status = status
	rec.UpdatedAt = now
	return rec, false, nil
}

func loadAssignment(ctx context.Context, q db.DBTX, teamID, assignmentID uuid.UUID) (roleAssignmentRecord, error) {
	var rec roleAssignmentRecord
	err := q.QueryRow(ctx, `
		SELECT ura.id, ura.user_id, ura.role_id, r.name, ura.team_id, ura.granted_by, ura.granted_at,
		       ura.revoked_at, ura.created_at, ura.updated_at
		FROM user_role_assignments ura
		JOIN roles r
		  ON r.id = ura.role_id
		WHERE ura.id = $1
		  AND ura.team_id = $2
		  AND ura.scope_type = 'team'
		FOR UPDATE
	`, assignmentID, teamID).Scan(
		&rec.ID,
		&rec.UserID,
		&rec.RoleID,
		&rec.RoleName,
		&rec.TeamID,
		&rec.GrantedBy,
		&rec.GrantedAt,
		&rec.RevokedAt,
		&rec.CreatedAt,
		&rec.UpdatedAt,
	)
	if err != nil {
		return roleAssignmentRecord{}, err
	}
	return rec, nil
}

func loadActiveRoleAssignments(ctx context.Context, q db.DBTX, teamID, userID uuid.UUID) ([]roleAssignmentRecord, error) {
	rows, err := q.Query(ctx, `
		SELECT ura.id, ura.user_id, ura.role_id, r.name, ura.team_id, ura.granted_by, ura.granted_at,
		       ura.revoked_at, ura.created_at, ura.updated_at
		FROM user_role_assignments ura
		JOIN roles r
		  ON r.id = ura.role_id
		WHERE ura.team_id = $1
		  AND ura.user_id = $2
		  AND ura.scope_type = 'team'
		  AND ura.revoked_at IS NULL
		ORDER BY ura.granted_at DESC, ura.created_at DESC
		FOR UPDATE
	`, teamID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	assignments := make([]roleAssignmentRecord, 0)
	for rows.Next() {
		var rec roleAssignmentRecord
		if err := rows.Scan(
			&rec.ID,
			&rec.UserID,
			&rec.RoleID,
			&rec.RoleName,
			&rec.TeamID,
			&rec.GrantedBy,
			&rec.GrantedAt,
			&rec.RevokedAt,
			&rec.CreatedAt,
			&rec.UpdatedAt,
		); err != nil {
			return nil, err
		}
		assignments = append(assignments, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return assignments, nil
}

func activeAssignmentExists(ctx context.Context, q db.DBTX, teamID, userID, roleID uuid.UUID) (bool, error) {
	var exists bool
	err := q.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM user_role_assignments
			WHERE team_id = $1
			  AND user_id = $2
			  AND role_id = $3
			  AND scope_type = 'team'
			  AND revoked_at IS NULL
		)
	`, teamID, userID, roleID).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

func hasActiveRoleGrants(ctx context.Context, q db.DBTX, teamID, userID uuid.UUID) (bool, error) {
	var exists bool
	err := q.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM user_role_assignments
			WHERE team_id = $1
			  AND user_id = $2
			  AND scope_type = 'team'
			  AND revoked_at IS NULL
		)
	`, teamID, userID).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

func hasActivePrivilegedRoleGrants(ctx context.Context, q db.DBTX, teamID, userID uuid.UUID) (bool, error) {
	var exists bool
	err := q.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM user_role_assignments ura
			JOIN roles r
			  ON r.id = ura.role_id
			 AND r.scope_type = 'team'
			WHERE ura.team_id = $1
			  AND ura.user_id = $2
			  AND ura.scope_type = 'team'
			  AND ura.revoked_at IS NULL
			  AND r.name IN ('team_owner', 'team_admin')
		)
	`, teamID, userID).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

func (h *Handlers) requireRolesWriteForActivePrivilegedGrants(ctx context.Context, q db.DBTX, svc *authz.Service, actorID, teamID, targetUserID uuid.UUID, platform bool) error {
	hasPrivilegedActiveGrant, err := hasActivePrivilegedRoleGrants(ctx, q, teamID, targetUserID)
	if err != nil {
		return err
	}
	if !hasPrivilegedActiveGrant {
		return nil
	}
	permission := "roles:write"
	if platform {
		permission = "platform:team_roles:write"
	}
	if platform {
		return svc.RequirePlatformPermission(ctx, actorID, permission)
	}
	return svc.RequireTeamPermission(ctx, actorID, teamID, permission)
}

func activeOwnerCount(ctx context.Context, q db.DBTX, teamID uuid.UUID) (int64, error) {
	var count int64
	err := q.QueryRow(ctx, `
		SELECT COUNT(*)::bigint
		FROM user_role_assignments ura
		JOIN roles r
		  ON r.id = ura.role_id
		 AND r.scope_type = 'team'
		JOIN team_memberships tm
		  ON tm.team_id = ura.team_id
		 AND tm.user_id = ura.user_id
		 AND tm.status = 'active'
		WHERE ura.team_id = $1
		  AND ura.scope_type = 'team'
		  AND ura.revoked_at IS NULL
		  AND r.name = 'team_owner'
	`, teamID).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

func jsonValue(v any) []byte {
	if v == nil {
		return nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return raw
}

func (h *Handlers) writeRBACAudit(ctx context.Context, q db.DBTX, actorID, targetID, teamID *uuid.UUID, eventType string, oldValue, newValue, metadata any) error {
	svc := authz.New(q)
	return svc.WriteAuditLog(ctx, q, authz.AuditEvent{
		ActorUserID:  actorID,
		TargetUserID: targetID,
		TeamID:       teamID,
		EventType:    eventType,
		OldValue:     jsonValue(oldValue),
		NewValue:     jsonValue(newValue),
		Metadata:     jsonValue(metadata),
	})
}

func (h *Handlers) requirePlatformAdminGoogleSession(ctx context.Context, q db.DBTX, actorID uuid.UUID) error {
	if q == nil {
		return fmt.Errorf("rbac store is not configured")
	}
	var provider, email sql.NullString
	if err := q.QueryRow(ctx, `SELECT provider, email FROM profile WHERE id = $1`, actorID).Scan(&provider, &email); err != nil {
		return err
	}
	if !provider.Valid || !email.Valid {
		return authz.ErrSessionNotEligible
	}
	claims := authz.SessionClaims{
		Provider: provider.String,
		Email:    email.String,
	}
	return authz.RequirePlatformAdminGoogleSession(ctx, claims)
}

func (h *Handlers) requireTeamPermission(c *gin.Context, actorID, teamID uuid.UUID, permission string, platform bool) error {
	svc := h.rbacService()
	if svc == nil {
		return fmt.Errorf("rbac service is not configured")
	}
	if platform {
		return svc.RequirePlatformPermission(c.Request.Context(), actorID, permission)
	}
	return svc.RequireTeamPermission(c.Request.Context(), actorID, teamID, permission)
}

func requireTeamPermissionOnTx(ctx context.Context, svc *authz.Service, actorID, teamID uuid.UUID, permission string, platform bool) error {
	if svc == nil {
		return fmt.Errorf("rbac service is not configured")
	}
	if platform {
		return svc.RequirePlatformPermission(ctx, actorID, permission)
	}
	return svc.RequireTeamPermission(ctx, actorID, teamID, permission)
}

func teamMemberResponseFromRow(row teamMemberResponse) gin.H {
	return gin.H{
		"user_id":    row.UserID,
		"email":      row.Email,
		"full_name":  row.FullName,
		"status":     row.Status,
		"roles":      row.Roles,
		"created_at": row.CreatedAt,
		"updated_at": row.UpdatedAt,
	}
}

func assignmentResponseFromRow(row roleAssignmentResponse) gin.H {
	return gin.H{
		"assignment_id": row.AssignmentID,
		"user_id":       row.UserID,
		"email":         row.Email,
		"role_name":     row.RoleName,
		"scope_type":    row.ScopeType,
		"team_id":       row.TeamID,
		"granted_by":    row.GrantedBy,
		"granted_at":    row.GrantedAt,
		"revoked_at":    row.RevokedAt,
		"created_at":    row.CreatedAt,
		"updated_at":    row.UpdatedAt,
	}
}

func (h *Handlers) listMembers(c *gin.Context, platform bool) {
	var teamID uuid.UUID
	var err error
	if platform {
		teamID, err = internalTeamID(c)
	} else {
		teamID, err = customerTeamID(c)
	}
	if err != nil {
		return
	}
	actorID, err := requestActorID(c, platform)
	if err != nil {
		return
	}
	if platform {
		if err := h.requirePlatformAdminGoogleSession(c.Request.Context(), h.Pool, actorID); err != nil {
			if errors.Is(err, authz.ErrSessionNotEligible) || errors.Is(err, pgx.ErrNoRows) {
				respondError(c, ErrForbidden)
				return
			}
			log.Error().Err(err).Str("team_id", teamID.String()).Msg("RBAC list members session validation failed")
			respondError(c, ErrInternal)
			return
		}
	}
	permission := "users:read"
	if platform {
		permission = "platform:teams:read"
	}
	if err := h.requireTeamPermission(c, actorID, teamID, permission, platform); err != nil {
		if errors.Is(err, authz.ErrPermissionDenied) || errors.Is(err, authz.ErrScopeMismatch) {
			respondError(c, ErrForbidden)
			return
		}
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("RBAC list members authorization failed")
		respondError(c, ErrInternal)
		return
	}

	ctx := c.Request.Context()
	if h.Pool == nil {
		respondError(c, ErrInternal)
		return
	}
	rows, err := h.Pool.Query(ctx, `
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
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("RBAC list members query failed")
		respondError(c, ErrInternal)
		return
	}
	defer rows.Close()

	members := make([]teamMemberResponse, 0)
	for rows.Next() {
		var row teamMemberResponse
		if err := rows.Scan(&row.UserID, &row.Email, &row.FullName, &row.Status, &row.CreatedAt, &row.UpdatedAt, &row.Roles); err != nil {
			log.Error().Err(err).Str("team_id", teamID.String()).Msg("RBAC list members scan failed")
			respondError(c, ErrInternal)
			return
		}
		members = append(members, row)
	}
	if err := rows.Err(); err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("RBAC list members rows failed")
		respondError(c, ErrInternal)
		return
	}

	c.JSON(http.StatusOK, gin.H{"members": members})
}

func (h *Handlers) listAssignments(c *gin.Context, platform bool) {
	var teamID uuid.UUID
	var err error
	if platform {
		teamID, err = internalTeamID(c)
	} else {
		teamID, err = customerTeamID(c)
	}
	if err != nil {
		return
	}
	actorID, err := requestActorID(c, platform)
	if err != nil {
		return
	}
	if platform {
		if err := h.requirePlatformAdminGoogleSession(c.Request.Context(), h.Pool, actorID); err != nil {
			if errors.Is(err, authz.ErrSessionNotEligible) || errors.Is(err, pgx.ErrNoRows) {
				respondError(c, ErrForbidden)
				return
			}
			log.Error().Err(err).Str("team_id", teamID.String()).Msg("RBAC list assignments session validation failed")
			respondError(c, ErrInternal)
			return
		}
	}
	permission := "roles:read"
	if platform {
		permission = "platform:teams:read"
	}
	if err := h.requireTeamPermission(c, actorID, teamID, permission, platform); err != nil {
		if errors.Is(err, authz.ErrPermissionDenied) || errors.Is(err, authz.ErrScopeMismatch) {
			respondError(c, ErrForbidden)
			return
		}
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("RBAC list assignments authorization failed")
		respondError(c, ErrInternal)
		return
	}

	ctx := c.Request.Context()
	if h.Pool == nil {
		respondError(c, ErrInternal)
		return
	}
	rows, err := h.Pool.Query(ctx, `
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
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("RBAC list assignments query failed")
		respondError(c, ErrInternal)
		return
	}
	defer rows.Close()

	out := make([]roleAssignmentResponse, 0)
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
			log.Error().Err(err).Str("team_id", teamID.String()).Msg("RBAC list assignments scan failed")
			respondError(c, ErrInternal)
			return
		}
		row.GrantedBy = uuidPGTypeString(grantedBy)
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("RBAC list assignments rows failed")
		respondError(c, ErrInternal)
		return
	}

	c.JSON(http.StatusOK, gin.H{"assignments": out})
}

func (h *Handlers) addMember(c *gin.Context, platform bool) {
	var teamID uuid.UUID
	var err error
	if platform {
		teamID, err = internalTeamID(c)
	} else {
		teamID, err = customerTeamID(c)
	}
	if err != nil {
		return
	}
	actorID, err := requestActorID(c, platform)
	if err != nil {
		return
	}
	if platform {
		if err := h.requirePlatformAdminGoogleSession(c.Request.Context(), h.Pool, actorID); err != nil {
			if errors.Is(err, authz.ErrSessionNotEligible) || errors.Is(err, pgx.ErrNoRows) {
				respondError(c, ErrForbidden)
				return
			}
			log.Error().Err(err).Str("team_id", teamID.String()).Msg("RBAC add member session validation failed")
			respondError(c, ErrInternal)
			return
		}
	}
	permission := "users:write"
	if platform {
		permission = "platform:team_users:write"
	}
	if err := h.requireTeamPermission(c, actorID, teamID, permission, platform); err != nil {
		if errors.Is(err, authz.ErrPermissionDenied) || errors.Is(err, authz.ErrScopeMismatch) {
			respondError(c, ErrForbidden)
			return
		}
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("RBAC add member authorization failed")
		respondError(c, ErrInternal)
		return
	}

	var req teamMembershipPayload
	if err := bindJSONStrict(c, &req); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	targetUserID, err := uuid.Parse(strings.TrimSpace(req.UserID))
	if err != nil {
		respondErrorMsg(c, "bad_request", "user_id is not a valid UUID", http.StatusBadRequest)
		return
	}
	status := strings.TrimSpace(req.Status)
	if status == "" {
		status = "active"
	}
	if status != "active" && status != "invited" {
		respondErrorMsg(c, "bad_request", "status must be active or invited", http.StatusBadRequest)
		return
	}

	ctx := c.Request.Context()
	err = h.withRBACMutation(ctx, teamID, func(q db.DBTX, svc *authz.Service) error {
		if err := lockTeamMutation(ctx, q, teamID); err != nil {
			return err
		}
		if err := requireTeamPermissionOnTx(ctx, svc, actorID, teamID, permission, platform); err != nil {
			return err
		}
		if err := ensureTeamExists(ctx, q, teamID); err != nil {
			return err
		}
		if err := ensureProfileExists(ctx, q, targetUserID); err != nil {
			return err
		}
		prior, priorErr := loadMembership(ctx, q, teamID, targetUserID)
		if priorErr != nil && !errors.Is(priorErr, pgx.ErrNoRows) {
			return priorErr
		}
		if priorErr == nil && prior.Status == "active" && status != "active" {
			revokedAssignments, err := loadActiveRoleAssignments(ctx, q, teamID, targetUserID)
			if err != nil {
				return err
			}
			ok, err := svc.CanRevokeLastTeamOwner(ctx, teamID, targetUserID)
			if err != nil {
				return err
			}
			if !ok {
				return ErrConflict
			}
			if err := h.requireRolesWriteForActivePrivilegedGrants(ctx, q, svc, actorID, teamID, targetUserID, platform); err != nil {
				return err
			}
			if err := h.auditRevokedRoleAssignments(ctx, q, &actorID, &targetUserID, &teamID, platform, revokedAssignments, time.Now().UTC()); err != nil {
				return err
			}
		}
		if priorErr == nil && prior.Status != "active" && status == "active" {
			hasActiveRole, err := hasActiveRoleGrants(ctx, q, teamID, targetUserID)
			if err != nil {
				return err
			}
			hasPrivilegedActiveGrant, err := hasActivePrivilegedRoleGrants(ctx, q, teamID, targetUserID)
			if err != nil {
				return err
			}
			if hasActiveRole || hasPrivilegedActiveGrant {
				permission := "roles:write"
				if platform {
					permission = "platform:team_roles:write"
				}
				if err := requireTeamPermissionOnTx(ctx, svc, actorID, teamID, permission, platform); err != nil {
					return err
				}
			}
		}
		rec, created, err := upsertMembership(ctx, q, teamID, targetUserID, status)
		if err != nil {
			return err
		}
		eventType := "team_member_added"
		if platform {
			eventType = "platform_team_member_added"
		}
		meta := map[string]any{"status": status, "created": created}
		return h.writeRBACAudit(ctx, q, &actorID, &targetUserID, &teamID, eventType, nil, map[string]any{
			"user_id":    rec.UserID.String(),
			"team_id":    rec.TeamID.String(),
			"status":     rec.Status,
			"created_at": rec.CreatedAt,
			"updated_at": rec.UpdatedAt,
		}, meta)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondErrorMsg(c, "not_found", "team or user not found", http.StatusNotFound)
			return
		}
		if errors.Is(err, ErrConflict) {
			respondError(c, ErrConflict)
			return
		}
		if errors.Is(err, authz.ErrPermissionDenied) || errors.Is(err, authz.ErrScopeMismatch) {
			respondError(c, ErrForbidden)
			return
		}
		log.Error().Err(err).Str("team_id", teamID.String()).Str("user_id", targetUserID.String()).Msg("RBAC add member failed")
		respondError(c, ErrInternal)
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"team_id":  teamID.String(),
		"user_id":  targetUserID.String(),
		"status":   status,
		"action":   "added",
		"platform": platform,
	})
}

func (h *Handlers) deactivateMember(c *gin.Context, platform bool) {
	var teamID uuid.UUID
	var err error
	if platform {
		teamID, err = internalTeamID(c)
	} else {
		teamID, err = customerTeamID(c)
	}
	if err != nil {
		return
	}
	actorID, err := requestActorID(c, platform)
	if err != nil {
		return
	}
	if platform {
		if err := h.requirePlatformAdminGoogleSession(c.Request.Context(), h.Pool, actorID); err != nil {
			if errors.Is(err, authz.ErrSessionNotEligible) || errors.Is(err, pgx.ErrNoRows) {
				respondError(c, ErrForbidden)
				return
			}
			log.Error().Err(err).Str("team_id", teamID.String()).Msg("RBAC deactivate member session validation failed")
			respondError(c, ErrInternal)
			return
		}
	}
	permission := "users:write"
	if platform {
		permission = "platform:team_users:write"
	}
	if err := h.requireTeamPermission(c, actorID, teamID, permission, platform); err != nil {
		if errors.Is(err, authz.ErrPermissionDenied) || errors.Is(err, authz.ErrScopeMismatch) {
			respondError(c, ErrForbidden)
			return
		}
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("RBAC deactivate member authorization failed")
		respondError(c, ErrInternal)
		return
	}

	targetUserID, err := parseUUIDParam(c, "user_id")
	if err != nil {
		return
	}

	ctx := c.Request.Context()
	err = h.withRBACMutation(ctx, teamID, func(q db.DBTX, svc *authz.Service) error {
		if err := lockTeamMutation(ctx, q, teamID); err != nil {
			return err
		}
		if err := requireTeamPermissionOnTx(ctx, svc, actorID, teamID, permission, platform); err != nil {
			return err
		}
		if err := ensureTeamExists(ctx, q, teamID); err != nil {
			return err
		}
		rec, err := loadMembership(ctx, q, teamID, targetUserID)
		if err != nil {
			return err
		}
		if rec.Status != "active" {
			return errMembershipNotActive
		}
		ok, err := svc.CanRevokeLastTeamOwner(ctx, teamID, targetUserID)
		if err != nil {
			return err
		}
		if !ok {
			return ErrConflict
		}
		revokedAssignments, err := loadActiveRoleAssignments(ctx, q, teamID, targetUserID)
		if err != nil {
			return err
		}
		if err := h.requireRolesWriteForActivePrivilegedGrants(ctx, q, svc, actorID, teamID, targetUserID, platform); err != nil {
			return err
		}
		now := time.Now().UTC()
		if _, err := q.Exec(ctx, `
			UPDATE team_memberships
			SET status = 'inactive',
			    updated_at = $2
			WHERE id = $1
		`, rec.ID, now); err != nil {
			return err
		}
		eventType := "team_member_deactivated"
		if platform {
			eventType = "platform_team_member_deactivated"
		}
		if err := h.auditRevokedRoleAssignments(ctx, q, &actorID, &targetUserID, &teamID, platform, revokedAssignments, now); err != nil {
			return err
		}
		return h.writeRBACAudit(ctx, q, &actorID, &targetUserID, &teamID, eventType, map[string]any{
			"status": rec.Status,
		}, map[string]any{
			"status":     "inactive",
			"updated_at": now,
		}, nil)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondErrorMsg(c, "not_found", "team or user not found", http.StatusNotFound)
			return
		}
		if errors.Is(err, ErrConflict) {
			respondError(c, ErrConflict)
			return
		}
		if errors.Is(err, authz.ErrPermissionDenied) || errors.Is(err, authz.ErrScopeMismatch) {
			respondError(c, ErrForbidden)
			return
		}
		if errors.Is(err, errMembershipNotActive) {
			respondErrorMsg(c, "conflict", errMembershipNotActive.Error(), http.StatusConflict)
			return
		}
		log.Error().Err(err).Str("team_id", teamID.String()).Str("user_id", targetUserID.String()).Msg("RBAC deactivate member failed")
		respondError(c, ErrInternal)
		return
	}

	c.Status(http.StatusNoContent)
}

func (h *Handlers) assignRole(c *gin.Context, platform bool) {
	var teamID uuid.UUID
	var err error
	if platform {
		teamID, err = internalTeamID(c)
	} else {
		teamID, err = customerTeamID(c)
	}
	if err != nil {
		return
	}
	actorID, err := requestActorID(c, platform)
	if err != nil {
		return
	}
	if platform {
		if err := h.requirePlatformAdminGoogleSession(c.Request.Context(), h.Pool, actorID); err != nil {
			if errors.Is(err, authz.ErrSessionNotEligible) || errors.Is(err, pgx.ErrNoRows) {
				respondError(c, ErrForbidden)
				return
			}
			log.Error().Err(err).Str("team_id", teamID.String()).Msg("RBAC assign role session validation failed")
			respondError(c, ErrInternal)
			return
		}
	}
	permission := "roles:write"
	if platform {
		permission = "platform:team_roles:write"
	}
	if err := h.requireTeamPermission(c, actorID, teamID, permission, platform); err != nil {
		if errors.Is(err, authz.ErrPermissionDenied) || errors.Is(err, authz.ErrScopeMismatch) {
			respondError(c, ErrForbidden)
			return
		}
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("RBAC assign role authorization failed")
		respondError(c, ErrInternal)
		return
	}

	var req teamRolePayload
	if err := bindJSONStrict(c, &req); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	targetUserID, err := uuid.Parse(strings.TrimSpace(req.UserID))
	if err != nil {
		respondErrorMsg(c, "bad_request", "user_id is not a valid UUID", http.StatusBadRequest)
		return
	}
	roleName := strings.TrimSpace(req.RoleName)
	if roleName == "" {
		respondErrorMsg(c, "bad_request", "role_name is required", http.StatusBadRequest)
		return
	}

	ctx := c.Request.Context()
	var assignment roleAssignmentRecord
	var assignmentEmail string
	err = h.withRBACMutation(ctx, teamID, func(q db.DBTX, svc *authz.Service) error {
		if err := lockTeamMutation(ctx, q, teamID); err != nil {
			return err
		}
		if err := requireTeamPermissionOnTx(ctx, svc, actorID, teamID, permission, platform); err != nil {
			return err
		}
		if err := ensureTeamExists(ctx, q, teamID); err != nil {
			return err
		}
		if err := ensureProfileExists(ctx, q, targetUserID); err != nil {
			return err
		}
		member, err := loadMembership(ctx, q, teamID, targetUserID)
		if err != nil {
			return err
		}
		if member.Status != "active" {
			return errMembershipNotActive
		}
		roleID, err := lookupRoleID(ctx, q, roleName, "team")
		if err != nil {
			return err
		}
		active, err := activeAssignmentExists(ctx, q, teamID, targetUserID, roleID)
		if err != nil {
			return err
		}
		if active {
			return ErrConflict
		}
		now := time.Now().UTC()
		if _, err := q.Exec(ctx, `
			INSERT INTO user_role_assignments (
				user_id, role_id, scope_type, team_id,
				granted_by, granted_at, created_at, updated_at
			)
			VALUES ($1, $2, 'team', $3, $4, $5, $5, $5)
		`, targetUserID, roleID, teamID, actorID, now); err != nil {
			return err
		}
		if err := q.QueryRow(ctx, `
			SELECT ura.id, ura.user_id, p.email, ura.role_id, r.name, ura.team_id, ura.granted_by, ura.granted_at,
			       ura.revoked_at, ura.created_at, ura.updated_at
			FROM user_role_assignments ura
			JOIN roles r
			  ON r.id = ura.role_id
			JOIN profile p
			  ON p.id = ura.user_id
			WHERE ura.user_id = $1
			  AND ura.role_id = $2
			  AND ura.team_id = $3
			  AND ura.scope_type = 'team'
			  AND ura.revoked_at IS NULL
			ORDER BY ura.created_at DESC
			LIMIT 1
		`, targetUserID, roleID, teamID).Scan(
			&assignment.ID,
			&assignment.UserID,
			&assignmentEmail,
			&assignment.RoleID,
			&assignment.RoleName,
			&assignment.TeamID,
			&assignment.GrantedBy,
			&assignment.GrantedAt,
			&assignment.RevokedAt,
			&assignment.CreatedAt,
			&assignment.UpdatedAt,
		); err != nil {
			return err
		}
		return h.writeRBACAudit(ctx, q, &actorID, &targetUserID, &teamID, map[bool]string{true: "platform_team_role_assigned", false: "team_role_assigned"}[platform], nil, map[string]any{
			"assignment_id": assignment.ID.String(),
			"role_name":     roleName,
			"user_id":       targetUserID.String(),
			"team_id":       teamID.String(),
		}, map[string]any{"role_name": roleName})
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondErrorMsg(c, "not_found", "team, user, or role not found", http.StatusNotFound)
			return
		}
		if errors.Is(err, ErrConflict) {
			respondError(c, ErrConflict)
			return
		}
		if errors.Is(err, authz.ErrPermissionDenied) || errors.Is(err, authz.ErrScopeMismatch) {
			respondError(c, ErrForbidden)
			return
		}
		if errors.Is(err, errMembershipNotActive) {
			respondErrorMsg(c, "conflict", errMembershipNotActive.Error(), http.StatusConflict)
			return
		}
		log.Error().Err(err).Str("team_id", teamID.String()).Str("user_id", targetUserID.String()).Str("role", roleName).Msg("RBAC assign role failed")
		respondError(c, ErrInternal)
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"assignment_id": assignment.ID.String(),
		"user_id":       assignment.UserID.String(),
		"email":         assignmentEmail,
		"role_name":     assignment.RoleName,
		"scope_type":    "team",
		"team_id":       assignment.TeamID.String(),
		"granted_by":    uuidPGTypeString(assignment.GrantedBy),
		"granted_at":    assignment.GrantedAt,
		"revoked_at":    assignment.RevokedAt,
		"created_at":    assignment.CreatedAt,
		"updated_at":    assignment.UpdatedAt,
	})
}

func uuidPtrString(id *uuid.UUID) *string {
	if id == nil {
		return nil
	}
	s := id.String()
	return &s
}

func uuidPGTypeString(id pgtype.UUID) *string {
	if !id.Valid {
		return nil
	}
	s := uuid.UUID(id.Bytes).String()
	return &s
}

func (h *Handlers) revokeRole(c *gin.Context, platform bool) {
	var teamID uuid.UUID
	var err error
	if platform {
		teamID, err = internalTeamID(c)
	} else {
		teamID, err = customerTeamID(c)
	}
	if err != nil {
		return
	}
	actorID, err := requestActorID(c, platform)
	if err != nil {
		return
	}
	if platform {
		if err := h.requirePlatformAdminGoogleSession(c.Request.Context(), h.Pool, actorID); err != nil {
			if errors.Is(err, authz.ErrSessionNotEligible) || errors.Is(err, pgx.ErrNoRows) {
				respondError(c, ErrForbidden)
				return
			}
			log.Error().Err(err).Str("team_id", teamID.String()).Msg("RBAC revoke role session validation failed")
			respondError(c, ErrInternal)
			return
		}
	}
	permission := "roles:write"
	if platform {
		permission = "platform:team_roles:write"
	}
	if err := h.requireTeamPermission(c, actorID, teamID, permission, platform); err != nil {
		if errors.Is(err, authz.ErrPermissionDenied) || errors.Is(err, authz.ErrScopeMismatch) {
			respondError(c, ErrForbidden)
			return
		}
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("RBAC revoke role authorization failed")
		respondError(c, ErrInternal)
		return
	}

	assignmentID, err := parseUUIDParam(c, "assignment_id")
	if err != nil {
		return
	}

	ctx := c.Request.Context()
	err = h.withRBACMutation(ctx, teamID, func(q db.DBTX, svc *authz.Service) error {
		if err := lockTeamMutation(ctx, q, teamID); err != nil {
			return err
		}
		if err := requireTeamPermissionOnTx(ctx, svc, actorID, teamID, permission, platform); err != nil {
			return err
		}
		rec, err := loadAssignment(ctx, q, teamID, assignmentID)
		if err != nil {
			return err
		}
		if rec.RevokedAt != nil {
			return pgx.ErrNoRows
		}
		if rec.RoleName == "team_owner" {
			ok, err := svc.CanRevokeLastTeamOwner(ctx, teamID, rec.UserID)
			if err != nil {
				return err
			}
			if !ok {
				return ErrConflict
			}
		}
		now := time.Now().UTC()
		if _, err := q.Exec(ctx, `
			UPDATE user_role_assignments
			SET revoked_at = $2,
			    updated_at = $2
			WHERE id = $1
		`, rec.ID, now); err != nil {
			return err
		}
		eventType := "team_role_revoked"
		if platform {
			eventType = "platform_team_role_revoked"
		}
		return h.writeRBACAudit(ctx, q, &actorID, &rec.UserID, &teamID, eventType, map[string]any{
			"assignment_id": rec.ID.String(),
			"role_name":     rec.RoleName,
		}, map[string]any{
			"assignment_id": rec.ID.String(),
			"role_name":     rec.RoleName,
			"revoked_at":    now,
		}, nil)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondErrorMsg(c, "not_found", "role assignment not found", http.StatusNotFound)
			return
		}
		if errors.Is(err, ErrConflict) {
			respondError(c, ErrConflict)
			return
		}
		if errors.Is(err, authz.ErrPermissionDenied) || errors.Is(err, authz.ErrScopeMismatch) {
			respondError(c, ErrForbidden)
			return
		}
		log.Error().Err(err).Str("team_id", teamID.String()).Str("assignment_id", assignmentID.String()).Msg("RBAC revoke role failed")
		respondError(c, ErrInternal)
		return
	}

	c.Status(http.StatusNoContent)
}

func (h *Handlers) recoverTeam(c *gin.Context) {
	teamID, err := internalTeamID(c)
	if err != nil {
		return
	}
	actorID, err := requestActorID(c, true)
	if err != nil {
		return
	}
	if err := h.requirePlatformAdminGoogleSession(c.Request.Context(), h.Pool, actorID); err != nil {
		if errors.Is(err, authz.ErrSessionNotEligible) || errors.Is(err, pgx.ErrNoRows) {
			respondError(c, ErrForbidden)
			return
		}
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("RBAC recovery session validation failed")
		respondError(c, ErrInternal)
		return
	}
	svc := h.rbacService()
	if svc == nil {
		respondError(c, ErrInternal)
		return
	}
	for _, permission := range []string{"platform:team_users:write", "platform:team_roles:write", "platform:teams:read"} {
		if err := svc.RequirePlatformPermission(c.Request.Context(), actorID, permission); err != nil {
			if errors.Is(err, authz.ErrPermissionDenied) || errors.Is(err, authz.ErrScopeMismatch) {
				respondError(c, ErrForbidden)
				return
			}
			log.Error().Err(err).Str("team_id", teamID.String()).Msg("RBAC recovery authorization failed")
			respondError(c, ErrInternal)
			return
		}
	}

	var req platformRecoveryPayload
	if err := bindJSONStrict(c, &req); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	targetUserID, err := uuid.Parse(strings.TrimSpace(req.UserID))
	if err != nil {
		respondErrorMsg(c, "bad_request", "user_id is not a valid UUID", http.StatusBadRequest)
		return
	}

	ctx := c.Request.Context()
	var output struct {
		Recovered bool `json:"recovered"`
	}
	err = h.withRBACMutation(ctx, teamID, func(q db.DBTX, txSvc *authz.Service) error {
		if err := lockTeamMutation(ctx, q, teamID); err != nil {
			return err
		}
		for _, permission := range []string{"platform:team_users:write", "platform:team_roles:write", "platform:teams:read"} {
			if err := requireTeamPermissionOnTx(ctx, txSvc, actorID, teamID, permission, true); err != nil {
				return err
			}
		}
		if err := ensureTeamExists(ctx, q, teamID); err != nil {
			return err
		}
		if err := ensureProfileExists(ctx, q, targetUserID); err != nil {
			return err
		}
		owners, err := activeOwnerCount(ctx, q, teamID)
		if err != nil {
			return err
		}
		if owners > 0 {
			return ErrConflict
		}

		var priorMembership *membershipRecord
		if m, err := loadMembership(ctx, q, teamID, targetUserID); err == nil {
			priorMembership = &m
		}

		member, created, err := upsertMembership(ctx, q, teamID, targetUserID, "active")
		if err != nil {
			return err
		}
		roleID, err := lookupRoleID(ctx, q, "team_owner", "team")
		if err != nil {
			return err
		}
		active, err := activeAssignmentExists(ctx, q, teamID, targetUserID, roleID)
		if err != nil {
			return err
		}
		if !active {
			now := time.Now().UTC()
			if _, err := q.Exec(ctx, `
				INSERT INTO user_role_assignments (
					user_id, role_id, scope_type, team_id,
					granted_by, granted_at, created_at, updated_at
				)
				VALUES ($1, $2, 'team', $3, $4, $5, $5, $5)
			`, targetUserID, roleID, teamID, actorID, now); err != nil {
				return err
			}
			if err := h.writeRBACAudit(ctx, q, &actorID, &targetUserID, &teamID, "platform_team_role_assigned", nil, map[string]any{
				"role_name": "team_owner",
				"user_id":   targetUserID.String(),
				"team_id":   teamID.String(),
			}, map[string]any{"created": true}); err != nil {
				return err
			}
		}
		if err := h.writeRBACAudit(ctx, q, &actorID, &targetUserID, &teamID, "platform_team_member_added", func() any {
			if priorMembership == nil {
				return nil
			}
			return map[string]any{"status": priorMembership.Status}
		}(), map[string]any{
			"status":  "active",
			"user_id": targetUserID.String(),
			"team_id": teamID.String(),
		}, map[string]any{"created": created}); err != nil {
			return err
		}
		if err := h.writeRBACAudit(ctx, q, &actorID, &targetUserID, &teamID, "platform_team_recovered", map[string]any{
			"active_owner_count": owners,
		}, map[string]any{
			"user_id":       targetUserID.String(),
			"membership_id": member.ID.String(),
			"membership":    member.Status,
		}, map[string]any{"membership_created": created}); err != nil {
			return err
		}
		output.Recovered = true
		return nil
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondErrorMsg(c, "not_found", "team or user not found", http.StatusNotFound)
			return
		}
		if errors.Is(err, ErrConflict) {
			respondError(c, ErrConflict)
			return
		}
		if errors.Is(err, authz.ErrPermissionDenied) || errors.Is(err, authz.ErrScopeMismatch) {
			respondError(c, ErrForbidden)
			return
		}
		log.Error().Err(err).Str("team_id", teamID.String()).Str("user_id", targetUserID.String()).Msg("RBAC recover team failed")
		respondError(c, ErrInternal)
		return
	}

	c.JSON(http.StatusOK, output)
}

func (h *Handlers) ListTeamMembers(c *gin.Context)         { h.listMembers(c, false) }
func (h *Handlers) ListPlatformTeamMembers(c *gin.Context) { h.listMembers(c, true) }
func (h *Handlers) AddTeamMember(c *gin.Context)           { h.addMember(c, false) }
func (h *Handlers) AddPlatformTeamMember(c *gin.Context)   { h.addMember(c, true) }
func (h *Handlers) DeactivateTeamMember(c *gin.Context)    { h.deactivateMember(c, false) }
func (h *Handlers) DeactivatePlatformTeamMember(c *gin.Context) {
	h.deactivateMember(c, true)
}
func (h *Handlers) ListTeamRoleAssignments(c *gin.Context)         { h.listAssignments(c, false) }
func (h *Handlers) ListPlatformTeamRoleAssignments(c *gin.Context) { h.listAssignments(c, true) }
func (h *Handlers) AssignTeamRole(c *gin.Context)                  { h.assignRole(c, false) }
func (h *Handlers) AssignPlatformTeamRole(c *gin.Context)          { h.assignRole(c, true) }
func (h *Handlers) RevokeTeamRole(c *gin.Context)                  { h.revokeRole(c, false) }
func (h *Handlers) RevokePlatformTeamRole(c *gin.Context)          { h.revokeRole(c, true) }
func (h *Handlers) RecoverTeam(c *gin.Context)                     { h.recoverTeam(c) }

func (h *Handlers) auditRevokedRoleAssignments(ctx context.Context, q db.DBTX, actorID, targetID, teamID *uuid.UUID, platform bool, assignments []roleAssignmentRecord, revokedAt time.Time) error {
	if len(assignments) == 0 {
		return nil
	}
	eventType := "team_role_revoked"
	if platform {
		eventType = "platform_team_role_revoked"
	}
	for _, assignment := range assignments {
		if err := h.writeRBACAudit(ctx, q, actorID, targetID, teamID, eventType, map[string]any{
			"assignment_id": assignment.ID.String(),
			"role_name":     assignment.RoleName,
		}, map[string]any{
			"assignment_id": assignment.ID.String(),
			"role_name":     assignment.RoleName,
			"revoked_at":    revokedAt,
		}, map[string]any{
			"cascade": true,
		}); err != nil {
			return err
		}
	}
	return nil
}
