package api

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type teamCreationResult struct {
	ID      uuid.UUID `json:"id"`
	Name    string    `json:"name"`
	Region  string    `json:"region"`
	Outcome string    `json:"-"`
}

var errTeamCreationConflict = errors.New("team creation request parameters changed")
var errTeamCreationDeleted = errors.New("created team was deleted")
var errTeamCreationIdentityUnavailable = errors.New("trusted promotion identity unavailable")

const teamCreationResultSQL = `
SELECT r.name, r.region, CASE WHEN r.deleted_at IS NULL THEN t.id END
FROM team_creation_requests r
LEFT JOIN team t ON t.id = r.team_id
WHERE r.actor_id = $1 AND r.cell = $2 AND r.request_id = $3`

// The result row has no team foreign key: deletion leaves a durable tombstone.
func readTeamCreationResult(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, actor uuid.UUID, input teamCreationInput) (teamCreationResult, error) {
	var result teamCreationResult
	var teamID *uuid.UUID
	err := q.QueryRow(ctx, teamCreationResultSQL, actor, input.Region, input.RequestID).Scan(&result.Name, &result.Region, &teamID)
	if err != nil {
		return result, err
	}
	if result.Name != input.Name || result.Region != input.Region {
		return result, errTeamCreationConflict
	}
	if teamID == nil {
		return result, errTeamCreationDeleted
	}
	result.ID = *teamID
	return result, nil
}

// The advisory lock serializes one actor/cell/request across API replicas.
// All provisioning writes and the immutable result are in the same transaction.
func createTeamCreationResult(ctx context.Context, pool *pgxpool.Pool, actor uuid.UUID, input teamCreationInput, identity *teamCreationIdentity, policyMode string) (teamCreationResult, error) {
	var result teamCreationResult
	tx, err := pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer tx.Rollback(ctx)
	lockKey := actor.String() + ":" + input.Region + ":" + input.RequestID
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey); err != nil {
		return result, err
	}
	result, err = readTeamCreationResult(ctx, tx, actor, input)
	if err == nil || errors.Is(err, errTeamCreationConflict) || errors.Is(err, errTeamCreationDeleted) {
		return result, err
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}

	if identity == nil {
		return result, errTeamCreationIdentityUnavailable
	}
	authUpdatedAt, err := parseTeamCreationIdentityTime(identity.AuthUpdatedAt)
	if err != nil {
		return result, errTeamCreationIdentityUnavailable
	}
	observedAt, err := parseTeamCreationIdentityTime(identity.ObservedAt)
	if err != nil {
		return result, errTeamCreationIdentityUnavailable
	}
	// Match the authority's gate -> actor lock order even while enforcement is off.
	var canonicalEnabled bool
	if err = tx.QueryRow(ctx, `SELECT canonical_promotion_identity_enabled()`).Scan(&canonicalEnabled); err != nil {
		return result, err
	}
	var evidenceOutcome string
	var evidenceVersion uuid.UUID
	err = tx.QueryRow(ctx, `SELECT outcome, evidence_version FROM upsert_profile_with_promotion_identity($1,$2,$3,$4,$5)`,
		actor, identity.Email, identity.EmailVerified, authUpdatedAt, observedAt).Scan(&evidenceOutcome, &evidenceVersion)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "22023" {
			return result, errTeamCreationIdentityUnavailable
		}
		return result, err
	}
	if (evidenceOutcome != "applied" && evidenceOutcome != "replayed") || evidenceVersion == uuid.Nil {
		return result, errTeamCreationIdentityUnavailable
	}

	if err = tx.QueryRow(ctx, `SELECT id FROM create_team_with_signup_trial($1, $2, $3, $4)`, input.Name, actor, input.Region, policyMode).Scan(&result.ID); err != nil {
		return result, err
	}
	// Require the authority's explicit outcome in both expansion and enforcement modes.
	if err = tx.QueryRow(ctx, `SELECT outcome FROM team_signup_promotion_outcome WHERE team_id=$1 AND user_id=$2`, result.ID, actor).Scan(&result.Outcome); err != nil {
		return result, err
	}
	if result.Outcome != "granted" && result.Outcome != "already_claimed" && result.Outcome != "promotion_ineligible" {
		return result, errors.New("unsupported promotion outcome")
	}
	result.Name, result.Region = input.Name, input.Region
	if _, err = tx.Exec(ctx, `INSERT INTO team_member(team_id, profile_id, role) VALUES($1, $2, 'owner')`, result.ID, actor); err != nil {
		return result, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO team_memberships(team_id, user_id, status) VALUES($1, $2, 'active')`, result.ID, actor); err != nil {
		return result, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO user_role_assignments(user_id, role_id, scope_type, team_id, granted_by)
		SELECT $1, id, 'team', $2, $1 FROM roles WHERE name = 'team_owner' AND scope_type = 'team'`, actor, result.ID); err != nil {
		return result, err
	}
	var ownerCount int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM user_role_assignments WHERE user_id=$1 AND team_id=$2 AND revoked_at IS NULL`, actor, result.ID).Scan(&ownerCount); err != nil || ownerCount != 1 {
		if err == nil {
			err = errors.New("team owner role unavailable")
		}
		return result, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO team_creation_requests(actor_id, cell, request_id, name, region, team_id)
		VALUES($1, $2, $3, $4, $5, $6)`, actor, input.Region, input.RequestID, result.Name, result.Region, result.ID); err != nil {
		return result, err
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return result, nil
}
