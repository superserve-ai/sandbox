package abuse

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/db"
)

type PolicyRecord struct {
	TeamID     uuid.UUID
	Trusted    bool
	Restricted bool
	ExpiresAt  *time.Time
}

// PolicyLoader streams only relevant teams. The complete projection is rebuilt
// in one database snapshot, so membership changes and expirations need no feed
// event and a lost cursor cannot permanently omit a restriction.
type PolicyLoader func(context.Context, func(PolicyRecord)) (ComputeMode, int64, error)

const policyCTE = `WITH owners AS (
    SELECT DISTINCT ura.team_id, ura.user_id
    FROM user_role_assignments ura
    JOIN roles r ON r.id=ura.role_id AND r.scope_type='team' AND r.name='team_owner'
    JOIN team_memberships tm ON tm.team_id=ura.team_id AND tm.user_id=ura.user_id AND tm.status='active'
    WHERE ura.scope_type='team' AND ura.revoked_at IS NULL %s
), verified AS (
    SELECT team_id FROM abuse_team_trust WHERE verified AND revoked_at IS NULL
), trusted_accounts AS (
    SELECT tm.user_id FROM team_memberships tm JOIN verified v ON v.team_id=tm.team_id WHERE tm.status='active' %s
    UNION %s
), trusted AS (
    SELECT team_id FROM verified
    UNION SELECT o.team_id FROM owners o JOIN trusted_accounts a ON a.user_id=o.user_id
), active AS (
    SELECT * FROM abuse_restrictions WHERE action IN ('create','resume') AND released_at IS NULL
      AND (expires_at IS NULL OR expires_at > statement_timestamp()) %s
), matches AS (
    SELECT subject_team_id AS team_id, expires_at FROM active WHERE subject_type='team'
    UNION ALL
    SELECT o.team_id, a.expires_at FROM active a JOIN owners o ON o.user_id=a.subject_user_id WHERE a.subject_type='user'
    UNION ALL
    SELECT o.team_id, a.expires_at FROM active a
      JOIN profile p ON a.subject_value=lower(split_part(p.email,'@',2))
      JOIN owners o ON o.user_id=p.id WHERE a.subject_type='domain'
), denies AS (
    SELECT team_id, CASE WHEN bool_or(expires_at IS NULL) THEN NULL ELSE max(expires_at) END AS expires_at
    FROM matches GROUP BY team_id
), settings AS (
    SELECT mode, (SELECT COALESCE(max(id),0) FROM abuse_state_changes) AS generation
    FROM abuse_runtime_settings WHERE singleton
), relevant AS (
    SELECT team_id FROM trusted UNION SELECT team_id FROM denies
)
`

// Provider identity_data is written by the auth provider. raw_user_meta_data
// and profile email/provider strings are deliberately not identity authority.
const corporateAccounts = `SELECT i.user_id FROM auth.identities i
    JOIN abuse_trusted_identities a ON a.auth_provider=i.provider
      AND a.domain=lower(i.identity_data->>'hd') AND a.revoked_at IS NULL
    WHERE i.provider='google' AND i.identity_data->>'email_verified'='true'
      AND lower(split_part(i.identity_data->>'email','@',2))=a.domain`

func policyPrefix(ctx context.Context, q db.DBTX) (string, error) {
	return policyPrefixForTeam(ctx, q, false)
}

func policyPrefixForTeam(ctx context.Context, q db.DBTX, scoped bool) (string, error) {
	var hasIdentity bool
	if err := q.QueryRow(ctx, `SELECT to_regclass('auth.identities') IS NOT NULL`).Scan(&hasIdentity); err != nil {
		return "", err
	}
	accounts := `SELECT NULL::uuid WHERE false`
	if hasIdentity {
		accounts = corporateAccounts
	}
	var owners, members, restrictions string
	if scoped {
		// Per-incident and pre-pause checks must not rebuild cell-wide ownership.
		// The complete background loader deliberately leaves these clauses empty.
		owners = `AND ura.team_id=$1`
		members = `AND tm.user_id IN (SELECT user_id FROM owners)`
		if hasIdentity {
			accounts += ` AND i.user_id IN (SELECT user_id FROM owners)`
		}
		restrictions = `AND (
   (subject_type='team' AND subject_team_id=$1) OR
   (subject_type='user' AND subject_user_id IN (SELECT user_id FROM owners)) OR
   (subject_type='domain' AND subject_value IN (
    SELECT lower(split_part(p.email,'@',2)) FROM profile p JOIN owners o ON o.user_id=p.id
   ))
  )`
	}
	return fmt.Sprintf(policyCTE, owners, members, accounts, restrictions), nil
}

func DatabasePolicyLoader(q db.DBTX) PolicyLoader {
	return func(ctx context.Context, emit func(PolicyRecord)) (ComputeMode, int64, error) {
		prefix, err := policyPrefix(ctx, q)
		if err != nil {
			return ModeOff, 0, err
		}
		rows, err := q.Query(ctx, prefix+`SELECT s.mode,s.generation,r.team_id,
            EXISTS(SELECT 1 FROM trusted t WHERE t.team_id=r.team_id),
            d.team_id IS NOT NULL,d.expires_at
            FROM settings s LEFT JOIN relevant r ON true LEFT JOIN denies d ON d.team_id=r.team_id
            ORDER BY r.team_id`)
		if err != nil {
			return ModeOff, 0, err
		}
		defer rows.Close()
		var mode ComputeMode
		var generation int64
		seen := false
		for rows.Next() {
			var id *uuid.UUID
			var record PolicyRecord
			if err := rows.Scan(&mode, &generation, &id, &record.Trusted, &record.Restricted, &record.ExpiresAt); err != nil {
				return ModeOff, 0, err
			}
			seen = true
			if id != nil {
				record.TeamID = *id
				emit(record)
			}
		}
		if err := rows.Err(); err != nil {
			return ModeOff, 0, err
		}
		if !seen || !ValidComputeMode(mode) {
			return ModeOff, 0, fmt.Errorf("authoritative abuse mode unavailable")
		}
		return mode, generation, nil
	}
}

func ValidComputeMode(mode ComputeMode) bool {
	return mode == ModeOff || mode == ModeObserve || mode == ModeEnforce
}

// ResolveTeamPolicy is a background-only current-state check. It must not be
// called by sandbox admission or networking packet evaluation.
func ResolveTeamPolicy(ctx context.Context, q db.DBTX, team uuid.UUID) (TeamPolicy, error) {
	policy := TeamPolicy{TeamID: team}
	prefix, err := policyPrefixForTeam(ctx, q, true)
	if err != nil {
		return policy, err
	}
	err = q.QueryRow(ctx, prefix+`SELECT s.mode,s.generation,
        EXISTS(SELECT 1 FROM trusted WHERE team_id=$1),
        EXISTS(SELECT 1 FROM denies WHERE team_id=$1)
        FROM settings s JOIN team t ON t.id=$1`, team).Scan(&policy.Mode, &policy.Generation, &policy.Trusted, &policy.Restricted)
	if err == pgx.ErrNoRows {
		return policy, nil
	}
	if err != nil {
		return policy, err
	}
	if !ValidComputeMode(policy.Mode) {
		return policy, fmt.Errorf("invalid authoritative abuse mode")
	}
	policy.Known = true
	if policy.Trusted {
		policy.Restricted = false
	}
	return policy, nil
}
