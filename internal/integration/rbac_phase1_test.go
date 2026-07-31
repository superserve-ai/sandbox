//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestRbacSeedData(t *testing.T) {
	ctx := context.Background()

	wantRoles := map[string]string{
		"platform_admin": "platform",
		"team_owner":     "team",
		"team_admin":     "team",
		"billing_admin":  "team",
		"user_admin":     "team",
		"viewer":         "team",
	}
	gotRoles := make(map[string]string)
	rows, err := testPool.Query(ctx, `SELECT name, scope_type FROM roles ORDER BY name`)
	if err != nil {
		t.Fatalf("query roles: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name, scope string
		if err := rows.Scan(&name, &scope); err != nil {
			t.Fatalf("scan role: %v", err)
		}
		gotRoles[name] = scope
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("roles rows: %v", err)
	}
	if len(gotRoles) != len(wantRoles) {
		t.Fatalf("roles count = %d, want %d", len(gotRoles), len(wantRoles))
	}
	for name, wantScope := range wantRoles {
		if gotRoles[name] != wantScope {
			t.Fatalf("role %s scope = %q, want %q", name, gotRoles[name], wantScope)
		}
	}

	wantPerms := []string{
		"billing:read",
		"billing:write",
		"users:read",
		"users:write",
		"roles:read",
		"roles:write",
		"settings:read",
		"settings:write",
		"audit_logs:read",
		"platform:teams:read",
		"platform:team_users:write",
		"platform:team_roles:write",
		"platform:billing:read",
		"platform:billing:write",
	}
	var gotPerms []string
	rows, err = testPool.Query(ctx, `SELECT name FROM permissions ORDER BY name`)
	if err != nil {
		t.Fatalf("query permissions: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan permission: %v", err)
		}
		gotPerms = append(gotPerms, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("permissions rows: %v", err)
	}
	if len(gotPerms) != len(wantPerms) {
		t.Fatalf("permissions count = %d, want %d", len(gotPerms), len(wantPerms))
	}
	sort.Strings(gotPerms)
	sort.Strings(wantPerms)
	for i := range wantPerms {
		if gotPerms[i] != wantPerms[i] {
			t.Fatalf("permission[%d] = %q, want %q", i, gotPerms[i], wantPerms[i])
		}
	}

	expectedMappings := map[string][]string{
		"platform_admin": {
			"platform:teams:read",
			"platform:team_users:write",
			"platform:team_roles:write",
			"platform:billing:read",
			"platform:billing:write",
			"billing:read",
			"billing:write",
			"users:read",
			"users:write",
			"roles:read",
			"roles:write",
			"settings:read",
			"settings:write",
			"audit_logs:read",
		},
		"team_owner": {
			"billing:read",
			"billing:write",
			"users:read",
			"users:write",
			"roles:read",
			"roles:write",
			"settings:read",
			"settings:write",
			"audit_logs:read",
		},
		"team_admin": {
			"users:read",
			"users:write",
			"roles:read",
			"settings:read",
			"settings:write",
			"billing:read",
		},
		"billing_admin": {
			"billing:read",
			"billing:write",
		},
		"user_admin": {
			"users:read",
			"users:write",
			"roles:read",
		},
		"viewer": {
			"billing:read",
			"users:read",
			"settings:read",
		},
	}
	for roleName, want := range expectedMappings {
		got, err := rolePermissionsFor(t, ctx, roleName)
		if err != nil {
			t.Fatalf("role permissions for %s: %v", roleName, err)
		}
		if len(got) != len(want) {
			t.Fatalf("role %s mapping count = %d, want %d", roleName, len(got), len(want))
		}
		sort.Strings(got)
		sort.Strings(want)
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("role %s permission[%d] = %q, want %q", roleName, i, got[i], want[i])
			}
		}
	}
}

func TestRbacAssignmentConstraints(t *testing.T) {
	ctx := context.Background()
	teamID, userID := seedRBACUser(t)
	platformRoleID := mustRoleID(t, ctx, "platform_admin")
	teamOwnerRoleID := mustRoleID(t, ctx, "team_owner")

	t.Run("platform role rejects team_id", func(t *testing.T) {
		_, err := testPool.Exec(ctx, `
			INSERT INTO user_role_assignments (user_id, role_id, scope_type, team_id)
			VALUES ($1, $2, 'platform', $3)
		`, userID, platformRoleID, teamID)
		if err == nil {
			t.Fatal("expected platform assignment with team_id to fail")
		}
	})

	t.Run("platform role cannot be assigned in team scope", func(t *testing.T) {
		_, err := testPool.Exec(ctx, `
			INSERT INTO user_role_assignments (user_id, role_id, scope_type, team_id)
			VALUES ($1, $2, 'team', $3)
		`, userID, platformRoleID, teamID)
		if err == nil {
			t.Fatal("expected platform role in team scope to fail")
		}
	})

	t.Run("team role cannot be assigned in platform scope", func(t *testing.T) {
		_, err := testPool.Exec(ctx, `
			INSERT INTO user_role_assignments (user_id, role_id, scope_type, team_id)
			VALUES ($1, $2, 'platform', NULL)
		`, userID, teamOwnerRoleID)
		if err == nil {
			t.Fatal("expected team role in platform scope to fail")
		}
	})

	t.Run("team role requires team_id", func(t *testing.T) {
		_, err := testPool.Exec(ctx, `
			INSERT INTO user_role_assignments (user_id, role_id, scope_type, team_id)
			VALUES ($1, $2, 'team', NULL)
		`, userID, teamOwnerRoleID)
		if err == nil {
			t.Fatal("expected team assignment without team_id to fail")
		}
	})

	t.Run("user can have active memberships in multiple teams", func(t *testing.T) {
		otherTeamID := mustCreateTeam(t, ctx, "rbac-second-team-"+uuid.NewString()[:8])
		_, err := testPool.Exec(ctx, `
			INSERT INTO team_memberships (team_id, user_id, status)
			VALUES ($1, $2, 'active')
		`, otherTeamID, userID)
		if err != nil {
			t.Fatalf("insert second active membership: %v", err)
		}
	})

	t.Run("duplicate active membership in same team is blocked", func(t *testing.T) {
		_, err := testPool.Exec(ctx, `
			INSERT INTO team_memberships (team_id, user_id, status)
			VALUES ($1, $2, 'active')
		`, teamID, userID)
		if err == nil {
			t.Fatal("expected duplicate active membership for same team and user to fail")
		}
	})

	t.Run("active team assignment requires active membership", func(t *testing.T) {
		otherUser := seedRBACProfile(t)
		_, err := testPool.Exec(ctx, `
			INSERT INTO user_role_assignments (user_id, role_id, scope_type, team_id)
			VALUES ($1, $2, 'team', $3)
		`, otherUser, teamOwnerRoleID, teamID)
		if err == nil {
			t.Fatal("expected team role assignment without active membership to fail")
		}
	})

	t.Run("duplicate platform assignment is blocked", func(t *testing.T) {
		_, err := testPool.Exec(ctx, `
			INSERT INTO user_role_assignments (user_id, role_id, scope_type, team_id)
			VALUES ($1, $2, 'platform', NULL)
		`, userID, platformRoleID)
		if err != nil {
			t.Fatalf("insert active platform assignment: %v", err)
		}
		_, err = testPool.Exec(ctx, `
			INSERT INTO user_role_assignments (user_id, role_id, scope_type, team_id)
			VALUES ($1, $2, 'platform', NULL)
		`, userID, platformRoleID)
		if err == nil {
			t.Fatal("expected duplicate active platform assignment to fail")
		}
	})

	t.Run("duplicate active assignment is blocked", func(t *testing.T) {
		_, err := testPool.Exec(ctx, `
			INSERT INTO user_role_assignments (user_id, role_id, scope_type, team_id)
			VALUES ($1, $2, 'team', $3)
		`, userID, teamOwnerRoleID, teamID)
		if err != nil {
			t.Fatalf("insert active assignment: %v", err)
		}
		_, err = testPool.Exec(ctx, `
			INSERT INTO user_role_assignments (user_id, role_id, scope_type, team_id)
			VALUES ($1, $2, 'team', $3)
		`, userID, teamOwnerRoleID, teamID)
		if err == nil {
			t.Fatal("expected duplicate active assignment to fail")
		}
	})

	t.Run("revoked assignment does not block new active row", func(t *testing.T) {
		otherTeamID := mustCreateTeam(t, ctx, "rbac-regrant-"+uuid.NewString()[:8])
		otherUser := seedRBACProfile(t)
		seedMembership(t, ctx, otherTeamID, otherUser)
		otherRoleID := mustRoleID(t, ctx, "team_admin")
		_, err := testPool.Exec(ctx, `
			INSERT INTO user_role_assignments (
				user_id, role_id, scope_type, team_id, revoked_at
			)
			VALUES ($1, $2, 'team', $3, now())
		`, otherUser, otherRoleID, otherTeamID)
		if err != nil {
			t.Fatalf("insert revoked assignment: %v", err)
		}
		_, err = testPool.Exec(ctx, `
			INSERT INTO user_role_assignments (user_id, role_id, scope_type, team_id)
			VALUES ($1, $2, 'team', $3)
		`, otherUser, otherRoleID, otherTeamID)
		if err != nil {
			t.Fatalf("insert active assignment after revoked history: %v", err)
		}
	})

	t.Run("membership deactivation revokes team assignments", func(t *testing.T) {
		otherTeamID := mustCreateTeam(t, ctx, "rbac-deactivate-"+uuid.NewString()[:8])
		otherUser := seedRBACProfile(t)
		seedMembership(t, ctx, otherTeamID, otherUser)
		seedTeamRoleAssignment(t, ctx, otherUser, teamOwnerRoleID, otherTeamID)

		if _, err := testPool.Exec(ctx, `
			UPDATE team_memberships
			SET status = 'inactive'
			WHERE team_id = $1 AND user_id = $2
		`, otherTeamID, otherUser); err != nil {
			t.Fatalf("deactivate membership: %v", err)
		}

		var revokedAt pgtype.Timestamptz
		if err := testPool.QueryRow(ctx, `
			SELECT revoked_at
			FROM user_role_assignments
			WHERE team_id = $1 AND user_id = $2 AND role_id = $3
		`, otherTeamID, otherUser, teamOwnerRoleID).Scan(&revokedAt); err != nil {
			t.Fatalf("read revoked assignment: %v", err)
		}
		if !revokedAt.Valid {
			t.Fatal("expected role assignment to be revoked")
		}
	})

	t.Run("membership invited transition revokes team assignments", func(t *testing.T) {
		otherTeamID := mustCreateTeam(t, ctx, "rbac-invite-transition-"+uuid.NewString()[:8])
		otherUser := seedRBACProfile(t)
		seedMembership(t, ctx, otherTeamID, otherUser)
		seedTeamRoleAssignment(t, ctx, otherUser, teamOwnerRoleID, otherTeamID)

		if _, err := testPool.Exec(ctx, `
			UPDATE team_memberships
			SET status = 'invited'
			WHERE team_id = $1 AND user_id = $2
		`, otherTeamID, otherUser); err != nil {
			t.Fatalf("move membership to invited: %v", err)
		}

		var revokedAt pgtype.Timestamptz
		if err := testPool.QueryRow(ctx, `
			SELECT revoked_at
			FROM user_role_assignments
			WHERE team_id = $1 AND user_id = $2 AND role_id = $3
		`, otherTeamID, otherUser, teamOwnerRoleID).Scan(&revokedAt); err != nil {
			t.Fatalf("read revoked assignment: %v", err)
		}
		if !revokedAt.Valid {
			t.Fatal("expected role assignment to be revoked after membership moved to invited")
		}
	})

	t.Run("membership delete revokes team assignments", func(t *testing.T) {
		otherTeamID := mustCreateTeam(t, ctx, "rbac-delete-membership-"+uuid.NewString()[:8])
		otherUser := seedRBACProfile(t)
		seedMembership(t, ctx, otherTeamID, otherUser)
		seedTeamRoleAssignment(t, ctx, otherUser, teamOwnerRoleID, otherTeamID)

		if _, err := testPool.Exec(ctx, `
			DELETE FROM team_memberships
			WHERE team_id = $1 AND user_id = $2
		`, otherTeamID, otherUser); err != nil {
			t.Fatalf("delete membership: %v", err)
		}

		var revokedAt pgtype.Timestamptz
		if err := testPool.QueryRow(ctx, `
			SELECT revoked_at
			FROM user_role_assignments
			WHERE team_id = $1 AND user_id = $2 AND role_id = $3
		`, otherTeamID, otherUser, teamOwnerRoleID).Scan(&revokedAt); err != nil {
			t.Fatalf("read revoked assignment: %v", err)
		}
		if !revokedAt.Valid {
			t.Fatal("expected role assignment to be revoked after membership delete")
		}
	})

	t.Run("membership identity updates are rejected", func(t *testing.T) {
		otherTeamID := mustCreateTeam(t, ctx, "rbac-update-membership-"+uuid.NewString()[:8])
		otherUser := seedRBACProfile(t)
		seedMembership(t, ctx, otherTeamID, otherUser)

		newTeamID := mustCreateTeam(t, ctx, "rbac-update-membership-target-"+uuid.NewString()[:8])
		_, err := testPool.Exec(ctx, `
			UPDATE team_memberships
			SET team_id = $1
			WHERE team_id = $2 AND user_id = $3
		`, newTeamID, otherTeamID, otherUser)
		if err == nil {
			t.Fatal("expected membership team_id update to fail")
		}

		replacementUser := seedRBACProfile(t)
		_, err = testPool.Exec(ctx, `
			UPDATE team_memberships
			SET user_id = $1
			WHERE team_id = $2 AND user_id = $3
		`, replacementUser, otherTeamID, otherUser)
		if err == nil {
			t.Fatal("expected membership user_id update to fail")
		}
	})
}

func TestRbacDeleteSemantics(t *testing.T) {
	ctx := context.Background()

	t.Run("profile delete blocked by membership", func(t *testing.T) {
		teamID := mustCreateTeam(t, ctx, "rbac-del-mem-"+uuid.NewString()[:8])
		userID := seedRBACProfile(t)
		seedMembership(t, ctx, teamID, userID)

		_, err := testPool.Exec(ctx, `DELETE FROM profile WHERE id = $1`, userID)
		assertFKViolation(t, err)
	})

	t.Run("team delete blocked by membership", func(t *testing.T) {
		teamID := mustCreateTeam(t, ctx, "rbac-del-team-mem-"+uuid.NewString()[:8])
		userID := seedRBACProfile(t)
		seedMembership(t, ctx, teamID, userID)

		_, err := testPool.Exec(ctx, `DELETE FROM team WHERE id = $1`, teamID)
		assertFKViolation(t, err)
	})

	t.Run("profile delete blocked by role assignment", func(t *testing.T) {
		teamID := mustCreateTeam(t, ctx, "rbac-del-role-"+uuid.NewString()[:8])
		userID := seedRBACProfile(t)
		seedMembership(t, ctx, teamID, userID)
		roleID := mustRoleID(t, ctx, "team_owner")
		seedTeamRoleAssignment(t, ctx, userID, roleID, teamID)

		_, err := testPool.Exec(ctx, `DELETE FROM profile WHERE id = $1`, userID)
		assertFKViolation(t, err)
	})

	t.Run("team delete blocked by role assignment", func(t *testing.T) {
		teamID := mustCreateTeam(t, ctx, "rbac-del-team-role-"+uuid.NewString()[:8])
		userID := seedRBACProfile(t)
		seedMembership(t, ctx, teamID, userID)
		roleID := mustRoleID(t, ctx, "team_owner")
		seedTeamRoleAssignment(t, ctx, userID, roleID, teamID)

		_, err := testPool.Exec(ctx, `DELETE FROM team WHERE id = $1`, teamID)
		assertFKViolation(t, err)
	})

	t.Run("role delete blocked by role assignment history", func(t *testing.T) {
		teamID := mustCreateTeam(t, ctx, "rbac-del-role-history-"+uuid.NewString()[:8])
		userID := seedRBACProfile(t)
		seedMembership(t, ctx, teamID, userID)
		roleID := mustRoleID(t, ctx, "viewer")
		seedTeamRoleAssignment(t, ctx, userID, roleID, teamID)

		_, err := testPool.Exec(ctx, `DELETE FROM roles WHERE id = $1`, roleID)
		assertFKViolation(t, err)
	})
}

func TestRbacBackfill(t *testing.T) {
	ctx := context.Background()

	oneUserTeam := mustCreateTeam(t, ctx, "rbac-single-"+uuid.NewString()[:8])
	oneUser := seedRBACProfile(t)
	seedLegacyMembership(t, ctx, oneUserTeam, oneUser, "member")

	soleAdminTeam := mustCreateTeam(t, ctx, "rbac-sole-admin-"+uuid.NewString()[:8])
	soleAdmin := seedRBACProfile(t)
	seedLegacyMembership(t, ctx, soleAdminTeam, soleAdmin, "admin")

	ambiguousTeam := mustCreateTeam(t, ctx, "rbac-multi-"+uuid.NewString()[:8])
	ambiguousA := seedRBACProfile(t)
	ambiguousB := seedRBACProfile(t)
	seedLegacyMembership(t, ctx, ambiguousTeam, ambiguousA, "member")
	seedLegacyMembership(t, ctx, ambiguousTeam, ambiguousB, "member")

	multiTeamUser := seedRBACProfile(t)
	multiTeamA := mustCreateTeam(t, ctx, "rbac-multi-user-a-"+uuid.NewString()[:8])
	multiTeamB := mustCreateTeam(t, ctx, "rbac-multi-user-b-"+uuid.NewString()[:8])
	seedLegacyMembership(t, ctx, multiTeamA, multiTeamUser, "member")
	seedLegacyMembership(t, ctx, multiTeamB, multiTeamUser, "member")

	runRBACBackfill(t, ctx)

	assertActiveMembership(t, ctx, oneUserTeam, oneUser)
	assertRoleAssignment(t, ctx, oneUserTeam, oneUser, "team_owner")

	assertActiveMembership(t, ctx, soleAdminTeam, soleAdmin)
	assertRoleAssignment(t, ctx, soleAdminTeam, soleAdmin, "team_owner")

	assertActiveMembership(t, ctx, ambiguousTeam, ambiguousA)
	assertActiveMembership(t, ctx, ambiguousTeam, ambiguousB)
	assertActiveOwnerCount(t, ctx, ambiguousTeam, 1)

	assertActiveMembership(t, ctx, multiTeamA, multiTeamUser)
	assertActiveMembership(t, ctx, multiTeamB, multiTeamUser)
	assertRoleAssignment(t, ctx, multiTeamA, multiTeamUser, "team_owner")
	assertRoleAssignment(t, ctx, multiTeamB, multiTeamUser, "team_owner")
}

func TestAuditLogAcceptsEvents(t *testing.T) {
	ctx := context.Background()
	teamID := uuid.New()
	actorID := seedRBACProfile(t)
	targetID := seedRBACProfile(t)

	if _, err := testPool.Exec(ctx, `
		INSERT INTO audit_logs (
			actor_user_id, target_user_id, team_id, event_type,
			old_value, new_value, metadata
		)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::jsonb)
	`, actorID, targetID, teamID, "role_assigned", `{"role":"viewer"}`, `{"role":"team_owner"}`, `{"source":"test"}`); err != nil {
		t.Fatalf("insert audit log: %v", err)
	}

	var got struct {
		ID        int64
		ActorID   pgtype.UUID
		TargetID  pgtype.UUID
		TeamID    pgtype.UUID
		EventType string
		OldValue  []byte
		NewValue  []byte
		Metadata  []byte
	}
	if err := testPool.QueryRow(ctx, `
		SELECT id, actor_user_id, target_user_id, team_id, event_type, old_value, new_value, metadata
		FROM audit_logs
		WHERE event_type = 'role_assigned'
		ORDER BY created_at DESC
		LIMIT 1
	`).Scan(&got.ID, &got.ActorID, &got.TargetID, &got.TeamID, &got.EventType, &got.OldValue, &got.NewValue, &got.Metadata); err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if !got.ActorID.Valid || got.ActorID.Bytes != actorID {
		t.Fatalf("actor_user_id = %v, want %v", got.ActorID, actorID)
	}
	if !got.TargetID.Valid || got.TargetID.Bytes != targetID {
		t.Fatalf("target_user_id = %v, want %v", got.TargetID, targetID)
	}
	if !got.TeamID.Valid || got.TeamID.Bytes != teamID {
		t.Fatalf("team_id = %v, want %v", got.TeamID, teamID)
	}
	if got.EventType != "role_assigned" {
		t.Fatalf("event_type = %q, want role_assigned", got.EventType)
	}

	if _, err := testPool.Exec(ctx, `
		UPDATE audit_logs
		SET event_type = 'tampered'
		WHERE id = $1
	`, got.ID); err == nil {
		t.Fatal("expected audit log update to fail")
	}

	if _, err := testPool.Exec(ctx, `
		DELETE FROM audit_logs
		WHERE id = $1
	`, got.ID); err == nil {
		t.Fatal("expected audit log delete to fail")
	}
}

func rolePermissionsFor(t *testing.T, ctx context.Context, roleName string) ([]string, error) {
	t.Helper()
	rows, err := testPool.Query(ctx, `
		SELECT p.name
		FROM role_permissions rp
		JOIN roles r ON r.id = rp.role_id
		JOIN permissions p ON p.id = rp.permission_id
		WHERE r.name = $1
		ORDER BY p.name
	`, roleName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		got = append(got, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return got, nil
}

func mustRoleID(t *testing.T, ctx context.Context, roleName string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(ctx, `SELECT id FROM roles WHERE name = $1`, roleName).Scan(&id); err != nil {
		t.Fatalf("lookup role %s: %v", roleName, err)
	}
	return id
}

func mustCreateTeam(t *testing.T, ctx context.Context, name string) uuid.UUID {
	t.Helper()
	team, err := testQueries.CreateTeam(ctx, name)
	if err != nil {
		t.Fatalf("create team %s: %v", name, err)
	}
	return team.ID
}

func seedRBACProfile(t *testing.T) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	id := uuid.New()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO profile (id, email)
		VALUES ($1, $2)
	`, id, fmt.Sprintf("user-%s@example.com", id.String()[:8])); err != nil {
		t.Fatalf("insert profile: %v", err)
	}
	return id
}

func seedRBACUser(t *testing.T) (uuid.UUID, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	teamID := mustCreateTeam(t, ctx, "rbac-constraints-"+uuid.NewString()[:8])
	userID := seedRBACProfile(t)
	seedMembership(t, ctx, teamID, userID)
	return teamID, userID
}

func seedLegacyMembership(t *testing.T, ctx context.Context, teamID, userID uuid.UUID, role string) {
	t.Helper()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_member (team_id, profile_id, role)
		VALUES ($1, $2, $3)
	`, teamID, userID, role); err != nil {
		t.Fatalf("insert legacy team_member: %v", err)
	}
}

func seedMembership(t *testing.T, ctx context.Context, teamID, userID uuid.UUID) {
	t.Helper()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_memberships (team_id, user_id, status)
		VALUES ($1, $2, 'active')
	`, teamID, userID); err != nil {
		t.Fatalf("insert team_memberships: %v", err)
	}
}

func seedTeamRoleAssignment(t *testing.T, ctx context.Context, userID, roleID, teamID uuid.UUID) {
	t.Helper()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO user_role_assignments (user_id, role_id, scope_type, team_id)
		VALUES ($1, $2, 'team', $3)
	`, userID, roleID, teamID); err != nil {
		t.Fatalf("insert user_role_assignments: %v", err)
	}
}

func runRBACBackfill(t *testing.T, ctx context.Context) {
	t.Helper()
	_, err := testPool.Exec(ctx, `
		INSERT INTO team_memberships (team_id, user_id, status, created_at, updated_at)
		SELECT
			tm.team_id,
			tm.profile_id,
			'active',
			COALESCE(tm.joined_at, now()),
			COALESCE(tm.joined_at, now())
		FROM team_member tm
		WHERE NOT EXISTS (
			SELECT 1
			FROM team_memberships m
			WHERE m.team_id = tm.team_id
			  AND m.user_id = tm.profile_id
			  AND m.status = 'active'
		);

		WITH legacy_memberships AS (
			SELECT
				tm.team_id,
				tm.profile_id AS user_id,
				COALESCE(tm.joined_at, now()) AS created_at,
				LOWER(COALESCE(tm.role, '')) AS legacy_role,
				BOOL_OR(LOWER(COALESCE(tm.role, '')) IN ('owner', 'team_owner'))
					OVER (PARTITION BY tm.team_id) AS has_explicit_owner,
				ROW_NUMBER() OVER (
					PARTITION BY tm.team_id
					ORDER BY COALESCE(tm.joined_at, 'infinity'::timestamptz), tm.profile_id
				) AS owner_rank
			FROM team_member tm
		)
		INSERT INTO user_role_assignments (
			user_id, role_id, scope_type, team_id,
			granted_by, granted_at, revoked_at, created_at, updated_at
		)
		SELECT
			lm.user_id,
			r.id,
			'team',
			lm.team_id,
			NULL,
			lm.created_at,
			NULL,
			lm.created_at,
			lm.created_at
		FROM legacy_memberships lm
		JOIN roles r
		  ON r.scope_type = 'team'
		 AND r.name = CASE
			WHEN lm.legacy_role IN ('owner', 'team_owner') THEN 'team_owner'
			WHEN NOT lm.has_explicit_owner AND lm.owner_rank = 1 THEN 'team_owner'
			WHEN lm.legacy_role IN ('admin', 'team_admin') THEN 'team_admin'
			ELSE 'viewer'
		 END
		WHERE NOT EXISTS (
			SELECT 1
			FROM user_role_assignments a
			WHERE a.user_id = lm.user_id
			  AND a.role_id = r.id
			  AND a.scope_type = 'team'
			  AND a.team_id = lm.team_id
			  AND a.revoked_at IS NULL
		);
	`)
	if err != nil {
		t.Fatalf("run backfill: %v", err)
	}
}

func assertActiveMembership(t *testing.T, ctx context.Context, teamID, userID uuid.UUID) {
	t.Helper()
	var status string
	if err := testPool.QueryRow(ctx, `
		SELECT status
		FROM team_memberships
		WHERE team_id = $1 AND user_id = $2
		ORDER BY created_at DESC
		LIMIT 1
	`, teamID, userID).Scan(&status); err != nil {
		t.Fatalf("read membership: %v", err)
	}
	if status != "active" {
		t.Fatalf("membership status = %q, want active", status)
	}
}

func assertActiveOwnerCount(t *testing.T, ctx context.Context, teamID uuid.UUID, want int) {
	t.Helper()
	var got int
	if err := testPool.QueryRow(ctx, `
		SELECT COUNT(*)::int
		FROM user_role_assignments a
		JOIN roles r ON r.id = a.role_id
		WHERE a.team_id = $1
		  AND a.scope_type = 'team'
		  AND a.revoked_at IS NULL
		  AND r.name = 'team_owner'
	`, teamID).Scan(&got); err != nil {
		t.Fatalf("count active owners: %v", err)
	}
	if got != want {
		t.Fatalf("active owner count = %d, want %d", got, want)
	}
}

func assertRoleAssignment(t *testing.T, ctx context.Context, teamID, userID uuid.UUID, roleName string) {
	t.Helper()
	var got string
	if err := testPool.QueryRow(ctx, `
		SELECT r.name
		FROM user_role_assignments a
		JOIN roles r ON r.id = a.role_id
		WHERE a.team_id = $1
		  AND a.user_id = $2
		  AND a.scope_type = 'team'
		  AND a.revoked_at IS NULL
		ORDER BY a.created_at DESC
		LIMIT 1
	`, teamID, userID).Scan(&got); err != nil {
		t.Fatalf("read assignment: %v", err)
	}
	if got != roleName {
		t.Fatalf("role assignment = %q, want %q", got, roleName)
	}
}

func assertFKViolation(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected delete to be blocked by foreign key")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
		t.Fatalf("expected foreign key violation 23503, got %v", err)
	}
}
