//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/authz"
)

func TestRbacTeamPermissionDecisions(t *testing.T) {
	ctx := context.Background()
	svc := authz.New(testPool)

	type teamCase struct {
		name       string
		roleName   string
		permission string
		want       bool
	}

	cases := []teamCase{
		{"team_owner billing read", "team_owner", "billing:read", true},
		{"team_owner billing write", "team_owner", "billing:write", true},
		{"team_owner users write", "team_owner", "users:write", true},
		{"team_owner roles write", "team_owner", "roles:write", true},
		{"billing_admin billing write", "billing_admin", "billing:write", true},
		{"billing_admin users write", "billing_admin", "users:write", false},
		{"user_admin users write", "user_admin", "users:write", true},
		{"user_admin billing write", "user_admin", "billing:write", false},
		{"viewer billing read", "viewer", "billing:read", true},
		{"viewer users read", "viewer", "users:read", true},
		{"viewer billing write", "viewer", "billing:write", false},
		{"inactive membership denied", "viewer", "billing:read", false},
		{"revoked assignment denied", "viewer", "billing:read", false},
		{"other team denied", "viewer", "billing:read", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			userID := seedRBACProfile(t)
			teamID := mustCreateTeam(t, ctx, "rbac-phase2-"+uuid.NewString()[:8])

			switch tc.name {
			case "other team denied":
				seedMembership(t, ctx, teamID, userID)
				roleID := mustRoleID(t, ctx, tc.roleName)
				seedTeamRoleAssignment(t, ctx, userID, roleID, teamID)

				otherTeam := mustCreateTeam(t, ctx, "rbac-phase2-other-"+uuid.NewString()[:8])
				got, err := svc.CanTeam(ctx, userID, otherTeam, tc.permission)
				if err != nil {
					t.Fatalf("CanTeam: %v", err)
				}
				if got != tc.want {
					t.Fatalf("CanTeam = %v, want %v", got, tc.want)
				}
				return
			case "inactive membership denied":
				seedMembership(t, ctx, teamID, userID)
				roleID := mustRoleID(t, ctx, tc.roleName)
				seedTeamRoleAssignment(t, ctx, userID, roleID, teamID)
				if _, err := testPool.Exec(ctx, `
					UPDATE team_memberships
					SET status = 'inactive', updated_at = now()
					WHERE team_id = $1 AND user_id = $2
				`, teamID, userID); err != nil {
					t.Fatalf("deactivate membership: %v", err)
				}
			case "revoked assignment denied":
				seedMembership(t, ctx, teamID, userID)
				roleID := mustRoleID(t, ctx, tc.roleName)
				if _, err := testPool.Exec(ctx, `
					INSERT INTO user_role_assignments (
						user_id, role_id, scope_type, team_id, revoked_at
					)
					VALUES ($1, $2, 'team', $3, now())
				`, userID, roleID, teamID); err != nil {
					t.Fatalf("insert revoked assignment: %v", err)
				}
			default:
				seedMembership(t, ctx, teamID, userID)
				roleID := mustRoleID(t, ctx, tc.roleName)
				seedTeamRoleAssignment(t, ctx, userID, roleID, teamID)
			}

			got, err := svc.CanTeam(ctx, userID, teamID, tc.permission)
			if err != nil {
				t.Fatalf("CanTeam: %v", err)
			}
			if got != tc.want {
				t.Fatalf("CanTeam = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRbacPlatformPermissionDecisions(t *testing.T) {
	ctx := context.Background()
	svc := authz.New(testPool)

	activeUser := seedRBACProfile(t)
	activeTeam := mustCreateTeam(t, ctx, "rbac-platform-active-"+uuid.NewString()[:8])
	seedMembership(t, ctx, activeTeam, activeUser)
	seedTeamRoleAssignment(t, ctx, activeUser, mustRoleID(t, ctx, "viewer"), activeTeam)
	if _, err := testPool.Exec(ctx, `
		INSERT INTO user_role_assignments (user_id, role_id, scope_type, team_id)
		VALUES ($1, $2, 'platform', NULL)
	`, activeUser, mustRoleID(t, ctx, "platform_admin")); err != nil {
		t.Fatalf("insert platform assignment: %v", err)
	}

	revokedUser := seedRBACProfile(t)
	revokedTeam := mustCreateTeam(t, ctx, "rbac-platform-revoked-"+uuid.NewString()[:8])
	seedMembership(t, ctx, revokedTeam, revokedUser)
	seedTeamRoleAssignment(t, ctx, revokedUser, mustRoleID(t, ctx, "viewer"), revokedTeam)
	if _, err := testPool.Exec(ctx, `
		INSERT INTO user_role_assignments (
			user_id, role_id, scope_type, team_id, revoked_at
		)
		VALUES ($1, $2, 'platform', NULL, now())
	`, revokedUser, mustRoleID(t, ctx, "platform_admin")); err != nil {
		t.Fatalf("insert revoked platform assignment: %v", err)
	}

	got, err := svc.CanPlatform(ctx, activeUser, "platform:teams:read")
	if err != nil {
		t.Fatalf("CanPlatform active: %v", err)
	}
	if !got {
		t.Fatal("expected active platform admin to pass platform permission check")
	}

	got, err = svc.CanPlatform(ctx, revokedUser, "platform:teams:read")
	if err != nil {
		t.Fatalf("CanPlatform revoked: %v", err)
	}
	if got {
		t.Fatal("expected revoked platform assignment to fail")
	}
}

func TestRbacFinalOwnerGuard(t *testing.T) {
	ctx := context.Background()
	svc := authz.New(testPool)

	teamID := mustCreateTeam(t, ctx, "rbac-owner-"+uuid.NewString()[:8])
	ownerA := seedRBACProfile(t)
	ownerB := seedRBACProfile(t)

	seedMembership(t, ctx, teamID, ownerA)
	seedMembership(t, ctx, teamID, ownerB)
	seedTeamRoleAssignment(t, ctx, ownerA, mustRoleID(t, ctx, "team_owner"), teamID)
	seedTeamRoleAssignment(t, ctx, ownerB, mustRoleID(t, ctx, "team_owner"), teamID)

	ok, err := svc.CanRevokeLastTeamOwner(ctx, teamID, ownerA)
	if err != nil {
		t.Fatalf("CanRevokeLastTeamOwner: %v", err)
	}
	if !ok {
		t.Fatal("expected removal of one of two owners to be allowed")
	}

	if _, err := testPool.Exec(ctx, `
		UPDATE user_role_assignments
		SET revoked_at = now()
		WHERE team_id = $1 AND user_id = $2 AND scope_type = 'team'
	`, teamID, ownerB); err != nil {
		t.Fatalf("revoke second owner: %v", err)
	}

	ok, err = svc.CanRevokeLastTeamOwner(ctx, teamID, ownerA)
	if err != nil {
		t.Fatalf("CanRevokeLastTeamOwner after revoke: %v", err)
	}
	if ok {
		t.Fatal("expected removal of last owner to be denied")
	}
}

func TestRbacAuditLogHelper(t *testing.T) {
	ctx := context.Background()
	svc := authz.New(testPool)
	teamID := mustCreateTeam(t, ctx, "rbac-audit-"+uuid.NewString()[:8])
	actorID := seedRBACProfile(t)
	targetID := seedRBACProfile(t)

	if err := svc.WriteAuditLog(ctx, testPool, authz.AuditEvent{
		ActorUserID:  &actorID,
		TargetUserID: &targetID,
		TeamID:       &teamID,
		EventType:    "team_role_assigned",
		OldValue:     []byte(`{"role":"viewer"}`),
		NewValue:     []byte(`{"role":"team_owner"}`),
		Metadata:     []byte(`{"source":"rbac-phase2-test"}`),
	}); err != nil {
		t.Fatalf("WriteAuditLog: %v", err)
	}

	var gotEvent string
	if err := testPool.QueryRow(ctx, `
		SELECT event_type
		FROM audit_logs
		WHERE team_id = $1 AND actor_user_id = $2 AND target_user_id = $3
		ORDER BY created_at DESC
		LIMIT 1
	`, teamID, actorID, targetID).Scan(&gotEvent); err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if gotEvent != "team_role_assigned" {
		t.Fatalf("event_type = %q, want team_role_assigned", gotEvent)
	}
}

func TestRbacPermissionScopeMismatch(t *testing.T) {
	ctx := context.Background()
	svc := authz.New(testPool)
	userID := seedRBACProfile(t)
	teamID := mustCreateTeam(t, ctx, "rbac-scope-"+uuid.NewString()[:8])
	seedMembership(t, ctx, teamID, userID)
	seedTeamRoleAssignment(t, ctx, userID, mustRoleID(t, ctx, "viewer"), teamID)

	got, err := svc.CanTeam(ctx, userID, teamID, "platform:team_roles:write")
	if err == nil || got {
		t.Fatal("expected platform permission name to be rejected in team scope")
	}

	got, err = svc.CanPlatform(ctx, userID, "billing:read")
	if err == nil || got {
		t.Fatal("expected team permission name to be rejected in platform scope")
	}
}

func TestRbacTeamPermissionAfterRevocationHistory(t *testing.T) {
	ctx := context.Background()
	svc := authz.New(testPool)
	teamID := mustCreateTeam(t, ctx, "rbac-history-"+uuid.NewString()[:8])
	userID := seedRBACProfile(t)
	seedMembership(t, ctx, teamID, userID)

	roleID := mustRoleID(t, ctx, "team_admin")
	if _, err := testPool.Exec(ctx, `
		INSERT INTO user_role_assignments (
			user_id, role_id, scope_type, team_id, revoked_at
		)
		VALUES ($1, $2, 'team', $3, now())
	`, userID, roleID, teamID); err != nil {
		t.Fatalf("insert revoked history: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO user_role_assignments (
			user_id, role_id, scope_type, team_id
		)
		VALUES ($1, $2, 'team', $3)
	`, userID, roleID, teamID); err != nil {
		t.Fatalf("insert active row after revoked history: %v", err)
	}

	got, err := svc.CanTeam(ctx, userID, teamID, "users:write")
	if err != nil {
		t.Fatalf("CanTeam: %v", err)
	}
	if !got {
		t.Fatal("expected active assignment after revoked history to permit access")
	}
}

func TestRbacPermissionChecksAtEndpoint(t *testing.T) {
	// Billing pricing is the first endpoint guarded by RBAC in this phase.
	teamID, apiKey, _ := seedTeamAndKeyWithRole(t, "viewer")
	r := newRouter(t)

	w := do(r, "GET", "/billing/pricing?team_id="+teamID.String(), apiKey, "")
	if w.Code != 200 {
		t.Fatalf("expected billing pricing to succeed for viewer, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRbacPermissionChecksAtEndpoint_DeniesUserAdmin(t *testing.T) {
	teamID, apiKey, _ := seedTeamAndKeyWithRole(t, "user_admin")
	r := newRouter(t)

	w := do(r, "GET", "/billing/pricing?team_id="+teamID.String(), apiKey, "")
	if w.Code != 403 {
		t.Fatalf("expected billing pricing to be forbidden for user_admin, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRbacPlatformSessionEligibility(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name    string
		session authz.SessionClaims
		wantErr bool
	}{
		{
			name: "google superserve verified",
			session: authz.SessionClaims{
				Provider:      "Google",
				Email:         "  admin@superserve.ai ",
				EmailVerified: boolPtr(true),
			},
			wantErr: false,
		},
		{
			name: "wrong provider",
			session: authz.SessionClaims{
				Provider: "email",
				Email:    "admin@superserve.ai",
			},
			wantErr: true,
		},
		{
			name: "bad domain",
			session: authz.SessionClaims{
				Provider: "google",
				Email:    "admin@superserve.ai.evil.com",
			},
			wantErr: true,
		},
		{
			name: "unverified email denied",
			session: authz.SessionClaims{
				Provider:      "google",
				Email:         "admin@superserve.ai",
				EmailVerified: boolPtr(false),
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := authz.RequirePlatformAdminGoogleSession(ctx, tc.session)
			if tc.wantErr && err == nil {
				t.Fatal("expected session to be rejected")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected session to pass, got %v", err)
			}
		})
	}
}

func boolPtr(v bool) *bool { return &v }
