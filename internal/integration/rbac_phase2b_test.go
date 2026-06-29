//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/authz"
)

const internalRBACToken = "integration-rbac-phase2b-token"

func newInternalRouter(t *testing.T) *gin.Engine {
	t.Helper()
	t.Setenv("INTERNAL_API_TOKEN", internalRBACToken)
	return newRouter(t)
}

func doInternal(r *gin.Engine, method, path, actorID, body string) *httptest.ResponseRecorder {
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+internalRBACToken)
	if actorID != "" {
		req.Header.Set("X-Actor-User-Id", actorID)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func seedPlatformAdminProfile(t *testing.T) uuid.UUID {
	t.Helper()
	return seedPlatformAdminProfileWithIdentity(t, fmt.Sprintf("admin-%s@superserve.ai", uuid.NewString()[:8]), "google")
}

func seedPlatformAdminProfileWithIdentity(t *testing.T, email, provider string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	userID := uuid.New()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO profile (id, email, provider, provider_id)
		VALUES ($1, $2, $3, $4)
	`, userID, email, provider, provider+"-"+userID.String()[:8]); err != nil {
		t.Fatalf("insert platform admin profile: %v", err)
	}
	roleID := mustRoleID(t, ctx, "platform_admin")
	if _, err := testPool.Exec(ctx, `
		INSERT INTO user_role_assignments (user_id, role_id, scope_type, team_id)
		VALUES ($1, $2, 'platform', NULL)
	`, userID, roleID); err != nil {
		t.Fatalf("insert platform admin assignment: %v", err)
	}
	return userID
}

func seedSuperserveEmailProfile(t *testing.T) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	userID := uuid.New()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO profile (id, email, provider, provider_id)
		VALUES ($1, $2, 'google', $3)
	`, userID, fmt.Sprintf("candidate-%s@superserve.ai", userID.String()[:8]), "google-"+userID.String()[:8]); err != nil {
		t.Fatalf("insert superserve email profile: %v", err)
	}
	return userID
}

func teamRoleAssignmentID(t *testing.T, ctx context.Context, teamID, userID uuid.UUID, roleName string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(ctx, `
		SELECT ura.id
		FROM user_role_assignments ura
		JOIN roles r ON r.id = ura.role_id
		WHERE ura.team_id = $1
		  AND ura.user_id = $2
		  AND ura.scope_type = 'team'
		  AND ura.revoked_at IS NULL
		  AND r.name = $3
		LIMIT 1
	`, teamID, userID, roleName).Scan(&id); err != nil {
		t.Fatalf("lookup team %s assignment: %v", roleName, err)
	}
	return id
}

func auditEventCount(t *testing.T, ctx context.Context, teamID uuid.UUID, eventType string) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM audit_logs
		WHERE team_id = $1
		  AND event_type = $2
	`, teamID, eventType).Scan(&n); err != nil {
		t.Fatalf("count audit logs: %v", err)
	}
	return n
}

func membershipStatus(t *testing.T, ctx context.Context, teamID, userID uuid.UUID) string {
	t.Helper()
	var status string
	if err := testPool.QueryRow(ctx, `
		SELECT status
		FROM team_memberships
		WHERE team_id = $1
		  AND user_id = $2
		ORDER BY updated_at DESC, created_at DESC
		LIMIT 1
	`, teamID, userID).Scan(&status); err != nil {
		t.Fatalf("membership status: %v", err)
	}
	return status
}

func TestRbacPhase2bTeamMemberManagement(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey, _ := seedTeamAndKeyWithRole(t, "team_owner")
	r := newRouter(t)

	targetID := seedRBACProfile(t)

	w := do(r, "GET", "/teams/"+teamID.String()+"/members", apiKey, "")
	if w.Code != http.StatusOK {
		t.Fatalf("list members: %d %s", w.Code, w.Body.String())
	}
	var listBody struct {
		Members []map[string]any `json:"members"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &listBody); err != nil {
		t.Fatalf("parse members: %v", err)
	}
	if len(listBody.Members) == 0 {
		t.Fatal("expected at least one team member")
	}

	addW := do(r, "POST", "/teams/"+teamID.String()+"/members", apiKey, fmt.Sprintf(`{"user_id":%q,"status":"active"}`, targetID))
	if addW.Code != http.StatusCreated {
		t.Fatalf("add member: %d %s", addW.Code, addW.Body.String())
	}
	if got := membershipStatus(t, ctx, teamID, targetID); got != "active" {
		t.Fatalf("membership status = %q, want active", got)
	}
	if auditEventCount(t, ctx, teamID, "team_member_added") == 0 {
		t.Fatal("expected team_member_added audit row")
	}

	delW := do(r, "DELETE", "/teams/"+teamID.String()+"/members/"+targetID.String(), apiKey, "")
	if delW.Code != http.StatusNoContent {
		t.Fatalf("deactivate member: %d %s", delW.Code, delW.Body.String())
	}
	if got := membershipStatus(t, ctx, teamID, targetID); got != "inactive" {
		t.Fatalf("membership status = %q, want inactive", got)
	}
	if auditEventCount(t, ctx, teamID, "team_member_deactivated") == 0 {
		t.Fatal("expected team_member_deactivated audit row")
	}

	t.Run("deactivating a member audits revoked roles", func(t *testing.T) {
		teamID2, key2, _ := seedTeamAndKeyWithRole(t, "team_owner")
		target := seedRBACProfile(t)
		seedMembership(t, ctx, teamID2, target)
		seedTeamRoleAssignment(t, ctx, target, mustRoleID(t, ctx, "team_admin"), teamID2)
		before := auditEventCount(t, ctx, teamID2, "team_role_revoked")

		w := do(r, "DELETE", "/teams/"+teamID2.String()+"/members/"+target.String(), key2, "")
		if w.Code != http.StatusNoContent {
			t.Fatalf("deactivate member: %d %s", w.Code, w.Body.String())
		}
		if got := auditEventCount(t, ctx, teamID2, "team_role_revoked"); got <= before {
			t.Fatalf("team_role_revoked audit rows = %d, want > %d", got, before)
		}
	})

	t.Run("customer route ignores actor header for legacy key", func(t *testing.T) {
		legacyTeam, legacyKey := seedTeamAndKeyNoCreator(t)
		privilegedUser := seedRBACProfile(t)
		seedMembership(t, ctx, legacyTeam, privilegedUser)
		seedTeamRoleAssignment(t, ctx, privilegedUser, mustRoleID(t, ctx, "team_owner"), legacyTeam)
		target := seedRBACProfile(t)

		req := httptest.NewRequest("POST", "/teams/"+legacyTeam.String()+"/members", strings.NewReader(fmt.Sprintf(`{"user_id":%q}`, target)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", legacyKey)
		req.Header.Set("X-Actor-User-Id", privilegedUser.String())
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected customer route to reject header actor fallback, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("cannot move final owner to invited through add member", func(t *testing.T) {
		ownerTeam, ownerKey, ownerProfile := seedTeamAndKeyWithRole(t, "team_owner")

		w := do(r, "POST", "/teams/"+ownerTeam.String()+"/members", ownerKey, fmt.Sprintf(`{"user_id":%q,"status":"invited"}`, ownerProfile))
		if w.Code != http.StatusConflict {
			t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
		}

		if got := membershipStatus(t, ctx, ownerTeam, ownerProfile); got != "active" {
			t.Fatalf("membership status = %q, want active", got)
		}
	})

	t.Run("user_admin can reactivate former team owner after role revoke", func(t *testing.T) {
		teamID2, userAdminKey, _ := seedTeamAndKeyWithRole(t, "user_admin")
		target := seedRBACProfile(t)
		seedMembership(t, ctx, teamID2, target)
		seedTeamRoleAssignment(t, ctx, target, mustRoleID(t, ctx, "team_owner"), teamID2)
		if _, err := testPool.Exec(ctx, `
			UPDATE team_memberships
			SET status = 'inactive', updated_at = now()
			WHERE team_id = $1 AND user_id = $2
		`, teamID2, target); err != nil {
			t.Fatalf("mark target inactive: %v", err)
		}

		w := do(r, "POST", "/teams/"+teamID2.String()+"/members", userAdminKey, fmt.Sprintf(`{"user_id":%q,"status":"active"}`, target))
		if w.Code != http.StatusCreated {
			t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
		}
		if got := membershipStatus(t, ctx, teamID2, target); got != "active" {
			t.Fatalf("membership status = %q, want active", got)
		}
	})

	t.Run("denied without users write", func(t *testing.T) {
		otherTeam, viewerKey, _ := seedTeamAndKeyWithRole(t, "viewer")
		otherTarget := seedRBACProfile(t)
		w := do(r, "POST", "/teams/"+otherTeam.String()+"/members", viewerKey, fmt.Sprintf(`{"user_id":%q}`, otherTarget))
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("cannot manage another team", func(t *testing.T) {
		otherTeam := mustCreateTeam(t, ctx, "rbac-other-"+uuid.NewString()[:8])
		otherTarget := seedRBACProfile(t)
		w := do(r, "POST", "/teams/"+otherTeam.String()+"/members", apiKey, fmt.Sprintf(`{"user_id":%q}`, otherTarget))
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("inactive membership denied", func(t *testing.T) {
		teamID2, apiKey2, actor2 := seedTeamAndKeyWithRole(t, "team_owner")
		if _, err := testPool.Exec(ctx, `
			UPDATE team_memberships
			SET status = 'inactive', updated_at = now()
			WHERE team_id = $1 AND user_id = $2
		`, teamID2, actor2); err != nil {
			t.Fatalf("deactivate actor membership: %v", err)
		}
		target := seedRBACProfile(t)
		w := do(r, "POST", "/teams/"+teamID2.String()+"/members", apiKey2, fmt.Sprintf(`{"user_id":%q}`, target))
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("deactivating active owner without roles write is forbidden", func(t *testing.T) {
		teamID2, userAdminKey, _ := seedTeamAndKeyWithRole(t, "user_admin")
		target := seedRBACProfile(t)
		spareOwner := seedRBACProfile(t)
		seedMembership(t, ctx, teamID2, target)
		seedMembership(t, ctx, teamID2, spareOwner)
		seedTeamRoleAssignment(t, ctx, target, mustRoleID(t, ctx, "team_owner"), teamID2)
		seedTeamRoleAssignment(t, ctx, spareOwner, mustRoleID(t, ctx, "team_owner"), teamID2)

		w := do(r, "DELETE", "/teams/"+teamID2.String()+"/members/"+target.String(), userAdminKey, "")
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
		}
	})
}

func TestRbacPhase2bTeamRoleManagement(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey, _ := seedTeamAndKeyWithRole(t, "team_owner")
	r := newRouter(t)

	targetID := seedRBACProfile(t)
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_memberships (team_id, user_id, status)
		VALUES ($1, $2, 'active')
	`, teamID, targetID); err != nil {
		t.Fatalf("insert target membership: %v", err)
	}

	assignW := do(r, "POST", "/teams/"+teamID.String()+"/roles", apiKey, fmt.Sprintf(`{"user_id":%q,"role_name":"team_admin"}`, targetID))
	if assignW.Code != http.StatusCreated {
		t.Fatalf("assign role: %d %s", assignW.Code, assignW.Body.String())
	}
	var assignBody map[string]any
	if err := json.Unmarshal(assignW.Body.Bytes(), &assignBody); err != nil {
		t.Fatalf("parse assign response: %v", err)
	}
	if email, ok := assignBody["email"].(string); !ok || email == "" {
		t.Fatalf("assign response email = %#v, want non-empty string", assignBody["email"])
	}
	assignmentID := teamRoleAssignmentID(t, ctx, teamID, targetID, "team_admin")

	listW := do(r, "GET", "/teams/"+teamID.String()+"/roles", apiKey, "")
	if listW.Code != http.StatusOK {
		t.Fatalf("list roles: %d %s", listW.Code, listW.Body.String())
	}

	revokeW := do(r, "DELETE", "/teams/"+teamID.String()+"/roles/"+assignmentID.String(), apiKey, "")
	if revokeW.Code != http.StatusNoContent {
		t.Fatalf("revoke role: %d %s", revokeW.Code, revokeW.Body.String())
	}
	if auditEventCount(t, ctx, teamID, "team_role_assigned") == 0 {
		t.Fatal("expected team_role_assigned audit row")
	}
	if auditEventCount(t, ctx, teamID, "team_role_revoked") == 0 {
		t.Fatal("expected team_role_revoked audit row")
	}

	t.Run("denied without roles write", func(t *testing.T) {
		otherTeam, viewerKey, _ := seedTeamAndKeyWithRole(t, "viewer")
		otherTarget := seedRBACProfile(t)
		if _, err := testPool.Exec(ctx, `
			INSERT INTO team_memberships (team_id, user_id, status)
			VALUES ($1, $2, 'active')
		`, otherTeam, otherTarget); err != nil {
			t.Fatalf("insert membership: %v", err)
		}
		w := do(r, "POST", "/teams/"+otherTeam.String()+"/roles", viewerKey, fmt.Sprintf(`{"user_id":%q,"role_name":"team_admin"}`, otherTarget))
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("customer cannot assign platform role", func(t *testing.T) {
		w := do(r, "POST", "/teams/"+teamID.String()+"/roles", apiKey, fmt.Sprintf(`{"user_id":%q,"role_name":"platform_admin"}`, targetID))
		if w.Code == http.StatusCreated {
			t.Fatalf("expected platform role assignment to fail, got %d", w.Code)
		}
	})

	t.Run("cannot manage another team", func(t *testing.T) {
		otherTeam := mustCreateTeam(t, ctx, "rbac-other-role-"+uuid.NewString()[:8])
		otherTarget := seedRBACProfile(t)
		if _, err := testPool.Exec(ctx, `
			INSERT INTO team_memberships (team_id, user_id, status)
			VALUES ($1, $2, 'active')
		`, otherTeam, otherTarget); err != nil {
			t.Fatalf("insert membership: %v", err)
		}
		w := do(r, "POST", "/teams/"+otherTeam.String()+"/roles", apiKey, fmt.Sprintf(`{"user_id":%q,"role_name":"team_admin"}`, otherTarget))
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("final active owner cannot be revoked", func(t *testing.T) {
		ownerTeam, ownerKey, ownerProfile := seedTeamAndKeyWithRole(t, "team_owner")
		ownerAssignment := teamRoleAssignmentID(t, ctx, ownerTeam, ownerProfile, "team_owner")
		w := do(r, "DELETE", "/teams/"+ownerTeam.String()+"/roles/"+ownerAssignment.String(), ownerKey, "")
		if w.Code != http.StatusConflict {
			t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
		}
	})
}

func TestRbacPhase2bPlatformRecovery(t *testing.T) {
	ctx := context.Background()
	r := newInternalRouter(t)
	platformActor := seedPlatformAdminProfile(t)
	invalidPlatformActor := seedPlatformAdminProfileWithIdentity(t, "admin@example.com", "google")
	nonPlatformActor := seedRBACProfile(t)
	superserveCandidate := seedSuperserveEmailProfile(t)
	teamID := mustCreateTeam(t, ctx, "rbac-recovery-"+uuid.NewString()[:8])

	t.Run("internal platform routes require a superserve google session", func(t *testing.T) {
		w := doInternal(r, "GET", "/internal/teams/"+teamID.String()+"/members", invalidPlatformActor.String(), "")
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
		}
	})

	w := doInternal(r, "POST", "/internal/teams/"+teamID.String()+"/recover", platformActor.String(), fmt.Sprintf(`{"user_id":%q}`, superserveCandidate))
	if w.Code != http.StatusOK {
		t.Fatalf("platform recovery: %d %s", w.Code, w.Body.String())
	}
	if got := membershipStatus(t, ctx, teamID, superserveCandidate); got != "active" {
		t.Fatalf("membership status = %q, want active", got)
	}
	if auditEventCount(t, ctx, teamID, "platform_team_recovered") == 0 {
		t.Fatal("expected platform_team_recovered audit row")
	}
	var membershipID string
	if err := testPool.QueryRow(ctx, `
		SELECT new_value->>'membership_id'
		FROM audit_logs
		WHERE team_id = $1
		  AND event_type = 'platform_team_recovered'
		ORDER BY created_at DESC
		LIMIT 1
	`, teamID).Scan(&membershipID); err != nil {
		t.Fatalf("read recovery audit membership id: %v", err)
	}
	if membershipID == "" || membershipID == uuid.Nil.String() {
		t.Fatalf("membership_id = %q, want real membership id", membershipID)
	}

	t.Run("non-platform user denied", func(t *testing.T) {
		teamID2 := mustCreateTeam(t, ctx, "rbac-recovery-deny-"+uuid.NewString()[:8])
		target := seedRBACProfile(t)
		w := doInternal(r, "POST", "/internal/teams/"+teamID2.String()+"/recover", nonPlatformActor.String(), fmt.Sprintf(`{"user_id":%q}`, target))
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("email-domain alone is not enough", func(t *testing.T) {
		teamID2 := mustCreateTeam(t, ctx, "rbac-recovery-domain-"+uuid.NewString()[:8])
		target := seedRBACProfile(t)
		w := doInternal(r, "POST", "/internal/teams/"+teamID2.String()+"/recover", superserveCandidate.String(), fmt.Sprintf(`{"user_id":%q}`, target))
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
		}
	})
}

func TestRbacPhase2bAuditHelperOmittedMetadata(t *testing.T) {
	ctx := context.Background()
	svc := authz.New(testPool)
	teamID := mustCreateTeam(t, ctx, "rbac-audit-metadata-"+uuid.NewString()[:8])
	actorID := seedRBACProfile(t)
	targetID := seedRBACProfile(t)

	if err := svc.WriteAuditLog(ctx, testPool, authz.AuditEvent{
		ActorUserID:  &actorID,
		TargetUserID: &targetID,
		TeamID:       &teamID,
		EventType:    "team_member_added",
		NewValue:     []byte(`{"status":"active"}`),
	}); err != nil {
		t.Fatalf("WriteAuditLog: %v", err)
	}

	var metadata string
	if err := testPool.QueryRow(ctx, `
		SELECT metadata::text
		FROM audit_logs
		WHERE team_id = $1
		  AND actor_user_id = $2
		  AND target_user_id = $3
		ORDER BY created_at DESC
		LIMIT 1
	`, teamID, actorID, targetID).Scan(&metadata); err != nil {
		t.Fatalf("read audit metadata: %v", err)
	}
	if metadata != "{}" {
		t.Fatalf("metadata = %q, want {}", metadata)
	}
}
