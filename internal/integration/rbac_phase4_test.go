//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

func TestRbacPhase4TeamManagementReadModel(t *testing.T) {
	ownerTeamID, ownerKey, _ := seedTeamAndKeyWithRole(t, "team_owner")
	viewerKey := seedKeyForExistingTeamWithRole(t, ownerTeamID, "viewer")
	r := newRouter(t)

	ownerW := do(r, "GET", "/teams/"+ownerTeamID.String()+"/management", ownerKey, "")
	if ownerW.Code != http.StatusOK {
		t.Fatalf("owner management summary: %d %s", ownerW.Code, ownerW.Body.String())
	}
	var ownerBody struct {
		Members      []map[string]any `json:"members"`
		Assignments  []map[string]any `json:"assignments"`
		Capabilities struct {
			CanInviteMembers       bool `json:"can_invite_members"`
			CanDeactivateMembers   bool `json:"can_deactivate_members"`
			CanAssignRoles         bool `json:"can_assign_roles"`
			CanRevokeRoles         bool `json:"can_revoke_roles"`
			CanViewRoleAssignments bool `json:"can_view_role_assignments"`
		} `json:"capabilities"`
		MutationOptions map[string]any `json:"mutation_options"`
	}
	if err := json.Unmarshal(ownerW.Body.Bytes(), &ownerBody); err != nil {
		t.Fatalf("decode owner management summary: %v", err)
	}
	if len(ownerBody.Members) == 0 {
		t.Fatal("owner management summary missing members")
	}
	if len(ownerBody.Assignments) == 0 {
		t.Fatal("owner management summary missing role assignments")
	}
	if !ownerBody.Capabilities.CanInviteMembers || !ownerBody.Capabilities.CanDeactivateMembers || !ownerBody.Capabilities.CanAssignRoles || !ownerBody.Capabilities.CanRevokeRoles || !ownerBody.Capabilities.CanViewRoleAssignments {
		t.Fatalf("owner capabilities = %+v, want all management capabilities", ownerBody.Capabilities)
	}
	if ownerBody.MutationOptions == nil {
		t.Fatal("owner management summary missing mutation_options")
	}
	if _, ok := ownerBody.MutationOptions["assignable_roles"]; !ok {
		t.Fatal("owner mutation_options missing assignable_roles")
	}

	viewerW := do(r, "GET", "/teams/"+ownerTeamID.String()+"/management", viewerKey, "")
	if viewerW.Code != http.StatusOK {
		t.Fatalf("viewer management summary: %d %s", viewerW.Code, viewerW.Body.String())
	}
	var viewerBody struct {
		Members      []map[string]any `json:"members"`
		Assignments  []map[string]any `json:"assignments"`
		Capabilities struct {
			CanInviteMembers       bool `json:"can_invite_members"`
			CanDeactivateMembers   bool `json:"can_deactivate_members"`
			CanAssignRoles         bool `json:"can_assign_roles"`
			CanRevokeRoles         bool `json:"can_revoke_roles"`
			CanViewRoleAssignments bool `json:"can_view_role_assignments"`
		} `json:"capabilities"`
		MutationOptions map[string]any `json:"mutation_options"`
	}
	if err := json.Unmarshal(viewerW.Body.Bytes(), &viewerBody); err != nil {
		t.Fatalf("decode viewer management summary: %v", err)
	}
	if len(viewerBody.Members) == 0 {
		t.Fatal("viewer management summary missing members")
	}
	for _, member := range viewerBody.Members {
		if roles, ok := member["roles"]; ok {
			if roleList, ok := roles.([]any); !ok || len(roleList) != 0 {
				t.Fatalf("viewer member roles = %#v, want omitted or empty without roles:read", roles)
			}
		}
	}
	if viewerBody.Capabilities.CanInviteMembers || viewerBody.Capabilities.CanDeactivateMembers || viewerBody.Capabilities.CanAssignRoles || viewerBody.Capabilities.CanRevokeRoles || viewerBody.Capabilities.CanViewRoleAssignments {
		t.Fatalf("viewer capabilities = %+v, want read-only users view without mutation or role-assignment controls", viewerBody.Capabilities)
	}
	if viewerBody.MutationOptions != nil {
		t.Fatalf("viewer mutation_options = %+v, want omitted", viewerBody.MutationOptions)
	}
	if len(viewerBody.Assignments) != 0 {
		t.Fatalf("viewer assignments length = %d, want hidden without roles:read", len(viewerBody.Assignments))
	}

	otherTeam := mustCreateTeam(t, t.Context(), "phase4-other-"+uuid.NewString()[:8])
	otherW := do(r, "GET", "/teams/"+otherTeam.String()+"/management", ownerKey, "")
	if otherW.Code != http.StatusForbidden {
		t.Fatalf("expected cross-team management summary forbidden, got %d: %s", otherW.Code, otherW.Body.String())
	}
}
