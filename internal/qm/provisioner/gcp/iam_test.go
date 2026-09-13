package gcp

import (
	"slices"
	"testing"

	secretmanager "google.golang.org/api/secretmanager/v1"
)

// The platform's shared secrets carry one binding for every tenant that has
// ever existed, so the edits to that policy have to be exact: adding twice
// must not duplicate, removing must not take anyone else with it, and a
// binding emptied of principals has to go — IAM rejects one with none.

func members(policy *secretmanager.Policy) []string {
	for _, b := range policy.Bindings {
		if isAccessorBinding(b) {
			return b.Members
		}
	}
	return nil
}

func TestAddMember(t *testing.T) {
	policy := &secretmanager.Policy{}
	if !addMember(policy, "serviceAccount:a@example.iam.gserviceaccount.com") {
		t.Fatal("the first grant reported no change")
	}
	if addMember(policy, "serviceAccount:a@example.iam.gserviceaccount.com") {
		t.Error("re-granting reported a change")
	}
	if !addMember(policy, "serviceAccount:b@example.iam.gserviceaccount.com") {
		t.Error("a second tenant's grant reported no change")
	}
	if got := members(policy); len(got) != 2 || len(policy.Bindings) != 1 {
		t.Errorf("members = %v across %d bindings", got, len(policy.Bindings))
	}
}

// A conditional binding is not the one the tenant reads through, so it must
// neither satisfy a grant nor be edited by a revoke.
func TestAddMemberIgnoresConditionalBindings(t *testing.T) {
	policy := &secretmanager.Policy{Bindings: []*secretmanager.Binding{{
		Role:      secretAccessorRole,
		Members:   []string{"serviceAccount:a@example.iam.gserviceaccount.com"},
		Condition: &secretmanager.Expr{Expression: "false"},
	}}}
	if !addMember(policy, "serviceAccount:a@example.iam.gserviceaccount.com") {
		t.Fatal("a conditional binding was treated as a grant")
	}
	if len(policy.Bindings) != 2 {
		t.Errorf("bindings = %d, want the conditional one plus a new unconditional one", len(policy.Bindings))
	}
}

func TestRemoveMember(t *testing.T) {
	policy := &secretmanager.Policy{Bindings: []*secretmanager.Binding{
		{Role: "roles/secretmanager.viewer", Members: []string{"serviceAccount:a@example.iam.gserviceaccount.com"}},
		{Role: secretAccessorRole, Members: []string{
			"serviceAccount:a@example.iam.gserviceaccount.com",
			"serviceAccount:b@example.iam.gserviceaccount.com",
		}},
	}}
	if !removeMember(policy, "serviceAccount:a@example.iam.gserviceaccount.com") {
		t.Fatal("the revoke reported no change")
	}
	if got := members(policy); !slices.Equal(got, []string{"serviceAccount:b@example.iam.gserviceaccount.com"}) {
		t.Errorf("members = %v", got)
	}
	// Another role's binding for the same principal is none of this
	// function's business.
	if len(policy.Bindings) != 2 {
		t.Errorf("bindings = %d, want the unrelated role's to survive", len(policy.Bindings))
	}
	if removeMember(policy, "serviceAccount:a@example.iam.gserviceaccount.com") {
		t.Error("revoking twice reported a change")
	}

	// The last principal takes the binding with it.
	if !removeMember(policy, "serviceAccount:b@example.iam.gserviceaccount.com") {
		t.Fatal("the last revoke reported no change")
	}
	for _, b := range policy.Bindings {
		if len(b.Members) == 0 {
			t.Error("an empty binding was left on the policy")
		}
		if isAccessorBinding(b) {
			t.Error("an accessor binding with no principals survived")
		}
	}
}
