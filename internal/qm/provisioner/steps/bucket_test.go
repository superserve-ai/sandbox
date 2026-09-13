package steps

import "testing"

// A lifecycle policy that parses into "no rules" is worse than one that
// fails to parse: the plan starts, every bucket is created, and the policy
// nobody notices is missing is the one that reaps abandoned uploads. So the
// outline is checked strictly, and by one parser the readiness check and the
// bucket client both use.
func TestParseLifecyclePolicy(t *testing.T) {
	for _, policy := range []string{"", "   ", "\n\t "} {
		got, err := ParseLifecyclePolicy(policy)
		if err != nil || got != "" {
			t.Errorf("ParseLifecyclePolicy(%q) = %q, %v; want no policy", policy, got, err)
		}
	}
	valid := `{"rule":[{"action":{"type":"Delete"},"condition":{"age":30}}]}`
	if got, err := ParseLifecyclePolicy(" " + valid + " "); err != nil || got != valid {
		t.Errorf("a valid policy = %q, %v", got, err)
	}
	// An empty rule list is a deliberate "no rules", and is kept.
	if got, err := ParseLifecyclePolicy(`{"rule":[]}`); err != nil || got != `{"rule":[]}` {
		t.Errorf("an empty rule list = %q, %v", got, err)
	}
	for _, policy := range []string{
		"{not json",
		"{}",                // no rule field at all
		"null",              // parses, means nothing
		`{"rules":[]}`,      // misspelled
		`{"rule":[],"x":1}`, // unknown field
		`[]`,
		`{"rule":[]} {}`,   // trailing value
		`{"rule":[]} junk`, // trailing anything
	} {
		if _, err := ParseLifecyclePolicy(policy); err == nil {
			t.Errorf("ParseLifecyclePolicy(%q) was accepted", policy)
		}
	}
}
