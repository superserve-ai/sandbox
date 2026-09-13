package gcp

import (
	"testing"

	compute "google.golang.org/api/compute/v1"
)

// The URL map edits are the part of the routing that is pure logic, and the
// part where a mistake is shared: every tenant's route lives on the one map,
// so an edit that drops somebody else's host rule takes their tenant down.

func routed(m *compute.UrlMap, host string) (string, bool) {
	for _, rule := range m.HostRules {
		for _, h := range rule.Hosts {
			if h == host {
				return rule.PathMatcher, true
			}
		}
	}
	return "", false
}

func matcherService(m *compute.UrlMap, name string) (string, bool) {
	for _, pm := range m.PathMatchers {
		if pm.Name == name {
			return pm.DefaultService, true
		}
	}
	return "", false
}

func TestAddRoute(t *testing.T) {
	m := &compute.UrlMap{
		HostRules:    []*compute.HostRule{{Hosts: []string{"other.qm.example.com"}, PathMatcher: "qm-other"}},
		PathMatchers: []*compute.PathMatcher{{Name: "qm-other", DefaultService: "other-backend"}},
	}
	if !addRoute(m, "pilot-team.qm.example.com", "qm-pilot-team", "pilot-backend") {
		t.Fatal("adding a route reported no change")
	}
	if matcher, ok := routed(m, "pilot-team.qm.example.com"); !ok || matcher != "qm-pilot-team" {
		t.Errorf("host rule = %q %v", matcher, ok)
	}
	if svc, ok := matcherService(m, "qm-pilot-team"); !ok || svc != "pilot-backend" {
		t.Errorf("path matcher = %q %v", svc, ok)
	}
	// The tenant that was already there is untouched.
	if matcher, ok := routed(m, "other.qm.example.com"); !ok || matcher != "qm-other" {
		t.Errorf("the existing tenant's route changed: %q %v", matcher, ok)
	}

	// Adding the same route again is a no-op, which is what makes the step
	// safe to re-run.
	if addRoute(m, "pilot-team.qm.example.com", "qm-pilot-team", "pilot-backend") {
		t.Error("re-adding the same route reported a change")
	}
	if len(m.HostRules) != 2 || len(m.PathMatchers) != 2 {
		t.Errorf("re-adding duplicated something: %d rules, %d matchers", len(m.HostRules), len(m.PathMatchers))
	}

	// A route whose backend moved is corrected rather than duplicated.
	if !addRoute(m, "pilot-team.qm.example.com", "qm-pilot-team", "pilot-backend-v2") {
		t.Error("a changed backend reported no change")
	}
	if svc, _ := matcherService(m, "qm-pilot-team"); svc != "pilot-backend-v2" {
		t.Errorf("backend = %q", svc)
	}
}

func TestRemoveRoute(t *testing.T) {
	m := &compute.UrlMap{
		HostRules: []*compute.HostRule{
			{Hosts: []string{"other.qm.example.com"}, PathMatcher: "qm-other"},
			{Hosts: []string{"pilot-team.qm.example.com"}, PathMatcher: "qm-pilot-team"},
		},
		PathMatchers: []*compute.PathMatcher{
			{Name: "qm-other", DefaultService: "other-backend"},
			{Name: "qm-pilot-team", DefaultService: "pilot-backend"},
		},
	}
	matcher, changed := removeRoute(m, "pilot-team.qm.example.com")
	if !changed || matcher != "qm-pilot-team" {
		t.Fatalf("removeRoute = %q %v", matcher, changed)
	}
	if _, ok := routed(m, "pilot-team.qm.example.com"); ok {
		t.Error("the host rule survived")
	}
	if _, ok := matcherService(m, "qm-pilot-team"); ok {
		t.Error("the path matcher survived")
	}
	if _, ok := routed(m, "other.qm.example.com"); !ok {
		t.Error("removing one tenant took another's route with it")
	}

	// Removing it again changes nothing: teardown is retried, and the
	// retry must not report an edit it did not make.
	if _, changed := removeRoute(m, "pilot-team.qm.example.com"); changed {
		t.Error("removing an absent host reported a change")
	}
}

// A rule that carries more than this tenant's host keeps the others, and
// its matcher stays in use — so the caller must not go on to delete the
// backend service behind it.
func TestRemoveRouteFromASharedRule(t *testing.T) {
	m := &compute.UrlMap{
		HostRules: []*compute.HostRule{
			{Hosts: []string{"pilot-team.qm.example.com", "alias.qm.example.com"}, PathMatcher: "qm-pilot-team"},
		},
		PathMatchers: []*compute.PathMatcher{{Name: "qm-pilot-team", DefaultService: "pilot-backend"}},
	}
	matcher, changed := removeRoute(m, "pilot-team.qm.example.com")
	if !changed {
		t.Fatal("removing a host from a shared rule reported no change")
	}
	if matcher != "" {
		t.Errorf("a matcher still in use was reported for deletion: %q", matcher)
	}
	if _, ok := routed(m, "alias.qm.example.com"); !ok {
		t.Error("the other host lost its route")
	}
	if _, ok := matcherService(m, "qm-pilot-team"); !ok {
		t.Error("a path matcher still in use was removed")
	}
}

// A backend service that drifted off this tenant's NEG is repaired; one
// already pointing at it is left alone. The comparison is by suffix because
// the API answers with a fully qualified URL where the create sends a
// relative path.
func TestBacksNEG(t *testing.T) {
	const negLink = "projects/example-project/regions/us-central1/networkEndpointGroups/qm-pilot-team"
	for name, tc := range map[string]struct {
		backends []*compute.Backend
		want     bool
	}{
		"relative path":        {[]*compute.Backend{{Group: negLink}}, true},
		"fully qualified":      {[]*compute.Backend{{Group: "https://www.googleapis.com/compute/v1/" + negLink}}, true},
		"another tenant's neg": {[]*compute.Backend{{Group: "projects/example-project/regions/us-central1/networkEndpointGroups/qm-other"}}, false},
		"no backends":          {nil, false},
		"more than one":        {[]*compute.Backend{{Group: negLink}, {Group: "other"}}, false},
	} {
		if got := backsNEG(&compute.BackendService{Backends: tc.backends}, negLink); got != tc.want {
			t.Errorf("%s: backsNEG = %v, want %v", name, got, tc.want)
		}
	}
}

func TestNEGTarget(t *testing.T) {
	if got := negTarget(&compute.NetworkEndpointGroup{CloudRun: &compute.NetworkEndpointGroupCloudRun{Service: "qm-pilot-team"}}); got != "qm-pilot-team" {
		t.Errorf("target = %q", got)
	}
	// A group that is not a Cloud Run NEG at all targets nothing this can
	// use, which is a mismatch rather than a match.
	if got := negTarget(&compute.NetworkEndpointGroup{}); got != "" {
		t.Errorf("target of a non-cloud-run group = %q", got)
	}
	if got := negTarget(nil); got != "" {
		t.Errorf("target of nothing = %q", got)
	}
}

// A URL map's host rules are shared state. Reconciling one tenant must
// never repoint a rule that other hostnames ride on: the tenant gets a rule
// of its own and the others are left where they were.
func TestAddRouteSplitsASharedRule(t *testing.T) {
	m := &compute.UrlMap{
		HostRules: []*compute.HostRule{
			{Hosts: []string{"pilot-team.qm.example.com", "other.qm.example.com"}, PathMatcher: "qm-legacy"},
		},
		PathMatchers: []*compute.PathMatcher{{Name: "qm-legacy", DefaultService: "legacy-backend"}},
	}
	if !addRoute(m, "pilot-team.qm.example.com", "qm-pilot-team", "pilot-backend") {
		t.Fatal("splitting a shared rule reported no change")
	}
	if matcher, ok := routed(m, "pilot-team.qm.example.com"); !ok || matcher != "qm-pilot-team" {
		t.Errorf("the tenant's route = %q %v", matcher, ok)
	}
	// The hostname that shared the rule is untouched, and still points at
	// the backend it did before.
	if matcher, ok := routed(m, "other.qm.example.com"); !ok || matcher != "qm-legacy" {
		t.Errorf("a hostname that shared the rule was rerouted: %q %v", matcher, ok)
	}
	if svc, _ := matcherService(m, "qm-legacy"); svc != "legacy-backend" {
		t.Errorf("the shared matcher's backend changed to %q", svc)
	}
	if svc, ok := matcherService(m, "qm-pilot-team"); !ok || svc != "pilot-backend" {
		t.Errorf("the tenant's matcher = %q %v", svc, ok)
	}

	// And it is idempotent from there.
	if addRoute(m, "pilot-team.qm.example.com", "qm-pilot-team", "pilot-backend") {
		t.Error("re-adding the split route reported a change")
	}
}
