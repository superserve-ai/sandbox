//go:build integration

package integration

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"sync"
	"testing"
)

const egressTestSeed = "integration-egress-seed-32-bytes!!"

// A create that asks for egress rules must not succeed when the rules could
// not be applied: the VM would otherwise run with the default allow-all and
// the caller would never know.
func TestIntegration_CreateSandbox_NetworkApplyFailure_FailsClosed(t *testing.T) {
	teamID, apiKey := seedTeamAndKey(t)
	r := previewTokenIntegrationRouter(t, &stubVMD{updateNetworkFn: func(context.Context, string, []string, []string, []string) error {
		return errors.New("forced rule application failure")
	}}, []byte(egressTestSeed))

	cw := do(r, "POST", "/sandboxes", apiKey,
		`{"name":"net-fail-closed","network":{"allow_out":["api.example.com"],"deny_out":["0.0.0.0/0"]}}`)
	if cw.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when rules cannot be applied, got %d: %s", cw.Code, cw.Body.String())
	}

	var status string
	if err := testPool.QueryRow(context.Background(),
		`SELECT status FROM sandbox WHERE team_id=$1 AND name=$2`, teamID, "net-fail-closed",
	).Scan(&status); err != nil {
		t.Fatalf("read sandbox row: %v", err)
	}
	if status != "failed" {
		t.Errorf("sandbox status = %q, want failed", status)
	}
}

// Bare IPs are accepted on the wire but reach VMD (and the persisted config)
// as single-host prefixes, so the firewall can always apply them.
func TestIntegration_CreateSandbox_NetworkBareIPNormalized(t *testing.T) {
	_, apiKey := seedTeamAndKey(t)
	var mu sync.Mutex
	var gotAllowed, gotDenied, gotDomains []string
	r := previewTokenIntegrationRouter(t, &stubVMD{updateNetworkFn: func(_ context.Context, _ string, allowed, denied, domains []string) error {
		mu.Lock()
		defer mu.Unlock()
		gotAllowed, gotDenied, gotDomains = allowed, denied, domains
		return nil
	}}, []byte(egressTestSeed))

	cw := do(r, "POST", "/sandboxes", apiKey,
		`{"name":"net-bare-ip","network":{"allow_out":["203.0.113.7","198.51.100.0/24","api.example.com"],"deny_out":["0.0.0.0/0","203.0.113.9"]}}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}

	mu.Lock()
	allowed, denied, domains := gotAllowed, gotDenied, gotDomains
	mu.Unlock()
	if want := []string{"203.0.113.7/32", "198.51.100.0/24"}; !reflect.DeepEqual(allowed, want) {
		t.Errorf("VMD allowed CIDRs = %v, want %v", allowed, want)
	}
	if want := []string{"0.0.0.0/0", "203.0.113.9/32"}; !reflect.DeepEqual(denied, want) {
		t.Errorf("VMD denied CIDRs = %v, want %v", denied, want)
	}
	if want := []string{"api.example.com"}; !reflect.DeepEqual(domains, want) {
		t.Errorf("VMD domains = %v, want %v", domains, want)
	}

	// The read-back reflects the canonical form, and it is what a resume replays.
	sid := mustJSON(t, cw)["id"].(string)
	gw := do(r, "GET", "/sandboxes/"+sid, apiKey, "")
	if gw.Code != http.StatusOK {
		t.Fatalf("get: %d %s", gw.Code, gw.Body.String())
	}
	network, _ := mustJSON(t, gw)["network"].(map[string]interface{})
	if network == nil {
		t.Fatalf("no network in response: %s", gw.Body.String())
	}
	allowOut := stringsOf(network["allow_out"])
	for _, want := range []string{"203.0.113.7/32", "198.51.100.0/24", "api.example.com"} {
		if !containsString(allowOut, want) {
			t.Errorf("allow_out %v missing %q", allowOut, want)
		}
	}
	if containsString(allowOut, "203.0.113.7") {
		t.Errorf("allow_out %v still carries the bare IP", allowOut)
	}
}

func TestIntegration_PatchSandbox_NetworkBareIPNormalized(t *testing.T) {
	_, apiKey := seedTeamAndKey(t)
	var mu sync.Mutex
	var gotAllowed, gotDenied []string
	r := previewTokenIntegrationRouter(t, &stubVMD{updateNetworkFn: func(_ context.Context, _ string, allowed, denied, _ []string) error {
		mu.Lock()
		defer mu.Unlock()
		gotAllowed, gotDenied = allowed, denied
		return nil
	}}, []byte(egressTestSeed))

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"net-patch-bare-ip"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sid := mustJSON(t, cw)["id"].(string)

	pw := do(r, "PATCH", "/sandboxes/"+sid, apiKey,
		`{"network":{"allow_out":["203.0.113.7"],"deny_out":["203.0.113.9"]}}`)
	if pw.Code != http.StatusNoContent {
		t.Fatalf("patch: %d %s", pw.Code, pw.Body.String())
	}
	mu.Lock()
	allowed, denied := gotAllowed, gotDenied
	mu.Unlock()
	if want := []string{"203.0.113.7/32"}; !reflect.DeepEqual(allowed, want) {
		t.Errorf("VMD allowed CIDRs = %v, want %v", allowed, want)
	}
	if want := []string{"203.0.113.9/32"}; !reflect.DeepEqual(denied, want) {
		t.Errorf("VMD denied CIDRs = %v, want %v", denied, want)
	}
}

func stringsOf(v interface{}) []string {
	items, _ := v.([]interface{})
	out := make([]string, 0, len(items))
	for _, it := range items {
		if s, ok := it.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
