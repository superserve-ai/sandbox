//go:build integration

package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func hostHeartbeat(t *testing.T, r http.Handler, token, hostID, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/internal/hosts/"+hostID+"/heartbeat", strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

const hostDescription = `"vmd_addr":"10.9.0.7:50051","proxy_addr":"10.9.0.7:5007",` +
	`"region":"test-region","capacity_memory_mib":1024,"capacity_vcpus":8`

// cleanupHost removes the test's host row so a leftover 'active' host can
// never be picked by another test's scheduler (its address isn't dialable —
// a leaked active row makes unrelated sandbox creates flake).
func cleanupHost(t *testing.T, hostID string) {
	t.Helper()
	t.Cleanup(func() {
		if _, err := testPool.Exec(context.Background(),
			`DELETE FROM host WHERE id = $1`, hostID); err != nil {
			t.Errorf("cleanup host %s: %v", hostID, err)
		}
	})
}

// A heartbeat for an unknown host id carrying a self-description registers
// the host in 'provisioning' with its capabilities bound to the heartbeat;
// further heartbeats never promote it past provisioning on their own.
func TestIntegration_HostRegistration_SelfRegistersProvisioning(t *testing.T) {
	ctx := context.Background()
	t.Setenv("INTERNAL_API_TOKEN", "itok-hostreg")
	r := newRouter(t)
	hostID := "reg-" + strings.ToLower(t.Name()[len(t.Name())-8:])
	cleanupHost(t, hostID)

	w := hostHeartbeat(t, r, "itok-hostreg", hostID,
		`{"capabilities":["preview_ports_v1"],`+hostDescription+`}`)
	if w.Code != http.StatusOK {
		t.Fatalf("register heartbeat: %d %s", w.Code, w.Body.String())
	}
	if got := mustJSON(t, w)["status"]; got != "provisioning" {
		t.Fatalf("status = %v, want provisioning", got)
	}

	host, err := testQueries.GetHost(ctx, hostID)
	if err != nil {
		t.Fatalf("get host: %v", err)
	}
	if host.Status != "provisioning" || host.VmdAddr != "10.9.0.7:50051" {
		t.Fatalf("row = %s/%s, want provisioning/10.9.0.7:50051", host.Status, host.VmdAddr)
	}
	if !host.LastHeartbeatAt.Valid {
		t.Fatal("registration must stamp last_heartbeat_at (capability attestation keys on it)")
	}
	var bound bool
	if err := testPool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM host_capability
		  WHERE host_id = $1 AND capability = 'preview_ports_v1'
		    AND heartbeat_at = (SELECT last_heartbeat_at FROM host WHERE id = $1))`,
		hostID).Scan(&bound); err != nil {
		t.Fatalf("capability query: %v", err)
	}
	if !bound {
		t.Fatal("capability not bound to the registration heartbeat")
	}

	// A second heartbeat keeps it provisioning — no self-activation.
	w = hostHeartbeat(t, r, "itok-hostreg", hostID, `{"capabilities":[],`+hostDescription+`}`)
	if w.Code != http.StatusOK || mustJSON(t, w)["status"] != "provisioning" {
		t.Fatalf("second heartbeat: %d %v", w.Code, w.Body.String())
	}
}

// A heartbeat for an unknown host without a self-description keeps today's
// behavior: 404, nothing created. Legacy vmds cannot register implicitly.
func TestIntegration_HostRegistration_NoDescriptionIs404(t *testing.T) {
	t.Setenv("INTERNAL_API_TOKEN", "itok-hostreg")
	r := newRouter(t)

	w := hostHeartbeat(t, r, "itok-hostreg", "ghost-host", `{"capabilities":[]}`)
	if w.Code != http.StatusNotFound {
		t.Fatalf("heartbeat = %d, want 404", w.Code)
	}
	if _, err := testQueries.GetHost(context.Background(), "ghost-host"); err == nil {
		t.Fatal("host row must not be created without a description")
	}
}

// A live identity cannot be claimed from another address; a silent one can.
func TestIntegration_HostRegistration_IdentityConflictAndReclaim(t *testing.T) {
	ctx := context.Background()
	t.Setenv("INTERNAL_API_TOKEN", "itok-hostreg")
	r := newRouter(t)
	hostID := "dup-" + strings.ToLower(t.Name()[len(t.Name())-8:])
	cleanupHost(t, hostID)

	if w := hostHeartbeat(t, r, "itok-hostreg", hostID, `{`+hostDescription+`}`); w.Code != http.StatusOK {
		t.Fatalf("seed host: %d %s", w.Code, w.Body.String())
	}

	// Same id, different vmd_addr, holder still fresh → 409, row untouched.
	intruder := `"vmd_addr":"10.9.0.8:50051","proxy_addr":"10.9.0.8:5007",` +
		`"region":"test-region","capacity_memory_mib":1024,"capacity_vcpus":8`
	if w := hostHeartbeat(t, r, "itok-hostreg", hostID, `{`+intruder+`}`); w.Code != http.StatusConflict {
		t.Fatalf("live conflict = %d, want 409", w.Code)
	}
	host, _ := testQueries.GetHost(ctx, hostID)
	if host.VmdAddr != "10.9.0.7:50051" {
		t.Fatalf("conflict must not rewrite vmd_addr, got %s", host.VmdAddr)
	}

	// Holder goes silent past the unhealthy threshold → identity released.
	if _, err := testPool.Exec(ctx,
		`UPDATE host SET last_heartbeat_at = now() - interval '3 minutes' WHERE id = $1`,
		hostID); err != nil {
		t.Fatalf("age heartbeat: %v", err)
	}
	if w := hostHeartbeat(t, r, "itok-hostreg", hostID, `{`+intruder+`}`); w.Code != http.StatusOK {
		t.Fatalf("stale reclaim = %d, want 200", w.Code)
	}
	host, _ = testQueries.GetHost(ctx, hostID)
	if host.VmdAddr != "10.9.0.8:50051" {
		t.Fatalf("reclaim must update vmd_addr, got %s", host.VmdAddr)
	}
}

// The operator status endpoint: provisioning → active → draining, with
// machine-managed and unknown values rejected.
func TestIntegration_HostStatus_OperatorTransitions(t *testing.T) {
	t.Setenv("INTERNAL_API_TOKEN", "itok-hostreg")
	r := newRouter(t)
	hostID := "act-" + strings.ToLower(t.Name()[len(t.Name())-8:])
	cleanupHost(t, hostID)

	if w := hostHeartbeat(t, r, "itok-hostreg", hostID, `{`+hostDescription+`}`); w.Code != http.StatusOK {
		t.Fatalf("seed host: %d %s", w.Code, w.Body.String())
	}

	setStatus := func(id, status string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/internal/hosts/"+id+"/status",
			strings.NewReader(`{"status":"`+status+`"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer itok-hostreg")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	if w := setStatus(hostID, "active"); w.Code != http.StatusOK || mustJSON(t, w)["status"] != "active" {
		t.Fatalf("activate: %d %s", w.Code, w.Body.String())
	}
	if w := setStatus(hostID, "draining"); w.Code != http.StatusOK || mustJSON(t, w)["status"] != "draining" {
		t.Fatalf("drain: %d %s", w.Code, w.Body.String())
	}
	if w := setStatus(hostID, "provisioning"); w.Code != http.StatusBadRequest {
		t.Fatalf("machine-managed status must be rejected, got %d", w.Code)
	}
	if w := setStatus("no-such-host", "active"); w.Code != http.StatusNotFound {
		t.Fatalf("unknown host = %d, want 404", w.Code)
	}
}

// Activating a host whose heartbeat went stale must be refused: the
// unhealthy detector only watches active rows, so a dead provisioning host
// would otherwise sit exposed to placement until the detector's next pass.
// Draining a silent host stays allowed, and a fresh heartbeat re-enables
// activation.
func TestIntegration_HostActivateRequiresFreshHeartbeat(t *testing.T) {
	ctx := context.Background()
	t.Setenv("INTERNAL_API_TOKEN", "itok-hostreg")
	r := newRouter(t)
	hostID := "stl-" + strings.ToLower(t.Name()[len(t.Name())-8:])
	cleanupHost(t, hostID)

	if w := hostHeartbeat(t, r, "itok-hostreg", hostID, `{`+hostDescription+`}`); w.Code != http.StatusOK {
		t.Fatalf("seed host: %d %s", w.Code, w.Body.String())
	}
	if _, err := testPool.Exec(ctx,
		`UPDATE host SET last_heartbeat_at = now() - interval '3 minutes' WHERE id = $1`,
		hostID); err != nil {
		t.Fatalf("age heartbeat: %v", err)
	}

	setStatus := func(status string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/internal/hosts/"+hostID+"/status",
			strings.NewReader(`{"status":"`+status+`"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer itok-hostreg")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	if w := setStatus("active"); w.Code != http.StatusConflict {
		t.Fatalf("stale activate = %d %s, want 409", w.Code, w.Body.String())
	}
	if host, _ := testQueries.GetHost(ctx, hostID); host.Status != "provisioning" {
		t.Fatalf("refused activation must not change status, got %s", host.Status)
	}
	if w := setStatus("draining"); w.Code != http.StatusOK {
		t.Fatalf("stale drain = %d %s, want 200 (draining a dead host is legitimate)", w.Code, w.Body.String())
	}

	// A fresh heartbeat makes the host activatable again.
	if w := hostHeartbeat(t, r, "itok-hostreg", hostID, `{`+hostDescription+`}`); w.Code != http.StatusOK {
		t.Fatalf("revive heartbeat: %d %s", w.Code, w.Body.String())
	}
	if w := setStatus("active"); w.Code != http.StatusOK {
		t.Fatalf("fresh activate = %d %s, want 200", w.Code, w.Body.String())
	}
}

// The operator list shows every status, not just active.
func TestIntegration_HostList_IncludesProvisioning(t *testing.T) {
	t.Setenv("INTERNAL_API_TOKEN", "itok-hostreg")
	r := newRouter(t)
	hostID := "lst-" + strings.ToLower(t.Name()[len(t.Name())-8:])
	cleanupHost(t, hostID)

	if w := hostHeartbeat(t, r, "itok-hostreg", hostID, `{`+hostDescription+`}`); w.Code != http.StatusOK {
		t.Fatalf("seed host: %d %s", w.Code, w.Body.String())
	}

	req := httptest.NewRequest("GET", "/internal/hosts", nil)
	req.Header.Set("Authorization", "Bearer itok-hostreg")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"`+hostID+`"`) ||
		!strings.Contains(w.Body.String(), `"provisioning"`) {
		t.Fatalf("list missing provisioning host: %s", w.Body.String())
	}
}
