//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/db"
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
	t.Setenv("OPERATOR_API_TOKEN", "optok-hostreg")
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
	t.Setenv("OPERATOR_API_TOKEN", "optok-hostreg")
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
	t.Setenv("OPERATOR_API_TOKEN", "optok-hostreg")
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

	// Activate the holder so the reclaim's demotion below is meaningful.
	areq := httptest.NewRequest("POST", "/internal/hosts/"+hostID+"/status",
		strings.NewReader(`{"status":"active"}`))
	areq.Header.Set("Content-Type", "application/json")
	areq.Header.Set("Authorization", "Bearer optok-hostreg")
	aw := httptest.NewRecorder()
	r.ServeHTTP(aw, areq)
	if aw.Code != http.StatusOK {
		t.Fatalf("activate holder: %d %s", aw.Code, aw.Body.String())
	}

	// Holder goes silent past the unhealthy threshold → identity released,
	// but the claimant must NOT inherit the active status: every vmd shares
	// the internal token, so a reclaim is a re-registration that demotes to
	// provisioning until the operator re-approves.
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
	if host.Status != "provisioning" {
		t.Fatalf("reclaimed identity status = %s, want provisioning (no self-approval)", host.Status)
	}
}

// The operator status endpoint: provisioning → active → draining, with
// machine-managed and unknown values rejected.
func TestIntegration_HostStatus_OperatorTransitions(t *testing.T) {
	t.Setenv("INTERNAL_API_TOKEN", "itok-hostreg")
	t.Setenv("OPERATOR_API_TOKEN", "optok-hostreg")
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
		req.Header.Set("Authorization", "Bearer optok-hostreg")
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
	t.Setenv("OPERATOR_API_TOKEN", "optok-hostreg")
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
		req.Header.Set("Authorization", "Bearer optok-hostreg")
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

// The operator list shows every status, not just active, and counts
// in-flight template builds so drain progress can see build VMs.
func TestIntegration_HostList_IncludesProvisioningAndBuilds(t *testing.T) {
	ctx := context.Background()
	_, apiKey := seedTeamAndKey(t)
	t.Setenv("INTERNAL_API_TOKEN", "itok-hostreg")
	t.Setenv("OPERATOR_API_TOKEN", "optok-hostreg")
	r := newRouter(t)
	hostID := "lst-" + strings.ToLower(t.Name()[len(t.Name())-8:])
	cleanupHost(t, hostID)

	if w := hostHeartbeat(t, r, "itok-hostreg", hostID, `{`+hostDescription+`}`); w.Code != http.StatusOK {
		t.Fatalf("seed host: %d %s", w.Code, w.Body.String())
	}

	// A template submit auto-creates a pending build; move it onto this
	// host in 'building' to simulate an in-flight build VM.
	tw := do(r, "POST", "/templates", apiKey,
		`{"name":"hostlist-build-probe","build_spec":{"from":"debian:12-slim","steps":[]}}`)
	if tw.Code != http.StatusAccepted {
		t.Fatalf("create template: %d %s", tw.Code, tw.Body.String())
	}
	templateID := mustJSON(t, tw)["id"].(string)
	if _, err := testPool.Exec(ctx,
		`UPDATE template_build SET status = 'building', vmd_host_id = $2 WHERE template_id = $1`,
		templateID, hostID); err != nil {
		t.Fatalf("mark build in-flight: %v", err)
	}

	req := httptest.NewRequest("GET", "/internal/hosts", nil)
	req.Header.Set("Authorization", "Bearer optok-hostreg")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `"`+hostID+`"`) || !strings.Contains(body, `"provisioning"`) {
		t.Fatalf("list missing provisioning host: %s", body)
	}
	var out struct {
		Hosts []struct {
			ID            string `json:"id"`
			BuildingCount int32  `json:"building_count"`
		} `json:"hosts"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	for _, h := range out.Hosts {
		if h.ID == hostID {
			if h.BuildingCount != 1 {
				t.Fatalf("building_count = %d, want 1 (in-flight build must show in drain progress)", h.BuildingCount)
			}
			return
		}
	}
	t.Fatalf("host %s not in list", hostID)
}

// Host lifecycle approval must not be reachable with the credential the
// hosts themselves hold: the vmd-held internal token gets 401 on operator
// endpoints (a self-registered host cannot approve itself), and the
// operator token gets 401 on the heartbeat.
func TestIntegration_HostStatus_RequiresOperatorCredential(t *testing.T) {
	t.Setenv("INTERNAL_API_TOKEN", "itok-hostreg")
	t.Setenv("OPERATOR_API_TOKEN", "optok-hostreg")
	r := newRouter(t)
	hostID := "sec-" + strings.ToLower(t.Name()[len(t.Name())-8:])
	cleanupHost(t, hostID)

	if w := hostHeartbeat(t, r, "itok-hostreg", hostID, `{`+hostDescription+`}`); w.Code != http.StatusOK {
		t.Fatalf("seed host: %d %s", w.Code, w.Body.String())
	}

	// The vmd credential must not activate the host it registered.
	req := httptest.NewRequest("POST", "/internal/hosts/"+hostID+"/status",
		strings.NewReader(`{"status":"active"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer itok-hostreg")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("internal token on status = %d, want 401", w.Code)
	}
	if host, _ := testQueries.GetHost(context.Background(), hostID); host.Status != "provisioning" {
		t.Fatalf("status = %s, want provisioning untouched", host.Status)
	}

	// And the operator credential is not a heartbeat credential.
	if w := hostHeartbeat(t, r, "optok-hostreg", hostID, `{`+hostDescription+`}`); w.Code != http.StatusUnauthorized {
		t.Fatalf("operator token on heartbeat = %d, want 401", w.Code)
	}
}

// The build claim itself re-asserts host status: a drain landing between
// the supervisor's pre-check and the claim must lose — TryDispatchBuild
// refuses to move a pending build onto a non-active host. A missing host
// row (bootstrap mode) keeps dispatching.
func TestIntegration_TryDispatchBuildRefusesNonActiveHost(t *testing.T) {
	ctx := context.Background()
	_, apiKey := seedTeamAndKey(t)
	t.Setenv("INTERNAL_API_TOKEN", "itok-hostreg")
	t.Setenv("OPERATOR_API_TOKEN", "optok-hostreg")
	r := newRouter(t)
	hostID := "bld-" + strings.ToLower(t.Name()[len(t.Name())-8:])
	cleanupHost(t, hostID)

	if w := hostHeartbeat(t, r, "itok-hostreg", hostID, `{`+hostDescription+`}`); w.Code != http.StatusOK {
		t.Fatalf("seed host: %d %s", w.Code, w.Body.String())
	}
	if _, err := testPool.Exec(ctx,
		`UPDATE host SET status = 'draining' WHERE id = $1`, hostID); err != nil {
		t.Fatalf("drain host: %v", err)
	}

	tw := do(r, "POST", "/templates", apiKey,
		`{"name":"dispatch-gate-probe","build_spec":{"from":"debian:12-slim","steps":[]}}`)
	if tw.Code != http.StatusAccepted {
		t.Fatalf("create template: %d %s", tw.Code, tw.Body.String())
	}
	templateID := mustJSON(t, tw)["id"].(string)
	var buildID uuid.UUID
	if err := testPool.QueryRow(ctx,
		`SELECT id FROM template_build WHERE template_id = $1`, templateID).Scan(&buildID); err != nil {
		t.Fatalf("find pending build: %v", err)
	}

	vmID := "build-" + buildID.String()
	claim := func(host string) int64 {
		n, err := testQueries.TryDispatchBuild(ctx, db.TryDispatchBuildParams{
			ID: buildID, VmdHostID: &host, VmdBuildVmID: &vmID,
		})
		if err != nil {
			t.Fatalf("TryDispatchBuild(%s): %v", host, err)
		}
		return n
	}

	if n := claim(hostID); n != 0 {
		t.Fatalf("claim on draining host = %d rows, want 0", n)
	}
	if _, err := testPool.Exec(ctx,
		`UPDATE host SET status = 'active' WHERE id = $1`, hostID); err != nil {
		t.Fatalf("activate host: %v", err)
	}
	if n := claim(hostID); n != 1 {
		t.Fatalf("claim on active host = %d rows, want 1", n)
	}

	// Bootstrap parity: a host id with no row dispatches. Reset the build to
	// pending first (it was just claimed).
	if _, err := testPool.Exec(ctx,
		`UPDATE template_build SET status = 'pending', vmd_host_id = NULL WHERE id = $1`,
		buildID); err != nil {
		t.Fatalf("reset build: %v", err)
	}
	if n := claim("no-such-host"); n != 1 {
		t.Fatalf("claim with missing host row = %d rows, want 1 (bootstrap)", n)
	}
}

// Once an identity is bound (registration, reclaim, or opt-in), a
// description-less heartbeat is rejected WITHOUT mutating the row: after B
// reclaims A's id, old daemon A — whose legacy sender omits the description
// entirely — must not keep refreshing liveness or capabilities on a row
// that now belongs to B.
func TestIntegration_HostIdentityBound_RejectsLegacyHeartbeatAfterReclaim(t *testing.T) {
	ctx := context.Background()
	t.Setenv("INTERNAL_API_TOKEN", "itok-hostreg")
	t.Setenv("OPERATOR_API_TOKEN", "optok-hostreg")
	r := newRouter(t)
	hostID := "bnd-" + strings.ToLower(t.Name()[len(t.Name())-8:])
	cleanupHost(t, hostID)

	// A self-registers: the identity is bound from birth.
	if w := hostHeartbeat(t, r, "itok-hostreg", hostID, `{"capabilities":["preview_ports_v1"],`+hostDescription+`}`); w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	host, _ := testQueries.GetHost(ctx, hostID)
	if !host.IdentityBound {
		t.Fatal("self-registration must bind the identity")
	}

	// B reclaims after A goes silent.
	if _, err := testPool.Exec(ctx,
		`UPDATE host SET last_heartbeat_at = now() - interval '3 minutes' WHERE id = $1`, hostID); err != nil {
		t.Fatalf("age heartbeat: %v", err)
	}
	intruder := `"vmd_addr":"10.9.0.8:50051","proxy_addr":"10.9.0.8:5007",` +
		`"region":"test-region","capacity_memory_mib":1024,"capacity_vcpus":8`
	if w := hostHeartbeat(t, r, "itok-hostreg", hostID, `{"capabilities":["preview_ports_v1"],`+intruder+`}`); w.Code != http.StatusOK {
		t.Fatalf("reclaim: %d %s", w.Code, w.Body.String())
	}
	before, _ := testQueries.GetHost(ctx, hostID)
	var capsBefore int
	if err := testPool.QueryRow(ctx,
		`SELECT COUNT(*) FROM host_capability WHERE host_id = $1`, hostID).Scan(&capsBefore); err != nil {
		t.Fatalf("count capabilities: %v", err)
	}

	// Old daemon A resumes its legacy, description-less heartbeat: rejected,
	// and nothing about the row moves — not liveness, not status, not caps.
	if w := hostHeartbeat(t, r, "itok-hostreg", hostID, `{"capabilities":[]}`); w.Code != http.StatusConflict {
		t.Fatalf("legacy heartbeat on bound identity = %d, want 409", w.Code)
	}
	after, _ := testQueries.GetHost(ctx, hostID)
	if !after.LastHeartbeatAt.Time.Equal(before.LastHeartbeatAt.Time) {
		t.Fatal("rejected heartbeat must not refresh last_heartbeat_at")
	}
	if after.Status != before.Status || after.VmdAddr != before.VmdAddr {
		t.Fatalf("rejected heartbeat mutated row: %s/%s -> %s/%s",
			before.Status, before.VmdAddr, after.Status, after.VmdAddr)
	}
	var capsAfter int
	if err := testPool.QueryRow(ctx,
		`SELECT COUNT(*) FROM host_capability WHERE host_id = $1`, hostID).Scan(&capsAfter); err != nil {
		t.Fatalf("count capabilities: %v", err)
	}
	if capsAfter != capsBefore {
		t.Fatalf("rejected heartbeat changed capabilities: %d -> %d", capsBefore, capsAfter)
	}
}

// Legacy rows (hand-created, never described) keep accepting description-less
// heartbeats until their holder opts in with a complete description at the
// current address — after which legacy heartbeats are rejected for good.
func TestIntegration_HostIdentityOptIn(t *testing.T) {
	ctx := context.Background()
	t.Setenv("INTERNAL_API_TOKEN", "itok-hostreg")
	t.Setenv("OPERATOR_API_TOKEN", "optok-hostreg")
	r := newRouter(t)
	hostID := "opt-" + strings.ToLower(t.Name()[len(t.Name())-8:])
	cleanupHost(t, hostID)

	if _, err := testQueries.CreateHost(ctx, db.CreateHostParams{
		ID: hostID, VmdAddr: "10.9.0.7:50051", ProxyAddr: "10.9.0.7:5007",
		Region: "test-region", CapacityMemoryMib: 1024, CapacityVcpus: 8,
	}); err != nil {
		t.Fatalf("create legacy host: %v", err)
	}

	// Legacy heartbeat accepted while unbound — today's fleet behavior.
	if w := hostHeartbeat(t, r, "itok-hostreg", hostID, `{"capabilities":[]}`); w.Code != http.StatusOK {
		t.Fatalf("legacy heartbeat on unbound row = %d, want 200", w.Code)
	}
	// A complete description at the current address binds the identity.
	if w := hostHeartbeat(t, r, "itok-hostreg", hostID, `{`+hostDescription+`}`); w.Code != http.StatusOK {
		t.Fatalf("opt-in heartbeat = %d, want 200", w.Code)
	}
	host, _ := testQueries.GetHost(ctx, hostID)
	if !host.IdentityBound {
		t.Fatal("complete description at current address must bind the identity")
	}
	// From here, description-less heartbeats are rejected.
	if w := hostHeartbeat(t, r, "itok-hostreg", hostID, `{"capabilities":[]}`); w.Code != http.StatusConflict {
		t.Fatalf("legacy heartbeat on bound row = %d, want 409", w.Code)
	}
}

// UNBACKED counts the paused sandboxes whose ONLY copy is the host's local
// disk — no durable backup generation anywhere. A durable copy moves a
// sandbox out of the count; it is the number that must be zero before
// retiring a machine is even discussable.
func TestIntegration_HostList_CountsUnbackedPaused(t *testing.T) {
	ctx := context.Background()
	_, apiKey := seedTeamAndKey(t)
	t.Setenv("INTERNAL_API_TOKEN", "itok-hostreg")
	t.Setenv("OPERATOR_API_TOKEN", "optok-hostreg")
	r := newRouter(t)
	hostID := "ubk-" + strings.ToLower(t.Name()[len(t.Name())-8:])
	cleanupHost(t, hostID)

	if w := hostHeartbeat(t, r, "itok-hostreg", hostID, `{`+hostDescription+`}`); w.Code != http.StatusOK {
		t.Fatalf("seed host: %d %s", w.Code, w.Body.String())
	}
	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"unbacked-probe"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create sandbox: %d %s", cw.Code, cw.Body.String())
	}
	sandboxID := mustJSON(t, cw)["id"].(string)
	// Pause with a head snapshot row, its pause-time manifest, AND the
	// pause token FinalizePause stores: reports naming that token match
	// the STRONG identity path; tokenless reports fall back to content.
	shaA, shaB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	if _, err := testPool.Exec(ctx,
		`WITH snap AS (
		   INSERT INTO snapshot (sandbox_id, team_id, path, trigger, pause_token)
		   SELECT id, team_id, '/snap/rootfs', 'pause', 'tok-1' FROM sandbox WHERE id = $1
		   RETURNING id
		 ),
		 manifest AS (
		   INSERT INTO artifact_manifest (snapshot_id, file_name, path, size_bytes, sha256)
		   SELECT id, 'vmstate.snap', '/snap/vmstate.snap', 1, $3 FROM snap
		 )
		 UPDATE sandbox SET status = 'paused', host_id = $2,
		        snapshot_id = (SELECT id FROM snap)
		 WHERE id = $1`,
		sandboxID, hostID, shaA); err != nil {
		t.Fatalf("pin paused sandbox: %v", err)
	}

	counts := func() (paused, unbacked int32) {
		// The scoped form drain polling uses: only the target host's row
		// comes back, so the counts asserted below are also proof the
		// filter path computes them correctly.
		req := httptest.NewRequest("GET", "/internal/hosts?id="+hostID, nil)
		req.Header.Set("Authorization", "Bearer optok-hostreg")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("list: %d %s", w.Code, w.Body.String())
		}
		var out struct {
			Hosts []struct {
				ID             string `json:"id"`
				PausedCount    int32  `json:"paused_count"`
				PausedUnbacked int32  `json:"paused_unbacked_count"`
			} `json:"hosts"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(out.Hosts) != 1 || out.Hosts[0].ID != hostID {
			t.Fatalf("filtered list returned %d hosts, want exactly %s", len(out.Hosts), hostID)
		}
		return out.Hosts[0].PausedCount, out.Hosts[0].PausedUnbacked
	}

	if paused, unbacked := counts(); paused != 1 || unbacked != 1 {
		t.Fatalf("before backup: paused=%d unbacked=%d, want 1/1", paused, unbacked)
	}

	// Reports go through the REAL handler: coverage is only ever linked to
	// a pause by ReportHostBackup's under-lock identity match, and this
	// test must exercise that code, not hand-write its conclusions.
	report := func(genKey, vmstateSHA, rootfsSHA, pauseToken string) {
		t.Helper()
		tokenField := ""
		if pauseToken != "" {
			tokenField = fmt.Sprintf(`"pause_token":%q,`, pauseToken)
		}
		body := fmt.Sprintf(`{"sandbox_id":%q,"generation":%q,"bucket":"cell-bucket","completed_at":%q,%s"files":[{"name":"vmstate.snap","size_bytes":1,"sha256":%q},{"name":"rootfs.ext4","size_bytes":1,"sha256":%q}]}`,
			sandboxID, genKey, time.Now().UTC().Format(time.RFC3339), tokenField, vmstateSHA, rootfsSHA)
		req := httptest.NewRequest("POST", "/internal/hosts/"+hostID+"/backups", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer itok-hostreg")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("report backup: %d %s", w.Code, w.Body.String())
		}
	}
	shaX, shaY := strings.Repeat("d", 64), strings.Repeat("e", 64)

	// A verified report carrying this pause's token arrives: the handler
	// links the generation via the STRONG identity path and the sandbox
	// leaves the unbacked class.
	report(strings.Repeat("1", 64), shaA, shaX, "tok-1")
	if paused, unbacked := counts(); paused != 1 || unbacked != 0 {
		t.Fatalf("after backup: paused=%d unbacked=%d, want 1/0", paused, unbacked)
	}

	// Resume + re-pause: the finalize rewrites the manifest digests,
	// advances the snapshot's generation counter (legacy mode reuses the
	// row id — the counter is what names the pause), and stores the new
	// pause's token. Every earlier link now points at a pause that no
	// longer exists.
	if _, err := testPool.Exec(ctx,
		`WITH snap AS (
		   UPDATE snapshot SET generation = generation + 1, pause_token = 'tok-2'
		   WHERE id = (SELECT snapshot_id FROM sandbox WHERE id = $1)
		   RETURNING id
		 )
		 UPDATE artifact_manifest SET sha256 = $2
		 WHERE snapshot_id IN (SELECT id FROM snap)`,
		sandboxID, shaB); err != nil {
		t.Fatalf("advance to a new pause: %v", err)
	}
	if paused, unbacked := counts(); paused != 1 || unbacked != 1 {
		t.Fatalf("after re-pause: paused=%d unbacked=%d, want 1/1 (stale link must not count as coverage)", paused, unbacked)
	}

	// The previous pause's report, delayed in the outbox, redelivers
	// AFTER the re-pause. Token AND content both mismatch; nothing links.
	report(strings.Repeat("1", 64), shaA, shaX, "tok-1")
	if paused, unbacked := counts(); paused != 1 || unbacked != 1 {
		t.Fatalf("after delayed stale report: paused=%d unbacked=%d, want 1/1 (late delivery of old content must not fake coverage)", paused, unbacked)
	}

	// The collision attack the token exists to stop: a delayed report
	// whose CONTENT coincides with the current manifest (pause-time
	// manifests are vmstate-only, so only the vmstate digest must
	// collide) but whose token names the previous pause. Content says
	// covered; the token conflict vetoes it.
	report(strings.Repeat("3", 64), shaB, shaX, "tok-1")
	if paused, unbacked := counts(); paused != 1 || unbacked != 1 {
		t.Fatalf("after token-conflict report: paused=%d unbacked=%d, want 1/1 (digest coincidence must not fake coverage)", paused, unbacked)
	}

	// A tokenless report against a TOKENED snapshot: rejected. A tokened
	// pause's own report always carries the echoed token, so a tokenless
	// one is necessarily some other pause's — content match or not.
	report(strings.Repeat("2", 64), shaB, shaY, "")
	if paused, unbacked := counts(); paused != 1 || unbacked != 1 {
		t.Fatalf("after tokenless report on tokened snapshot: paused=%d unbacked=%d, want 1/1", paused, unbacked)
	}

	// The current pause's own report, carrying its token: covered.
	report(strings.Repeat("4", 64), shaB, shaY, "tok-2")
	if paused, unbacked := counts(); paused != 1 || unbacked != 0 {
		t.Fatalf("after current-pause backup: paused=%d unbacked=%d, want 1/0", paused, unbacked)
	}

	// A pause finalized WITHOUT a token (older daemon, or an old
	// control-plane replica): its tokenless report must stay unlinked
	// even on a perfect content match. There is no tokenless fallback —
	// vmstate-only manifests are the same evidence the migration refused
	// to backfill from, and the count over-reports until the sandbox
	// pauses through the token path.
	if _, err := testPool.Exec(ctx,
		`WITH snap AS (
		   UPDATE snapshot SET generation = generation + 1, pause_token = NULL
		   WHERE id = (SELECT snapshot_id FROM sandbox WHERE id = $1)
		   RETURNING id
		 )
		 UPDATE artifact_manifest SET sha256 = $2
		 WHERE snapshot_id IN (SELECT id FROM snap)`,
		sandboxID, strings.Repeat("f", 64)); err != nil {
		t.Fatalf("advance to a tokenless pause: %v", err)
	}
	report(strings.Repeat("5", 64), strings.Repeat("f", 64), shaY, "")
	if paused, unbacked := counts(); paused != 1 || unbacked != 1 {
		t.Fatalf("after tokenless content-matched report: paused=%d unbacked=%d, want 1/1 (no tokenless links)", paused, unbacked)
	}

	// The rolling-deploy hazard: an old replica's legacy finalize does
	// not mention pause_token, so the PREVIOUS pause's token would ride
	// under the rewritten artifacts. First give the row a token again
	// (a new-replica pause)...
	if _, err := testPool.Exec(ctx,
		`WITH snap AS (
		   UPDATE snapshot SET generation = generation + 1, pause_token = 'tok-3'
		   WHERE id = (SELECT snapshot_id FROM sandbox WHERE id = $1)
		   RETURNING id
		 )
		 UPDATE artifact_manifest SET sha256 = $2
		 WHERE snapshot_id IN (SELECT id FROM snap)`,
		sandboxID, shaB); err != nil {
		t.Fatalf("tokened pause: %v", err)
	}
	// ...then the old-writer signature: generation advances, the token
	// column untouched. The migration's trigger must clear it. The
	// manifest keeps the SAME vmstate digest — the collision case where
	// the old pause's delayed report would otherwise match both the
	// preserved token and the vmstate-only manifest.
	if _, err := testPool.Exec(ctx,
		`UPDATE snapshot SET generation = generation + 1
		 WHERE id = (SELECT snapshot_id FROM sandbox WHERE id = $1)`,
		sandboxID); err != nil {
		t.Fatalf("simulate legacy-upsert: %v", err)
	}
	var storedToken *string
	if err := testPool.QueryRow(ctx,
		`SELECT pause_token FROM snapshot WHERE id = (SELECT snapshot_id FROM sandbox WHERE id = $1)`,
		sandboxID).Scan(&storedToken); err != nil {
		t.Fatalf("read token: %v", err)
	}
	if storedToken != nil {
		t.Fatalf("preserved token survived a legacy-style generation advance: %q", *storedToken)
	}
	// The old pause's delayed report: its token matches what the row
	// WOULD have preserved, and its vmstate digest collides with the
	// unchanged manifest. Cleared token means asymmetry — refused.
	report(strings.Repeat("6", 64), shaB, shaY, "tok-3")
	if paused, unbacked := counts(); paused != 1 || unbacked != 1 {
		t.Fatalf("delayed report linked through a preserved token: paused=%d unbacked=%d, want 1/1", paused, unbacked)
	}
}

// The stale-build reap is the bound on requeued dispatch retries, so it
// must be complete: a timed-out build fails its never-ready template too
// (a template stuck in 'building' forever is not a bound), while a
// template that already reached 'ready' keeps its status.

// The stale-build reap is the bound on requeued dispatch retries, so it
// must be complete: a timed-out build fails its never-ready template too
// (a template stuck in 'building' forever is not a bound), while a
// template that already reached 'ready' keeps its status.
func TestIntegration_ReapStaleBuilds_FailsNeverReadyTemplate(t *testing.T) {
	ctx := context.Background()
	_, apiKey := seedTeamAndKey(t)
	t.Setenv("INTERNAL_API_TOKEN", "itok-hostreg")
	t.Setenv("OPERATOR_API_TOKEN", "optok-hostreg")
	r := newRouter(t)

	tw := do(r, "POST", "/templates", apiKey,
		`{"name":"reap-template-probe","build_spec":{"from":"debian:12-slim","steps":[]}}`)
	if tw.Code != http.StatusAccepted {
		t.Fatalf("create template: %d %s", tw.Code, tw.Body.String())
	}
	templateID := mustJSON(t, tw)["id"].(string)

	// Age the pending build past the reap's pending timeout.
	if _, err := testPool.Exec(ctx,
		`UPDATE template_build SET created_at = now() - interval '10 minutes' WHERE template_id = $1`,
		templateID); err != nil {
		t.Fatalf("age build: %v", err)
	}

	reaped, err := testQueries.ReapStaleBuilds(ctx, db.ReapStaleBuildsParams{
		Limit: 20, PendingTimeoutSeconds: 120, BuildTimeoutSeconds: 1800,
	})
	if err != nil {
		t.Fatalf("reap: %v", err)
	}
	found := false
	for _, row := range reaped {
		if row.TemplateID.String() == templateID {
			found = true
		}
	}
	if !found {
		t.Fatalf("aged build not reaped (reaped %d rows)", len(reaped))
	}

	var buildStatus, templateStatus string
	if err := testPool.QueryRow(ctx,
		`SELECT tb.status::text, t.status::text FROM template_build tb
		 JOIN template t ON t.id = tb.template_id WHERE tb.template_id = $1`,
		templateID).Scan(&buildStatus, &templateStatus); err != nil {
		t.Fatalf("read statuses: %v", err)
	}
	if buildStatus != "failed" || templateStatus != "failed" {
		t.Fatalf("after reap: build=%s template=%s, want failed/failed", buildStatus, templateStatus)
	}

	// A template that already reached 'ready' keeps it when a later build
	// times out.
	if _, err := testPool.Exec(ctx,
		`UPDATE template SET status = 'ready', error_message = NULL WHERE id = $1`,
		templateID); err != nil {
		t.Fatalf("mark ready: %v", err)
	}
	if _, err := testPool.Exec(ctx,
		`UPDATE template_build SET status = 'pending', finalized_at = NULL,
		 created_at = now() - interval '10 minutes' WHERE template_id = $1`,
		templateID); err != nil {
		t.Fatalf("stage second stale build: %v", err)
	}
	if _, err := testQueries.ReapStaleBuilds(ctx, db.ReapStaleBuildsParams{
		Limit: 20, PendingTimeoutSeconds: 120, BuildTimeoutSeconds: 1800,
	}); err != nil {
		t.Fatalf("second reap: %v", err)
	}
	if err := testPool.QueryRow(ctx,
		`SELECT status::text FROM template WHERE id = $1`, templateID).Scan(&templateStatus); err != nil {
		t.Fatalf("read template: %v", err)
	}
	if templateStatus != "ready" {
		t.Fatalf("ready template after build timeout = %s, want ready untouched", templateStatus)
	}
}

// The pressure endpoint upserts identity-fenced telemetry: only the
// address holding the host identity may write, the row is wholesale
// last-write-wins with a DB-clock reported_at, a reclaim clears it, and
// the admin view carries it (null for hosts that never published).
func TestIntegration_HostPressureLifecycle(t *testing.T) {
	ctx := context.Background()
	t.Setenv("INTERNAL_API_TOKEN", "itok-hostreg")
	t.Setenv("OPERATOR_API_TOKEN", "optok-hostreg")
	r := newRouter(t)
	hostID := "prs-" + strings.ToLower(t.Name()[len(t.Name())-8:])
	cleanupHost(t, hostID)

	// Self-register the host, then publish pressure from its address.
	if w := hostHeartbeat(t, r, "itok-hostreg", hostID, `{"capabilities":[],`+hostDescription+`}`); w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	pressure := func(vmdAddr string, running int) *httptest.ResponseRecorder {
		body := fmt.Sprintf(`{"vmd_addr":%q,"running_sandboxes":%d,"provisioning_sandboxes":1,"paused_sandboxes":2,"allocated_memory_mib":4096,"allocated_vcpus":6,"used_net_slots":9,"provisioning_net_slots":1,"warm_net_slots":32,"net_slot_ceiling":65000,"max_network_slots":500,"max_sandboxes":40}`, vmdAddr, running)
		req := httptest.NewRequest("PUT", "/internal/hosts/"+hostID+"/pressure", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer itok-hostreg")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	if w := pressure("10.9.0.7:50051", 5); w.Code != http.StatusOK {
		t.Fatalf("pressure: %d %s", w.Code, w.Body.String())
	}
	var running, maxSandboxes int
	var reportedAge float64
	if err := testPool.QueryRow(ctx,
		`SELECT running_sandboxes, max_sandboxes,
		        EXTRACT(EPOCH FROM (now() - reported_at))
		 FROM host_pressure WHERE host_id = $1`, hostID).
		Scan(&running, &maxSandboxes, &reportedAge); err != nil {
		t.Fatalf("read pressure row: %v", err)
	}
	if running != 5 || maxSandboxes != 40 {
		t.Fatalf("row = running %d max %d, want 5/40", running, maxSandboxes)
	}
	if reportedAge < 0 || reportedAge > 60 {
		t.Fatalf("reported_at age = %fs, want DB-clock recent", reportedAge)
	}

	// Wrong address: identity fence refuses, row untouched.
	if w := pressure("10.9.9.9:50051", 99); w.Code != http.StatusConflict {
		t.Fatalf("mismatched addr = %d, want 409", w.Code)
	}
	if err := testPool.QueryRow(ctx,
		`SELECT running_sandboxes FROM host_pressure WHERE host_id = $1`, hostID).
		Scan(&running); err != nil || running != 5 {
		t.Fatalf("row after fenced write: running=%d err=%v, want 5 untouched", running, err)
	}

	// Last-write-wins from the holder.
	if w := pressure("10.9.0.7:50051", 8); w.Code != http.StatusOK {
		t.Fatalf("second pressure: %d %s", w.Code, w.Body.String())
	}

	// Admin view carries it.
	req := httptest.NewRequest("GET", "/internal/hosts", nil)
	req.Header.Set("Authorization", "Bearer optok-hostreg")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		Hosts []struct {
			ID              string `json:"id"`
			PressureRunning *int32 `json:"pressure_running_sandboxes"`
			PressureMem     *int64 `json:"pressure_allocated_memory_mib"`
		} `json:"hosts"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	found := false
	for _, h := range out.Hosts {
		if h.ID != hostID {
			continue
		}
		found = true
		if h.PressureRunning == nil || *h.PressureRunning != 8 || h.PressureMem == nil || *h.PressureMem != 4096 {
			t.Fatalf("admin pressure = %+v, want running 8 mem 4096", h)
		}
	}
	if !found {
		t.Fatalf("host %s not in admin list", hostID)
	}

	// A reclaim from a new address (old holder stale) clears pressure:
	// the old machine's numbers mean nothing for the new holder.
	if _, err := testPool.Exec(ctx,
		`UPDATE host SET last_heartbeat_at = now() - interval '10 minutes' WHERE id = $1`, hostID); err != nil {
		t.Fatalf("age heartbeat: %v", err)
	}
	reclaimDesc := `"vmd_addr":"10.9.0.8:50051","proxy_addr":"10.9.0.8:5007",` +
		`"region":"test-region","capacity_memory_mib":1024,"capacity_vcpus":8`
	if w := hostHeartbeat(t, r, "itok-hostreg", hostID, `{"capabilities":[],`+reclaimDesc+`}`); w.Code != http.StatusOK {
		t.Fatalf("reclaim heartbeat: %d %s", w.Code, w.Body.String())
	}
	var count int
	if err := testPool.QueryRow(ctx,
		`SELECT COUNT(*) FROM host_pressure WHERE host_id = $1`, hostID).Scan(&count); err != nil {
		t.Fatalf("count pressure rows: %v", err)
	}
	if count != 0 {
		t.Fatal("pressure row survived identity reclaim")
	}
}

// A pressure write concurrent with an identity reclaim must serialize:
// FOR SHARE on the host row means either the reclaim waits for the write
// (then deletes it in its own transaction), or the write waits for the
// reclaim (then matches nothing on the new address). Stale pressure must
// never survive a reclaim.

// A pressure write concurrent with an identity reclaim must serialize:
// FOR SHARE on the host row means either the reclaim waits for the write
// (then deletes it in its own transaction), or the write waits for the
// reclaim (then matches nothing on the new address). Stale pressure must
// never survive a reclaim.
func TestIntegration_HostPressureSerializesWithReclaim(t *testing.T) {
	ctx := context.Background()
	t.Setenv("INTERNAL_API_TOKEN", "itok-hostreg")
	r := newRouter(t)
	hostID := "prc-" + strings.ToLower(t.Name()[len(t.Name())-8:])
	cleanupHost(t, hostID)

	if w := hostHeartbeat(t, r, "itok-hostreg", hostID, `{"capabilities":[],`+hostDescription+`}`); w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	// Make the current holder stale so a new address may reclaim.
	if _, err := testPool.Exec(ctx,
		`UPDATE host SET last_heartbeat_at = now() - interval '10 minutes' WHERE id = $1`, hostID); err != nil {
		t.Fatalf("age heartbeat: %v", err)
	}

	// Transaction A: take the pressure statement's FOR SHARE lock on the
	// host row at the OLD address and hold it open — the mid-statement
	// pause the race needs.
	txA, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer txA.Rollback(ctx)
	var lockedID string
	if err := txA.QueryRow(ctx,
		`SELECT id FROM host WHERE id = $1 AND vmd_addr = '10.9.0.7:50051' FOR SHARE`, hostID).
		Scan(&lockedID); err != nil {
		t.Fatalf("take FOR SHARE: %v", err)
	}

	// Concurrently: a reclaim heartbeat from a new address. Its FOR UPDATE
	// must block behind A's FOR SHARE.
	reclaimDone := make(chan int, 1)
	go func() {
		desc := `"vmd_addr":"10.9.0.9:50051","proxy_addr":"10.9.0.9:5007",` +
			`"region":"test-region","capacity_memory_mib":1024,"capacity_vcpus":8`
		w := hostHeartbeat(t, r, "itok-hostreg", hostID, `{"capabilities":[],`+desc+`}`)
		reclaimDone <- w.Code
	}()
	select {
	case code := <-reclaimDone:
		t.Fatalf("reclaim completed (%d) while pressure held FOR SHARE — no serialization", code)
	case <-time.After(300 * time.Millisecond):
		// Blocked, as required.
	}

	// A completes its pressure write under the lock, then commits.
	if _, err := txA.Exec(ctx,
		`INSERT INTO host_pressure (host_id, running_sandboxes, provisioning_sandboxes,
		   paused_sandboxes, allocated_memory_mib, allocated_vcpus, used_net_slots,
		   provisioning_net_slots, warm_net_slots, net_slot_ceiling)
		 VALUES ($1, 3, 0, 0, 1024, 2, 3, 0, 8, 65000)`, hostID); err != nil {
		t.Fatalf("pressure insert under lock: %v", err)
	}
	if err := txA.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	// The reclaim proceeds — and its transaction deletes the pressure the
	// old holder just wrote.
	select {
	case code := <-reclaimDone:
		if code != http.StatusOK {
			t.Fatalf("reclaim after unblock: %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reclaim never completed after lock release")
	}
	var count int
	if err := testPool.QueryRow(ctx,
		`SELECT COUNT(*) FROM host_pressure WHERE host_id = $1`, hostID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("stale pressure from the old holder survived the reclaim")
	}
}
