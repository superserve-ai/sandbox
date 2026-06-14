package secretsproxy

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// startControlServerOnSocket binds the control server to a temp unix socket.
func startControlServerOnSocket(t *testing.T, cv *cachedVault, cr *cachedRules) (*http.Client, *ControlServer, *Revoker) {
	t.Helper()
	sockPath := filepath.Join(t.TempDir(), "control.sock")
	rev := NewRevoker()
	cs := NewControlServer(sockPath, cv, cr, rev)

	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = cs.Serve(l) }()
	t.Cleanup(func() { _ = cs.Shutdown(context.Background()) })

	for i := 0; i < 50; i++ {
		if cs.IsListening() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !cs.IsListening() {
		t.Fatal("control server not listening")
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
			},
		},
		Timeout: 2 * time.Second,
	}
	return client, cs, rev
}

func TestControlInvalidateDropsCacheEntry(t *testing.T) {
	clock := newFakeClock()
	upstream := &stubVault{values: map[string]string{"s": "v1"}}
	cv := newCachedVaultWithClock(upstream, time.Hour, clock)
	client, _, _ := startControlServerOnSocket(t, cv, nil)

	// Warm the cache.
	_, _ = cv.FetchCredential(context.Background(), "team-1", "s")
	upstream.values["s"] = "v2"

	// Hit the invalidate endpoint over the control socket.
	req, _ := http.NewRequest(http.MethodPost, "http://unix/v1/secrets/s/invalidate", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("invalidate: want 200, got %d", resp.StatusCode)
	}

	v, _ := cv.FetchCredential(context.Background(), "team-1", "s")
	if v != "v2" {
		t.Errorf("invalidate should have forced a refetch, got %q", v)
	}
}

func TestControlInvalidateIsNoOpWithoutVault(t *testing.T) {
	client, _, _ := startControlServerOnSocket(t, nil, nil)

	req, _ := http.NewRequest(http.MethodPost, "http://unix/v1/secrets/sec-1/invalidate", nil)
	resp, _ := client.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("invalidate without cache: want 200, got %d", resp.StatusCode)
	}
}

func TestControlInvalidateRejectsMalformedPath(t *testing.T) {
	client, _, _ := startControlServerOnSocket(t, nil, nil)
	req, _ := http.NewRequest(http.MethodPost, "http://unix/v1/secrets/bare", nil)
	resp, _ := client.Do(req)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("bare /v1/secrets/<id>: want 404, got %d", resp.StatusCode)
	}
}

func TestControlInvalidateRejectsGET(t *testing.T) {
	client, _, _ := startControlServerOnSocket(t, nil, nil)
	resp, _ := client.Get("http://unix/v1/secrets/s/invalidate")
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET should be 405, got %d", resp.StatusCode)
	}
}

func TestControlSandboxRevoke(t *testing.T) {
	client, _, rev := startControlServerOnSocket(t, nil, nil)

	req, _ := http.NewRequest(http.MethodPost, "http://unix/v1/sandboxes/sb-1/revoke", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke: want 200, got %d", resp.StatusCode)
	}
	if !rev.IsSandboxRevoked("sb-1") {
		t.Fatal("revoker should reflect the revoke call")
	}
}

func TestControlInvalidateSandboxRules(t *testing.T) {
	upstream := &stubRules{rules: EgressRules{Allow: []string{"a.com"}}}
	cr := NewCachedRules(upstream, RulesCacheOptions{TTL: time.Hour})
	client, _, _ := startControlServerOnSocket(t, nil, cr)

	_, _ = cr.FetchRules(context.Background(), "sb-1") // warm

	req, _ := http.NewRequest(http.MethodPost, "http://unix/v1/sandboxes/sb-1/rules", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rules invalidate: want 200, got %d", resp.StatusCode)
	}

	_, _ = cr.FetchRules(context.Background(), "sb-1") // must re-fetch
	if upstream.calls != 2 {
		t.Errorf("invalidate should force a refetch; calls=%d", upstream.calls)
	}
}

func TestControlSandboxRevokeRejectsMalformedPath(t *testing.T) {
	client, _, _ := startControlServerOnSocket(t, nil, nil)

	for _, path := range []string{"/v1/sandboxes/", "/v1/sandboxes/sb-1", "/v1/sandboxes/sb-1/destroy"} {
		req, _ := http.NewRequest(http.MethodPost, "http://unix"+path, nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: want 404, got %d", path, resp.StatusCode)
		}
	}
}

func TestControlSandboxRevokeRejectsGET(t *testing.T) {
	client, _, _ := startControlServerOnSocket(t, nil, nil)
	resp, err := client.Get("http://unix/v1/sandboxes/sb-1/revoke")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("want 405, got %d", resp.StatusCode)
	}
}

func TestControlHealth(t *testing.T) {
	client, _, _ := startControlServerOnSocket(t, nil, nil)
	resp, err := client.Get("http://unix/healthz")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health: want 200, got %d", resp.StatusCode)
	}
	var body struct {
		OK bool `json:"ok"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if !body.OK {
		t.Errorf("health.ok should be true")
	}
}

func TestControlSocketIsModeRestricted(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "ctl.sock")
	cs := NewControlServer(sockPath, nil, nil, nil)
	go func() { _ = cs.ListenAndServe() }()
	t.Cleanup(func() { _ = cs.Shutdown(context.Background()) })

	for i := 0; i < 50; i++ {
		if cs.IsListening() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !cs.IsListening() {
		t.Fatal("control server not listening via ListenAndServe")
	}

	info, err := os.Stat(sockPath)
	if err != nil {
		t.Fatal(err)
	}
	mode := info.Mode().Perm()
	if mode != 0o600 {
		t.Errorf("socket mode = %o, want 0600", mode)
	}
}

func TestControlShutdownBeforeServeIsSafe(t *testing.T) {
	// httpServer is constructed in NewControlServer, so Shutdown can be
	// called before Serve without racing on a nil pointer.
	c := NewControlServer("/dev/null/not-a-socket", nil, nil, nil)
	if err := c.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown before Serve should be a no-op, got %v", err)
	}
}
