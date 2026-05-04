package secretsproxy

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/secrets"
	"github.com/superserve-ai/sandbox/internal/secretsproxy/api"
)

// ---------------------------------------------------------------------------
// Test scaffolding — fake upstream + a Server pointed at it.
// ---------------------------------------------------------------------------

type testFixture struct {
	server   *Server
	state    *State
	signer   *secrets.Signer
	upstream *httptest.Server
	upstreamHits int
	lastKey  string
}

// newFixture spins up a fake upstream and returns a Server whose
// Anthropic provider points at that upstream.
func newFixture(t *testing.T) *testFixture {
	t.Helper()
	f := &testFixture{state: NewState()}
	key := make([]byte, 32)
	rand.Read(key)
	signer, err := secrets.NewSigner(key, "v1", "test-iss", "secretsproxy", time.Hour)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	f.signer = signer

	f.upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.upstreamHits++
		f.lastKey = r.Header.Get("x-api-key")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(f.upstream.Close)

	cfg := AnthropicConfig
	cfg.Upstream = f.upstream.URL
	registry := NewRegistry(cfg)
	f.server = NewServer(f.state, signer, registry, nil) // no audit writer in tests
	return f
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (f *testFixture) sandboxAndToken(t *testing.T, sandboxID, secretID, teamID uuid.UUID, srcIP, realKey string) string {
	t.Helper()
	f.state.Register(api.RegisterRequest{
		SandboxID: sandboxID.String(),
		TeamID:    teamID.String(),
		SourceIP:  srcIP,
		Bindings: []api.SecretBinding{{
			SecretID:  secretID.String(),
			Provider:  "anthropic",
			EnvKey:    "ANTHROPIC_API_KEY",
			RealValue: realKey,
		}},
	})
	tok, err := f.signer.Mint(time.Now(), sandboxID, secretID, teamID)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	return tok
}

// makeRequestRecorder wraps a request through the server with a custom
// RemoteAddr. httptest.NewRequest defaults RemoteAddr to "192.0.2.1:1234"
// unless we set it ourselves.
func (f *testFixture) doRequest(t *testing.T, method, path, body, srcIP, authHeader string) *httptest.ResponseRecorder {
	t.Helper()
	var bodyR io.Reader
	if body != "" {
		bodyR = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, bodyR)
	req.RemoteAddr = net.JoinHostPort(srcIP, "12345")
	if authHeader != "" {
		req.Header.Set("x-api-key", authHeader)
	}
	w := httptest.NewRecorder()
	f.server.serve(w, req)
	return w
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestServer_HappyPath(t *testing.T) {
	f := newFixture(t)
	srcIP := "10.11.0.1"
	realKey := "sk-ant-real-12345"
	sandboxID := uuid.New()
	tok := f.sandboxAndToken(t, sandboxID, uuid.New(), uuid.New(), srcIP, realKey)

	w := f.doRequest(t, http.MethodPost, "/anthropic/v1/messages", `{"hi":1}`, srcIP, tok)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if f.upstreamHits != 1 {
		t.Errorf("upstream hits=%d", f.upstreamHits)
	}
	if f.lastKey != realKey {
		t.Errorf("upstream saw key=%q, want real key", f.lastKey)
	}
}

func TestServer_UnknownSourceIP(t *testing.T) {
	f := newFixture(t)
	w := f.doRequest(t, http.MethodPost, "/anthropic/v1/messages", "", "10.11.99.99", "anything")
	if w.Code != http.StatusForbidden {
		t.Errorf("status=%d", w.Code)
	}
	if f.upstreamHits != 0 {
		t.Errorf("upstream hit despite unknown sandbox")
	}
}

func TestServer_UnknownProvider(t *testing.T) {
	f := newFixture(t)
	srcIP := "10.11.0.2"
	tok := f.sandboxAndToken(t, uuid.New(), uuid.New(), uuid.New(), srcIP, "x")
	w := f.doRequest(t, http.MethodPost, "/openai/v1/chat", "", srcIP, tok)
	if w.Code != http.StatusNotFound {
		t.Errorf("status=%d", w.Code)
	}
}

func TestServer_InvalidToken(t *testing.T) {
	f := newFixture(t)
	srcIP := "10.11.0.3"
	f.state.Register(api.RegisterRequest{
		SandboxID: uuid.New().String(),
		TeamID:    uuid.New().String(),
		SourceIP:  srcIP,
	})
	w := f.doRequest(t, http.MethodPost, "/anthropic/v1/messages", "", srcIP, "garbage.token.here")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status=%d", w.Code)
	}
}

func TestServer_TokenSandboxMismatch(t *testing.T) {
	f := newFixture(t)
	srcIP := "10.11.0.4"
	// Register sandbox A at this IP.
	sandboxA := uuid.New()
	teamID := uuid.New()
	secretID := uuid.New()
	f.state.Register(api.RegisterRequest{
		SandboxID: sandboxA.String(),
		TeamID:    teamID.String(),
		SourceIP:  srcIP,
		Bindings: []api.SecretBinding{{
			SecretID: secretID.String(), Provider: "anthropic", EnvKey: "K", RealValue: "x",
		}},
	})
	// Mint a token for sandbox B (different sub claim).
	tok, _ := f.signer.Mint(time.Now(), uuid.New(), secretID, teamID)
	w := f.doRequest(t, http.MethodPost, "/anthropic/v1/messages", "", srcIP, tok)
	if w.Code != http.StatusForbidden {
		t.Errorf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestServer_SecretRevoked(t *testing.T) {
	f := newFixture(t)
	srcIP := "10.11.0.5"
	sandboxID := uuid.New()
	teamID := uuid.New()
	revokedID := uuid.New()
	// Register WITHOUT the secret that the JWT will reference.
	f.state.Register(api.RegisterRequest{
		SandboxID: sandboxID.String(),
		TeamID:    teamID.String(),
		SourceIP:  srcIP,
	})
	tok, _ := f.signer.Mint(time.Now(), sandboxID, revokedID, teamID)
	w := f.doRequest(t, http.MethodPost, "/anthropic/v1/messages", "", srcIP, tok)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestServer_EgressBlocked(t *testing.T) {
	f := newFixture(t)
	srcIP := "10.11.0.6"
	sandboxID := uuid.New()
	teamID := uuid.New()
	secretID := uuid.New()
	f.state.Register(api.RegisterRequest{
		SandboxID: sandboxID.String(),
		TeamID:    teamID.String(),
		SourceIP:  srcIP,
		Bindings: []api.SecretBinding{{
			SecretID: secretID.String(), Provider: "anthropic", EnvKey: "K", RealValue: "x",
		}},
		Egress: api.EgressRules{
			AllowOut: []string{"api.openai.com"}, // doesn't include our fake upstream
		},
	})
	tok, _ := f.signer.Mint(time.Now(), sandboxID, secretID, teamID)
	w := f.doRequest(t, http.MethodPost, "/anthropic/v1/messages", "", srcIP, tok)
	if w.Code != http.StatusForbidden {
		t.Errorf("status=%d body=%s", w.Code, w.Body.String())
	}
	if f.upstreamHits != 0 {
		t.Error("upstream hit despite egress block")
	}
}

func TestServer_StreamingForward(t *testing.T) {
	// Replace the upstream with one that streams chunked output and
	// confirm the proxy forwards each chunk promptly.
	f := newFixture(t)
	f.upstream.Close()
	chunks := []string{"event: a\n\n", "event: b\n\n", "event: c\n\n"}
	f.upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		for _, c := range chunks {
			w.Write([]byte(c))
			if flusher != nil {
				flusher.Flush()
			}
			time.Sleep(2 * time.Millisecond)
		}
	}))
	t.Cleanup(f.upstream.Close)
	cfg := AnthropicConfig
	cfg.Upstream = f.upstream.URL
	f.server = NewServer(f.state, f.signer, NewRegistry(cfg), nil)

	srcIP := "10.11.0.7"
	tok := f.sandboxAndToken(t, uuid.New(), uuid.New(), uuid.New(), srcIP, "real")
	w := f.doRequest(t, http.MethodPost, "/anthropic/v1/messages", "", srcIP, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	got := w.Body.String()
	for _, c := range chunks {
		if !strings.Contains(got, c) {
			t.Errorf("body missing chunk %q; got %q", c, got)
		}
	}
}

// ---------------------------------------------------------------------------
// scanForMarker — chunk-boundary detection of the SSE error marker.
// ---------------------------------------------------------------------------

func TestScanForMarker_FullChunk(t *testing.T) {
	progress, hit := scanForMarker([]byte("event: error\ndata: {}"), sseStreamErrorMarker, 0)
	if !hit || progress != 0 {
		t.Fatalf("hit=%v progress=%d", hit, progress)
	}
}

func TestScanForMarker_NoMatch(t *testing.T) {
	progress, hit := scanForMarker([]byte("event: message_delta\ndata: {}"), sseStreamErrorMarker, 0)
	if hit {
		t.Fatal("false positive on non-error event")
	}
	if progress != 0 {
		t.Errorf("progress=%d, want 0 on no match", progress)
	}
}

func TestScanForMarker_AcrossBoundary(t *testing.T) {
	// Split the marker between two chunks to verify state carries.
	marker := string(sseStreamErrorMarker)
	cut := len(marker) / 2
	first := []byte("noise " + marker[:cut])
	second := []byte(marker[cut:] + " trailing")

	progress, hit := scanForMarker(first, sseStreamErrorMarker, 0)
	if hit {
		t.Fatal("matched on first half alone")
	}
	if progress == 0 {
		t.Fatal("progress not preserved across boundary")
	}
	_, hit = scanForMarker(second, sseStreamErrorMarker, progress)
	if !hit {
		t.Fatal("did not match across boundary")
	}
}

func TestScanForMarker_FalseStartThenMatch(t *testing.T) {
	// First "e" is a false start; the real match comes later.
	chunk := []byte("e\nevent: error\n")
	_, hit := scanForMarker(chunk, sseStreamErrorMarker, 0)
	if !hit {
		t.Fatal("missed real match after a false start")
	}
}

func TestServer_StreamingErrorMarkedInAudit(t *testing.T) {
	f := newFixture(t)
	f.upstream.Close()
	f.upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		w.Write([]byte("event: message_start\ndata: {}\n\n"))
		flusher.Flush()
		w.Write([]byte("event: error\ndata: {\"type\":\"error\"}\n\n"))
		flusher.Flush()
	}))
	t.Cleanup(f.upstream.Close)
	cfg := AnthropicConfig
	cfg.Upstream = f.upstream.URL
	f.server = NewServer(f.state, f.signer, NewRegistry(cfg), nil)

	srcIP := "10.11.99.1"
	tok := f.sandboxAndToken(t, uuid.New(), uuid.New(), uuid.New(), srcIP, "real")
	w := f.doRequest(t, http.MethodPost, "/anthropic/v1/messages", "", srcIP, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "event: error") {
		t.Fatalf("response body did not pass through error chunk: %q", w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// PropagateSecret — rotation and revocation across the in-memory state.
// ---------------------------------------------------------------------------

func TestState_PropagateSecret_Rotation(t *testing.T) {
	st := NewState()
	secretID := uuid.NewString()
	st.Register(api.RegisterRequest{
		SandboxID: uuid.NewString(),
		SourceIP:  "10.11.0.1",
		Bindings: []api.SecretBinding{
			{SecretID: secretID, Provider: "anthropic", EnvKey: "K", RealValue: "old"},
		},
	})
	st.Register(api.RegisterRequest{
		SandboxID: uuid.NewString(),
		SourceIP:  "10.11.0.2",
		Bindings: []api.SecretBinding{
			{SecretID: secretID, Provider: "anthropic", EnvKey: "K", RealValue: "old"},
		},
	})

	st.PropagateSecret(secretID, "new")

	for _, ip := range []string{"10.11.0.1", "10.11.0.2"} {
		sb, ok := st.LookupBySourceIP(ip)
		if !ok {
			t.Fatalf("sandbox at %s missing", ip)
		}
		if sb.Bindings[secretID].RealValue != "new" {
			t.Errorf("ip=%s real value=%q, want new", ip, sb.Bindings[secretID].RealValue)
		}
	}
}

func TestState_PropagateSecret_Revoke(t *testing.T) {
	st := NewState()
	secretID := uuid.NewString()
	st.Register(api.RegisterRequest{
		SandboxID: uuid.NewString(),
		SourceIP:  "10.11.0.5",
		Bindings: []api.SecretBinding{
			{SecretID: secretID, Provider: "anthropic", EnvKey: "K", RealValue: "v"},
		},
	})
	st.PropagateSecret(secretID, "")

	sb, _ := st.LookupBySourceIP("10.11.0.5")
	if _, present := sb.Bindings[secretID]; present {
		t.Error("revoke did not remove binding")
	}
}

// ---------------------------------------------------------------------------
// Egress logic, isolated.
// ---------------------------------------------------------------------------

func TestEgressAllowed(t *testing.T) {
	cases := []struct {
		name   string
		rules  api.EgressRules
		host   string
		expect bool
	}{
		{"empty rules", api.EgressRules{}, "api.anthropic.com", true},
		{"allow exact", api.EgressRules{AllowOut: []string{"api.anthropic.com"}}, "api.anthropic.com", true},
		{"allow doesn't match", api.EgressRules{AllowOut: []string{"api.openai.com"}}, "api.anthropic.com", false},
		{"deny wins", api.EgressRules{AllowOut: []string{"api.anthropic.com"}, DenyOut: []string{"api.anthropic.com"}}, "api.anthropic.com", false},
		{"wildcard suffix", api.EgressRules{AllowOut: []string{"*.anthropic.com"}}, "api.anthropic.com", true},
		{"wildcard miss", api.EgressRules{AllowOut: []string{"*.openai.com"}}, "api.anthropic.com", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := mustURL(t, "https://"+tc.host)
			if got := egressAllowed(tc.rules, u); got != tc.expect {
				t.Errorf("got %v, want %v", got, tc.expect)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Control endpoints — unit-test the in-memory state via the HTTP handler.
// ---------------------------------------------------------------------------

func TestControl_RegisterAndLookup(t *testing.T) {
	state := NewState()
	cs := NewControlServer(state)
	srv := httptest.NewServer(cs.Handler())
	defer srv.Close()

	body, _ := json.Marshal(api.RegisterRequest{
		SandboxID: uuid.NewString(),
		TeamID:    uuid.NewString(),
		SourceIP:  "10.11.0.42",
		Bindings:  []api.SecretBinding{{SecretID: uuid.NewString(), Provider: "anthropic", EnvKey: "K", RealValue: "v"}},
	})
	resp, err := http.Post(srv.URL+"/sandboxes/register", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("register status=%d", resp.StatusCode)
	}
	if _, ok := state.LookupBySourceIP("10.11.0.42"); !ok {
		t.Fatal("state did not record sandbox after register")
	}
}

func TestControl_UpdateBindings_NotFound(t *testing.T) {
	state := NewState()
	cs := NewControlServer(state)
	srv := httptest.NewServer(cs.Handler())
	defer srv.Close()

	body, _ := json.Marshal(api.UpdateBindingsRequest{Bindings: nil})
	resp, err := http.Post(srv.URL+"/sandboxes/missing/bindings", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}
