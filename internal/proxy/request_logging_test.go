package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/superserve-ai/sandbox/internal/auth"
)

type requestLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *requestLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}
func (b *requestLogBuffer) text() string { b.mu.Lock(); defer b.mu.Unlock(); return b.buf.String() }
func (b *requestLogBuffer) events(t *testing.T) []map[string]any {
	t.Helper()
	var events []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(b.text()), "\n") {
		var event map[string]any
		if json.Unmarshal([]byte(line), &event) == nil && event["event_type"] != nil {
			events = append(events, event)
		}
	}
	return events
}

const logTestSandbox = "12345678-1234-1234-1234-123456789abc"
const logTestTeam = "00000000-0000-4000-8000-000000000001"

var logTestSeed = []byte("test-log-seed-at-least-thirty-two-bytes")

func loggingProxy(t *testing.T, upstream http.Handler) (*Handler, *requestLogBuffer) {
	t.Helper()
	buf := &requestLogBuffer{}
	logger := zerolog.New(buf).With().Str("service", "proxy").Logger()
	resolver := &stubResolver{info: InstanceInfo{VMIP: "127.0.0.1", Status: "running", TeamID: logTestTeam, OwnerID: uuid.NewString()}}
	h := NewHandler([]string{"sandbox.test"}, resolver, logger).WithAuth(logTestSeed).WithFiles().WithExec().WithTerminal([]string{"*"})
	if upstream != nil {
		srv := httptest.NewServer(upstream)
		t.Cleanup(srv.Close)
		tr := newTransport()
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
		}
		h.transports.items[logTestSandbox] = &transportEntry{lifecycleKey: resolver.info.lifecycleKey(), transport: tr, lastUsed: time.Now()}
		t.Cleanup(tr.CloseIdleConnections)
	}
	return h, buf
}

func loggingRequest(method, path, token string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	r.Host = "boxd-" + logTestSandbox + ".sandbox.test"
	r.Header.Set(accessTokenHeader, token)
	return r
}

func TestRequestLoggingFilesRedactionAndResponse(t *testing.T) {
	const secret = "SYNTHETIC_CONTENT_SECRET"
	h, buf := loggingProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(accessTokenHeader) != "" || r.Header.Get(peerRequestIDHeader) != "" {
			t.Error("credential/correlation leaked upstream")
		}
		w.WriteHeader(500)
		io.WriteString(w, secret)
	}))
	token := auth.ComputeAccessToken(logTestSeed, logTestSandbox)
	r := loggingRequest("GET", "/files?path=/"+secret, token)
	r.Header.Set("X-Actor-User-Id", secret)
	r.Header.Set(peerRequestIDHeader, uuid.NewString())
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 500 || w.Body.String() != secret {
		t.Fatal("upstream response changed")
	}
	events := buf.events(t)
	if len(events) != 1 {
		t.Fatalf("events = %v", events)
	}
	e := events[0]
	for key, want := range map[string]any{"actor_type": "sandbox_capability", "attribution_status": "sandbox_only", "auth_outcome": "authenticated", "resource_team_id": logTestTeam, "sandbox_id": logTestSandbox, "route": "/files", "status": float64(500), "body_size": float64(len(secret))} {
		if e[key] != want {
			t.Errorf("%s = %v, want %v", key, e[key], want)
		}
	}
	for _, key := range []string{"actor_id", "credential_id", "user_id", "team_id"} {
		if e[key] != nil {
			t.Errorf("fabricated %s", key)
		}
	}
	if strings.Contains(buf.text(), secret) || strings.Contains(buf.text(), token) {
		t.Fatalf("secret leaked: %s", buf.text())
	}
}

func TestRequestLoggingDesktopStep(t *testing.T) {
	h, buf := loggingProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != desktopStepPath {
			t.Errorf("upstream path = %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "SYNTHETIC_SCREENSHOT_SECRET")
	}))
	h.WithDesktop()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, loggingRequest("POST", desktopStepPath, auth.ComputeAccessToken(logTestSeed, logTestSandbox)))
	events := buf.events(t)
	if w.Code != http.StatusOK || w.Body.String() != "SYNTHETIC_SCREENSHOT_SECRET" || len(events) != 1 {
		t.Fatalf("step changed: status=%d events=%v", w.Code, events)
	}
	if events[0]["route"] != desktopStepPath || events[0]["path"] != desktopStepPath || events[0]["auth_outcome"] != "authenticated" {
		t.Fatal(events)
	}
	if strings.Contains(buf.text(), "SYNTHETIC_SCREENSHOT_SECRET") {
		t.Fatal("screenshot content leaked")
	}
}

func TestRequestLoggingEarlyFailures(t *testing.T) {
	for _, tc := range []struct {
		name, path, token, outcome string
		status                     int
	}{
		{"missing", "/files?path=/data", "", "missing", 401},
		{"invalid", "/files?path=/data", "SYNTHETIC_BAD_TOKEN", "invalid", 401},
		{"unmatched", "/SYNTHETIC_PATH_SECRET", "", "not_evaluated", 404},
		{"invalid file request", "/files", "", "not_evaluated", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, buf := loggingProxy(t, nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, loggingRequest("GET", tc.path, tc.token))
			events := buf.events(t)
			if len(events) != 1 || events[0]["status"] != float64(tc.status) || events[0]["auth_outcome"] != tc.outcome {
				t.Fatal(events)
			}
			if strings.Contains(buf.text(), "SYNTHETIC") {
				t.Fatal(buf.text())
			}
		})
	}
}

func TestRequestLoggingAuthenticatedRoutingFailure(t *testing.T) {
	h, buf := loggingProxy(t, nil)
	router := NewRoutingHandler(h.domains, "local", RouteLookupFunc(func(context.Context, string) (SandboxRoute, error) { return SandboxRoute{}, errors.New("unavailable") }), nil, h, h.log)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, loggingRequest("GET", "/files?path=/data", auth.ComputeAccessToken(logTestSeed, logTestSandbox)))
	events := buf.events(t)
	if w.Code != 502 || len(events) != 1 || events[0]["auth_outcome"] != "authenticated" {
		t.Fatal(events)
	}
}

func TestRequestLoggingStreamStartsBeforeCompletion(t *testing.T) {
	for _, path := range []string{execStreamPath, desktopStreamPath} {
		t.Run(path, func(t *testing.T) {
			release := make(chan struct{})
			var once sync.Once
			h, buf := loggingProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				io.WriteString(w, "data: SYNTHETIC_STREAM_SECRET\n\n")
				w.(http.Flusher).Flush()
				<-release
			}))
			h.WithDesktop()
			srv := httptest.NewServer(h)
			defer srv.Close()
			defer once.Do(func() { close(release) })
			r, _ := http.NewRequest("POST", srv.URL+path, strings.NewReader(`{"command":"SYNTHETIC_COMMAND_SECRET"}`))
			r.Host = "boxd-" + logTestSandbox + ".sandbox.test"
			r.Header.Set(accessTokenHeader, auth.ComputeAccessToken(logTestSeed, logTestSandbox))
			resp, err := srv.Client().Do(r)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			initial := buf.events(t)
			if len(initial) != 1 || initial[0]["event_type"] != "session_start" {
				t.Fatalf("stream not immediately observable: %v", initial)
			}
			once.Do(func() { close(release) })
			data, err := io.ReadAll(resp.Body)
			if err != nil || !strings.Contains(string(data), "SYNTHETIC_STREAM_SECRET") {
				t.Fatalf("stream changed: %s %v", data, err)
			}
			events := awaitRequestEvents(t, buf, 2)
			if events[1]["event_type"] != "session_complete" || events[1]["request_id"] != events[0]["request_id"] {
				t.Fatal(events)
			}
			if strings.Contains(buf.text(), "SYNTHETIC") {
				t.Fatal("content leaked")
			}
		})
	}
}

func awaitRequestEvents(t *testing.T, buf *requestLogBuffer, count int) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if events := buf.events(t); len(events) >= count {
			return events
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("missing request events: %s", buf.text())
	return nil
}

func TestRequestLoggingCanceledStream(t *testing.T) {
	h, buf := loggingProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	srv := httptest.NewServer(h)
	defer srv.Close()
	r, _ := http.NewRequest("POST", srv.URL+execStreamPath, strings.NewReader(`{}`))
	r.Host = "boxd-" + logTestSandbox + ".sandbox.test"
	r.Header.Set(accessTokenHeader, auth.ComputeAccessToken(logTestSeed, logTestSandbox))
	resp, err := srv.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	events := awaitRequestEvents(t, buf, 2)
	if len(events) != 2 || events[0]["event_type"] != "session_start" || events[1]["event_type"] != "session_complete" || events[0]["request_id"] != events[1]["request_id"] {
		t.Fatal(events)
	}
	if outcome := events[1]["outcome"]; outcome != "canceled" && outcome != "aborted" && outcome != "transport_error" {
		t.Fatalf("canceled stream reported success: %v", events[1])
	}
}

func TestRequestLoggingUntrustedSandboxName(t *testing.T) {
	h, buf := loggingProxy(t, nil)
	r := loggingRequest("GET", filesPath+"?path=/data", "invalid")
	r.Host = "sandbox.test"
	r.Header.Set(headerSandboxID, "SYNTHETIC-PRIVATE-MARKER")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized || strings.Contains(buf.text(), "SYNTHETIC") {
		t.Fatalf("untrusted target leaked: %s", buf.text())
	}
	if got := buf.events(t); len(got) != 1 || got[0]["auth_outcome"] != "invalid" {
		t.Fatal(got)
	}
}

func TestRequestLoggingWebsocketUpgradeAndClose(t *testing.T) {
	h, buf := loggingProxy(t, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Host = "boxd-" + logTestSandbox + ".sandbox.test"
		h.ServeHTTP(w, r)
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	headers := http.Header{"Host": {"boxd-" + logTestSandbox + ".sandbox.test"}}
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/exec/connect", &websocket.DialOptions{
		HTTPHeader: headers, Subprotocols: []string{execProtocol, "token." + auth.ComputeAccessToken(logTestSeed, logTestSandbox)},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	initial := awaitRequestEvents(t, buf, 1)
	if initial[0]["event_type"] != "session_start" || initial[0]["status"] != float64(101) {
		t.Fatal(initial)
	}
	if err := ws.Write(ctx, websocket.MessageText, []byte(`{"SYNTHETIC_SECRET":"invalid start"}`)); err != nil {
		t.Fatal(err)
	}
	_, _, _ = ws.Read(ctx)
	events := awaitRequestEvents(t, buf, 2)
	if events[1]["event_type"] != "session_complete" || events[1]["request_id"] != initial[0]["request_id"] {
		t.Fatal(events)
	}
	if events[1]["body_size"] != nil {
		t.Fatal("hijacked byte count falsely reported")
	}
	if strings.Contains(buf.text(), "SYNTHETIC_SECRET") {
		t.Fatal("frame leaked")
	}
}

func TestRequestLoggingPeerHasOnePrimaryEvent(t *testing.T) {
	h, buf := loggingProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	owner := httptest.NewServer(PeerRequestLogging(h))
	defer owner.Close()
	peers, addr := startRoutingTestPeer(t, owner.Listener.Addr().String())
	router := NewRoutingHandler(h.domains, "edge", RouteLookupFunc(func(context.Context, string) (SandboxRoute, error) {
		return SandboxRoute{HostID: "owner", ProxyAddr: addr, Generation: 1}, nil
	}), peers, h, h.log)
	edge := httptest.NewServer(router)
	defer edge.Close()
	r, _ := http.NewRequest("GET", edge.URL+"/files?path=/data", nil)
	r.Host = "boxd-" + logTestSandbox + ".sandbox.test"
	r.Close = true
	r.Header.Set(accessTokenHeader, auth.ComputeAccessToken(logTestSeed, logTestSandbox))
	spoofed := uuid.NewString()
	r.Header.Set(peerRequestIDHeader, spoofed)
	resp, err := edge.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil || string(data) != "ok" {
		t.Fatalf("%s %v", data, err)
	}
	events := awaitRequestEvents(t, buf, 2)
	if len(events) != 2 || events[0]["request_id"] != events[1]["request_id"] || events[0]["request_id"] == spoofed {
		t.Fatal(events)
	}
	counts := map[string]int{}
	for _, e := range events {
		counts[e["event_type"].(string)]++
	}
	if counts["request"] != 1 || counts["proxy_forward"] != 1 {
		t.Fatal(events)
	}
}
