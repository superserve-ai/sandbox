package proxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog"
	"github.com/superserve-ai/sandbox/internal/auth"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/telemetry"
)

type hintHosts map[string]SandboxRoute

func (h hintHosts) ResolveHost(id string) (SandboxRoute, bool) { r, ok := h[id]; return r, ok }

func TestHintRoutingFallbackAndAuthorization(t *testing.T) {
	const id = "00000000-0000-4000-8000-000000000001"
	seed := []byte(strings.Repeat("k", 32))
	for _, tc := range []struct {
		name, hint, token string
		lookups           int
	}{
		{"valid", auth.SignRoutingHint(seed, id, "local", "sandbox.test", time.Now(), 1), auth.ComputeAccessToken(seed, id), 0},
		{"revoked", auth.SignRoutingHint(seed, id, "local", "sandbox.test", time.Now(), 1), auth.ComputeAccessToken(seed, id), 1},
		{"stale revocations", auth.SignRoutingHint(seed, id, "local", "sandbox.test", time.Now(), 1), auth.ComputeAccessToken(seed, id), 1},
		{"missing", "", auth.ComputeAccessToken(seed, id), 1},
		{"invalid", "tampered", auth.ComputeAccessToken(seed, id), 1},
		{"expired", auth.SignRoutingHint(seed, id, "local", "sandbox.test", time.Now().Add(-2*time.Hour), 1), auth.ComputeAccessToken(seed, id), 1},
		{"unknown host", auth.SignRoutingHint(seed, id, "missing", "sandbox.test", time.Now(), 1), auth.ComputeAccessToken(seed, id), 1},
		{"unauthorized", auth.SignRoutingHint(seed, id, "local", "sandbox.test", time.Now(), 1), "bad", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			local := NewHandler([]string{"sandbox.test"}, &stubResolver{err: ErrInstanceNotFound}, zerolog.Nop()).WithAuth(seed).WithExec()
			router := NewRoutingHandler([]string{"sandbox.test"}, "local", RouteLookupFunc(func(context.Context, string) (SandboxRoute, error) {
				calls++
				return SandboxRoute{HostID: "local"}, nil
			}), nil, local, zerolog.Nop()).WithRoutingHints(hintHosts{"local": {HostID: "local"}}, freshTestRevocations())
			if tc.name == "revoked" {
				router.revocations = &RoutingRevocations{expires: time.Now().Add(time.Second), revoked: map[routeVersion]struct{}{{id, 1}: {}}}
			}
			if tc.name == "stale revocations" {
				router.revocations = &RoutingRevocations{}
			}
			req := httptest.NewRequest("POST", "http://boxd-"+id+".sandbox.test/exec", strings.NewReader(`{"command":"echo"}`))
			req.Header.Set(accessTokenHeader, tc.token)
			req.Header.Set(routingHintHeader, tc.hint)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if calls != tc.lookups {
				t.Fatalf("lookups=%d want %d", calls, tc.lookups)
			}
			if tc.name == "unauthorized" {
				if w.Code != 401 {
					t.Fatal(w.Code)
				}
			} else if w.Code != 404 || !strings.Contains(w.Body.String(), "sandbox_route_stale") {
				t.Fatalf("missing safe pre-execution error: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestRoutingHintWebSocketCarrierAndScrubbing(t *testing.T) {
	req := httptest.NewRequest("GET", "http://sandbox.test/exec/connect", nil)
	req.Header.Set("Sec-WebSocket-Protocol", "superserve.exec.v1, token.secret, route.hint")
	if got := requestRoutingHint(req); got != "hint" {
		t.Fatal(got)
	}
	scrubRoutingHint(req)
	if got := req.Header.Get("Sec-WebSocket-Protocol"); got != "superserve.exec.v1, token.secret" {
		t.Fatal(got)
	}
	req.Header.Set(routingHintHeader, "hint")
	scrubRoutingHint(req)
	if req.Header.Get(routingHintHeader) != "" {
		t.Fatal("hint leaked")
	}
	req.Header.Set("Sec-WebSocket-Protocol", "route.one, route.two")
	if requestRoutingHint(req) != "" {
		t.Fatal("duplicate hint accepted")
	}
}

type directorySource struct {
	rows []db.GetSandboxPeerEndpointRow
	err  error
}

func (s directorySource) ListPeerHosts(context.Context) ([]db.GetSandboxPeerEndpointRow, error) {
	return s.rows, s.err
}
func TestHostDirectoryRefreshExpiryAndGeneration(t *testing.T) {
	ip, addr, generation := "10.0.0.1:50051", "10.0.0.1:5009", int64(1)
	row := db.GetSandboxPeerEndpointRow{HostID: "host-a", VmdAddr: &ip, ProxyAddr: &addr, IncarnationID: pgtype.UUID{Bytes: uuid.New(), Valid: true}, PeerGeneration: &generation}
	d := &HostDirectory{}
	ctx := context.Background()
	if err := d.refresh(ctx, directorySource{rows: []db.GetSandboxPeerEndpointRow{row}}); err != nil {
		t.Fatal(err)
	}
	if r, ok := d.ResolveHost("host-a"); !ok || r.Generation != 1 {
		t.Fatal(r, ok)
	}
	generation = 2
	_ = d.refresh(ctx, directorySource{rows: []db.GetSandboxPeerEndpointRow{row}})
	if r, _ := d.ResolveHost("host-a"); r.Generation != 2 {
		t.Fatal(r)
	}
	_ = d.refresh(ctx, directorySource{err: errors.New("offline")})
	if _, ok := d.ResolveHost("host-a"); !ok {
		t.Fatal("lost fresh snapshot on transient failure")
	}
	d.expires = time.Now().Add(-time.Second)
	if _, ok := d.ResolveHost("host-a"); ok {
		t.Fatal("served expired snapshot")
	}
	_ = d.refresh(ctx, directorySource{})
	if _, ok := d.ResolveHost("host-a"); ok {
		t.Fatal("retained removed host")
	}
	row.ProxyAddr = &ip
	_ = d.refresh(ctx, directorySource{rows: []db.GetSandboxPeerEndpointRow{row}})
	if _, ok := d.ResolveHost("host-a"); ok {
		t.Fatal("accepted untrusted endpoint")
	}
}

type burstResolver struct {
	entered chan struct{}
	release chan struct{}
}

func (r *burstResolver) Lookup(context.Context, string) (InstanceInfo, error) {
	r.entered <- struct{}{}
	<-r.release
	return InstanceInfo{}, ErrInstanceNotFound
}
func (r *burstResolver) Invalidate(string) {}
func TestHintedThousandConcurrentRequestsBypassOwnership(t *testing.T) {
	seed := []byte(strings.Repeat("k", 32))
	resolver := &burstResolver{make(chan struct{}, 1000), make(chan struct{})}
	local := NewHandler([]string{"sandbox.test"}, resolver, zerolog.Nop()).WithAuth(seed).WithExec()
	var lookups atomic.Int32
	router := NewRoutingHandler([]string{"sandbox.test"}, "local", RouteLookupFunc(func(context.Context, string) (SandboxRoute, error) {
		lookups.Add(1)
		return SandboxRoute{}, errors.New("lookup forbidden")
	}), nil, local, zerolog.Nop()).WithRoutingHints(hintHosts{"local": {HostID: "local"}}, freshTestRevocations())
	var wg sync.WaitGroup
	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("00000000-0000-4000-8000-%012d", i)
			r := httptest.NewRequest("POST", "http://boxd-"+id+".sandbox.test/exec", nil)
			r.Header.Set(accessTokenHeader, auth.ComputeAccessToken(seed, id))
			r.Header.Set(routingHintHeader, auth.SignRoutingHint(seed, id, "local", "sandbox.test", time.Now(), 1))
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)
			if w.Code != http.StatusNotFound {
				t.Errorf("status %d", w.Code)
			}
		}(i)
	}
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for i := 0; i < 1000; i++ {
		select {
		case <-resolver.entered:
		case <-timer.C:
			close(resolver.release)
			wg.Wait()
			t.Fatalf("only %d of 1000 reached destination", i)
		}
	}
	close(resolver.release)
	wg.Wait()
	if lookups.Load() != 0 {
		t.Fatal("ownership lookup on hinted path")
	}
}

type observedHintPeer struct {
	PeerTransport
	opens        atomic.Int32
	failFirst    bool
	wantHost     string
	wantEndpoint PeerEndpoint
	t            *testing.T
}

func (p *observedHintPeer) OpenStream(ctx context.Context, host string, endpoint PeerEndpoint) (PeerStream, error) {
	count := p.opens.Add(1)
	if host != p.wantHost || endpoint != p.wantEndpoint {
		p.t.Errorf("untrusted route %s %+v", host, endpoint)
	}
	if p.failFirst && count == 1 {
		return nil, errors.New("failed before request bytes")
	}
	return p.PeerTransport.OpenStream(ctx, host, endpoint)
}

func TestHintedRemoteExecAndPreDispatchFallback(t *testing.T) {
	for _, failFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(failFirst), func(t *testing.T) {
			env := newExecTestEnv(t)
			id := uuid.NewString()
			env.handler.transports.items[id] = env.handler.transports.items[env.sandboxID]
			env.sandboxID = id
			var executions atomic.Int32
			upstream := env.upstream.Config.Handler
			env.upstream.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get(routingHintHeader) != "" || strings.Contains(r.Header.Get("Sec-WebSocket-Protocol"), "route.") {
					t.Error("routing carrier leaked to boxd")
				}
				executions.Add(1)
				upstream.ServeHTTP(w, r)
			})
			owner := httptest.NewServer(env.handler)
			defer owner.Close()
			peers, addr := startRoutingTestPeer(t, owner.Listener.Addr().String())
			spy := &observedHintPeer{PeerTransport: peers, failFirst: failFirst, wantHost: "owner", wantEndpoint: PeerEndpoint{Address: addr, Generation: 7}, t: t}
			var lookups atomic.Int32
			route := SandboxRoute{HostID: "owner", ProxyAddr: addr, Generation: 7}
			edge := NewHandler([]string{env.domain}, &stubResolver{err: ErrInstanceNotFound}, zerolog.Nop()).WithAuth(env.seedKey).WithExec()
			router := httptest.NewServer(NewRoutingHandler([]string{env.domain}, "edge", RouteLookupFunc(func(context.Context, string) (SandboxRoute, error) { lookups.Add(1); return route, nil }), spy, edge, zerolog.Nop()).WithRoutingHints(hintHosts{"owner": route}, freshTestRevocations()))
			defer router.Close()
			req, _ := http.NewRequest("POST", router.URL+"/exec", strings.NewReader(`{"command":"echo once"}`))
			req.Host = "boxd-" + id + "." + env.domain
			req.Header.Set(accessTokenHeader, auth.ComputeAccessToken(env.seedKey, id))
			req.Header.Set(routingHintHeader, auth.SignRoutingHint(env.seedKey, id, "owner", env.domain, time.Now(), 1))
			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Fatal(resp.StatusCode)
			}
			if executions.Load() != 1 {
				t.Fatalf("executions=%d", executions.Load())
			}
			want := int32(0)
			if failFirst {
				want = 1
			}
			if lookups.Load() != want {
				t.Fatal("fallback count", lookups.Load())
			}
			if spy.opens.Load() != want+1 {
				t.Fatal("open count", spy.opens.Load())
			}
		})
	}
}

func TestHintedPeerOpenFailureRecoversBeforeExecution(t *testing.T) {
	for _, tc := range []struct {
		name       string
		lookupErr  error
		status     int
		outcome    string
		executions int32
	}{
		{"local", nil, http.StatusOK, "local", 1},
		{"missing", ErrInstanceNotFound, http.StatusNotFound, "not_found", 0},
		{"lookup unavailable", errors.New("database unavailable"), http.StatusBadGateway, "peer_error", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newExecTestEnv(t)
			id := uuid.NewString()
			env.handler.transports.items[id] = env.handler.transports.items[env.sandboxID]
			env.sandboxID = id
			var executions atomic.Int32
			upstream := env.upstream.Config.Handler
			env.upstream.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				executions.Add(1)
				upstream.ServeHTTP(w, r)
			})
			lookups, opens := 0, 0
			var outcomes []string
			router := NewRoutingHandler([]string{env.domain}, "local", RouteLookupFunc(func(context.Context, string) (SandboxRoute, error) {
				lookups++
				return SandboxRoute{HostID: "local"}, tc.lookupErr
			}), routePeerFunc(func(context.Context, string, PeerEndpoint) (PeerStream, error) {
				opens++
				return nil, errors.New("failed before request bytes")
			}), env.handler, zerolog.Nop(), routingOutcomeRecorderFunc(func(_ context.Context, outcome telemetry.RoutingOutcome) {
				outcomes = append(outcomes, outcome.Outcome)
			})).WithRoutingHints(hintHosts{"former-owner": {HostID: "former-owner", ProxyAddr: "10.0.0.2:5009", Generation: 1}}, freshTestRevocations())
			req := httptest.NewRequest(http.MethodPost, "http://boxd-"+id+"."+env.domain+"/exec", strings.NewReader(`{"command":"echo"}`))
			req.Header.Set(accessTokenHeader, env.validToken())
			req.Header.Set(routingHintHeader, auth.SignRoutingHint(env.seedKey, id, "former-owner", env.domain, time.Now(), 1))
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != tc.status || executions.Load() != tc.executions || lookups != 1 || opens != 1 {
				t.Fatalf("status=%d body=%s executions=%d lookups=%d opens=%d", w.Code, w.Body, executions.Load(), lookups, opens)
			}
			if len(outcomes) != 1 || outcomes[0] != tc.outcome {
				t.Fatalf("outcomes=%v", outcomes)
			}
			if tc.name == "missing" && (w.Header().Get("Content-Type") != "application/json" || !strings.Contains(w.Body.String(), `"sandbox_route_stale"`)) {
				t.Fatalf("missing stale-route signal: %s", w.Body)
			}
		})
	}
}

func TestHintedThousandConcurrentPeerRequests(t *testing.T) {
	seed := []byte(strings.Repeat("k", 32))
	destination := &burstResolver{make(chan struct{}, 1000), make(chan struct{})}
	owner := httptest.NewServer(NewHandler([]string{"sandbox.test"}, destination, zerolog.Nop()).WithAuth(seed).WithExec())
	defer owner.Close()
	peers, addr := startRoutingTestPeer(t, owner.Listener.Addr().String(), 1024)
	var lookups atomic.Int32
	edge := NewHandler([]string{"sandbox.test"}, &stubResolver{err: ErrInstanceNotFound}, zerolog.Nop()).WithAuth(seed).WithExec()
	route := SandboxRoute{HostID: "owner", ProxyAddr: addr, Generation: 1}
	server := httptest.NewServer(NewRoutingHandler([]string{"sandbox.test"}, "edge", RouteLookupFunc(func(context.Context, string) (SandboxRoute, error) {
		lookups.Add(1)
		return SandboxRoute{}, errors.New("lookup forbidden")
	}), peers, edge, zerolog.Nop()).WithRoutingHints(hintHosts{"owner": route}, freshTestRevocations()))
	defer server.Close()
	transport := &http.Transport{DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	var wg sync.WaitGroup
	failures := make(chan string, 1000)
	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("00000000-0000-4000-8000-%012d", i)
			req, _ := http.NewRequest("POST", server.URL+"/exec", nil)
			req.Host = "boxd-" + id + ".sandbox.test"
			req.Header.Set(accessTokenHeader, auth.ComputeAccessToken(seed, id))
			req.Header.Set(routingHintHeader, auth.SignRoutingHint(seed, id, "owner", "sandbox.test", time.Now(), 1))
			resp, err := client.Do(req)
			if err != nil {
				failures <- err.Error()
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != 404 {
				failures <- fmt.Sprint(resp.StatusCode)
			}
		}(i)
	}
	timer := time.NewTimer(20 * time.Second)
	defer timer.Stop()
	entered := 0
	for entered < 1000 {
		select {
		case <-destination.entered:
			entered++
		case failure := <-failures:
			close(destination.release)
			wg.Wait()
			t.Fatalf("request failed after %d entered: %s", entered, failure)
		case <-timer.C:
			close(destination.release)
			wg.Wait()
			t.Fatalf("only %d requests reached destination", entered)
		}
	}
	close(destination.release)
	wg.Wait()
	close(failures)
	for failure := range failures {
		t.Error(failure)
	}
	if lookups.Load() != 0 {
		t.Fatalf("ownership lookups=%d", lookups.Load())
	}
}

func freshTestRevocations() *RoutingRevocations {
	return &RoutingRevocations{expires: time.Now().Add(time.Minute)}
}
