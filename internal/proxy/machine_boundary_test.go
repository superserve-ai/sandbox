package proxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog"
	"github.com/superserve-ai/sandbox/internal/auth"
)

type authorityTestRow struct{ scan func(...any) error }

func (r authorityTestRow) Scan(dest ...any) error { return r.scan(dest...) }

type countingAuthorityDB struct {
	calls   atomic.Int64
	blocked chan struct{}
}

func (d *countingAuthorityDB) QueryRow(ctx context.Context, _ string, _ ...any) pgx.Row {
	d.calls.Add(1)
	return authorityTestRow{scan: func(dest ...any) error {
		if d.blocked != nil {
			select {
			case <-d.blocked:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		*dest[0].(*int64) = 1
		return nil
	}}
}

func TestMachineAuthorityRefreshReusesStaggeredObservations(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := &countingAuthorityDB{}
		cache := NewCachedMachineAuthority(nil, 5*time.Second)
		cache.pool = store
		p, c := uuid.New(), uuid.New()
		_, first, err := cache.LookupSnapshot(context.Background(), p, c)
		if err != nil {
			t.Fatal(err)
		}
		for range 100 {
			if _, _, err = cache.RefreshSnapshot(context.Background(), p, c); err != nil {
				t.Fatal(err)
			}
		}
		if store.calls.Load() != 1 {
			t.Fatalf("fresh observations reread %d times", store.calls.Load())
		}
		time.Sleep(3 * time.Second)
		for range 100 {
			if _, _, err = cache.RefreshSnapshot(context.Background(), p, c); err != nil {
				t.Fatal(err)
			}
		}
		if store.calls.Load() != 2 {
			t.Fatalf("staggered refreshes queried %d times", store.calls.Load())
		}
		_, next, err := cache.LookupSnapshot(context.Background(), p, c)
		if err != nil || !next.After(first) {
			t.Fatalf("healthy authority not renewed: %v", err)
		}
		cache.InvalidateCredential(c)
		if _, _, err = cache.LookupSnapshot(context.Background(), p, c); err != nil {
			t.Fatal(err)
		}
		if store.calls.Load() != 3 {
			t.Fatal("invalidation reused stale observation")
		}
	})
}

func TestMachineAuthorityRejectsInvalidatedFill(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := &countingAuthorityDB{blocked: make(chan struct{})}
		cache := NewCachedMachineAuthority(nil, time.Second)
		cache.pool = store
		p, c := uuid.New(), uuid.New()
		done := make(chan error, 1)
		go func() { _, _, err := cache.LookupSnapshot(context.Background(), p, c); done <- err }()
		synctest.Wait()
		cache.InvalidateCredential(c)
		close(store.blocked)
		if err := <-done; err == nil {
			t.Fatal("invalidated fill restored authority")
		}
		if len(cache.items) != 0 {
			t.Fatal("stale authority cached")
		}
	})
}

func TestVerifiedOperationDenialRetainsAPIKeyProvenance(t *testing.T) {
	key := []byte("machine-boundary-test-signing-key-000")
	parent, team, sandbox := uuid.New(), uuid.New(), uuid.New()
	now := time.Now()
	claim, err := auth.DeriveAPIKeyCapability(parent, team, sandbox, "sandbox-proxy", []auth.MachineOperation{auth.MachineOperationFileRead}, now.Add(time.Minute), now.Add(time.Minute), now)
	if err != nil {
		t.Fatal(err)
	}
	token, err := auth.SignMachineCapability(claim, key, now)
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(nil, &stubResolver{info: InstanceInfo{TeamID: team.String(), Status: "running", OwnershipState: auth.OwnershipMachine, MachineOwned: true, MachineOwnerPrincipalID: uuid.NewString()}}, zerolog.Nop()).WithAuth(key)
	req := httptest.NewRequest(http.MethodPost, "http://sandbox.test/files", nil)
	req.Header.Set(accessTokenHeader, token)
	w := httptest.NewRecorder()
	_, ok := h.authorizeBoxdRequest(w, req, sandbox.String(), "test")
	if ok || w.Code != http.StatusForbidden {
		t.Fatalf("operation denial=%d ok=%v", w.Code, ok)
	}
	caller, verified := VerifiedCallerFromContext(req.Context())
	if !verified || caller.CredentialID != parent || caller.CallerKind != "api_key" || caller.ActorID != uuid.Nil {
		t.Fatalf("incorrect verified provenance: %+v", caller)
	}
	req = httptest.NewRequest(http.MethodPost, "http://sandbox.test/files", nil)
	req.Header.Set(accessTokenHeader, token+"tampered")
	h.authorizeBoxdRequest(httptest.NewRecorder(), req, sandbox.String(), "test")
	if _, verified = VerifiedCallerFromContext(req.Context()); verified {
		t.Fatal("invalid signature retained identity")
	}
}

func TestAPIKeyExpiryCancelsBlockedFileTransport(t *testing.T) {
	key := []byte("machine-boundary-test-signing-key-000")
	parent, team, sandbox := uuid.New(), uuid.New(), uuid.New()
	started, closed := make(chan struct{}), make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(closed)
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	info := InstanceInfo{VMIP: "127.0.0.1", TeamID: team.String(), Status: "running", OwnershipState: auth.OwnershipMachine, MachineOwned: true, MachineOwnerPrincipalID: uuid.NewString()}
	h := NewHandler(nil, &stubResolver{info: info}, zerolog.Nop()).WithAuth(key).WithFiles()
	tr := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, u.Host)
	}}
	defer tr.CloseIdleConnections()
	h.transports = &transportCache{items: map[string]*transportEntry{sandbox.String(): {lifecycleKey: info.lifecycleKey(), transport: tr, lastUsed: time.Now()}}}
	now := time.Now()
	claim, err := auth.DeriveAPIKeyCapability(parent, team, sandbox, "sandbox-proxy", []auth.MachineOperation{auth.MachineOperationFileRead}, now.Add(time.Minute), now.Add(200*time.Millisecond), now)
	if err != nil {
		t.Fatal(err)
	}
	token, err := auth.SignMachineCapability(claim, key, now)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://sandbox.test/files?path=/tmp/example", nil)
	req.Header.Set(accessTokenHeader, token)
	done := make(chan struct{})
	go func() { defer close(done); h.serveFiles(httptest.NewRecorder(), req, sandbox.String()) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("upstream not reached")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("expired key left upstream stream open")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("transport handler leaked")
	}
	reconnect := httptest.NewRequest(http.MethodGet, "http://sandbox.test/files?path=/tmp/example", nil)
	reconnect.Header.Set(accessTokenHeader, token)
	w := httptest.NewRecorder()
	h.serveFiles(w, reconnect, sandbox.String())
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expired reconnect=%d", w.Code)
	}
}

func TestTeamDesktopCapabilityAdmission(t *testing.T) {
	key := []byte("machine-boundary-test-signing-key-000")
	team, sandbox, parent := uuid.New(), uuid.New(), uuid.New()
	now := time.Now()
	claim, err := auth.DeriveAPIKeyCapability(parent, team, sandbox, "sandbox-proxy", []auth.MachineOperation{auth.TeamOperationDesktopRead}, now.Add(time.Minute), time.Time{}, now)
	if err != nil {
		t.Fatal(err)
	}
	token, err := auth.SignMachineCapability(claim, key, now)
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(nil, &stubResolver{info: InstanceInfo{TeamID: team.String(), Status: "running", OwnershipState: auth.OwnershipMachine, MachineOwned: true, MachineOwnerPrincipalID: uuid.NewString()}}, zerolog.Nop()).WithAuth(key)
	for _, tc := range []struct {
		path, method string
		allowed      bool
	}{
		{desktopScreenshotPath, http.MethodPost, true}, {desktopStreamPath, http.MethodPost, true},
		{desktopSendKeyPath, http.MethodPost, false}, {desktopStepPath, http.MethodPost, false}, {desktopScreenshotPath, http.MethodGet, false},
		{desktopScreenshotPath + "/unknown", http.MethodPost, false},
	} {
		req := httptest.NewRequest(tc.method, "http://sandbox.test"+tc.path, nil)
		req.Header.Set(accessTokenHeader, token)
		_, ok := h.authorizeBoxdRequest(httptest.NewRecorder(), req, sandbox.String(), "desktop")
		if ok != tc.allowed {
			t.Fatalf("%s %s admission=%v", tc.method, tc.path, ok)
		}
	}
	claim.CallerKind = "machine"
	claim.ParentCredentialID = uuid.Nil
	claim.PrincipalID = uuid.New()
	claim.CredentialID = uuid.New()
	claim.LineageID = uuid.New()
	claim.RevocationGeneration = 1
	if _, err := auth.SignMachineCapability(claim, key, now); err == nil {
		t.Fatal("machine received team-only desktop authority")
	}
	if auth.NewTrustedIssuancePolicy([]auth.MachineOperation{auth.TeamOperationDesktopRead}, "sandbox-proxy").Allows(auth.TeamOperationDesktopRead) {
		t.Fatal("machine policy allowed desktop")
	}
}

type failedAuthorityDB struct{ err error }

func (d failedAuthorityDB) QueryRow(context.Context, string, ...any) pgx.Row {
	return authorityTestRow{scan: func(...any) error { return d.err }}
}
func TestMachineAuthorityDenialIsDistinctFromOutage(t *testing.T) {
	for _, err := range []error{pgx.ErrNoRows, context.DeadlineExceeded} {
		cache := NewCachedMachineAuthority(nil, time.Second)
		cache.pool = failedAuthorityDB{err: err}
		_, _, got := cache.LookupSnapshot(context.Background(), uuid.New(), uuid.New())
		if errors.Is(got, auth.ErrMachineCapabilityDenied) != errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("classification for %v: %v", err, got)
		}
	}
}

func TestMachineAuthoritySharedRefreshSurvivesCallerCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := &countingAuthorityDB{blocked: make(chan struct{})}
		cache := NewCachedMachineAuthority(nil, 5*time.Second)
		cache.pool = store
		p, c := uuid.New(), uuid.New()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		leader, sibling := make(chan error, 1), make(chan error, 1)
		go func() { _, _, err := cache.RefreshSnapshot(ctx, p, c); leader <- err }()
		synctest.Wait()
		go func() { _, _, err := cache.RefreshSnapshot(context.Background(), p, c); sibling <- err }()
		synctest.Wait()
		cancel()
		synctest.Wait()
		if err := <-leader; !errors.Is(err, context.Canceled) {
			t.Fatalf("disconnected caller did not stop waiting: %v", err)
		}
		select {
		case err := <-sibling:
			t.Fatalf("sibling lost its shared observation: %v", err)
		default:
		}
		close(store.blocked)
		if err := <-sibling; err != nil {
			t.Fatalf("healthy sibling refresh failed: %v", err)
		}
		if store.calls.Load() != 1 {
			t.Fatalf("refresh was not coalesced: %d queries", store.calls.Load())
		}
		if generation, _, err := cache.LookupSnapshot(context.Background(), p, c); err != nil || generation != 1 || store.calls.Load() != 1 {
			t.Fatalf("shared observation was not cached: generation=%d err=%v", generation, err)
		}
	})
}

func TestMachineAuthoritySharedRefreshStillTimesOut(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := &countingAuthorityDB{blocked: make(chan struct{})}
		cache := NewCachedMachineAuthority(nil, 5*time.Second)
		cache.pool = store
		started := time.Now()
		_, _, err := cache.RefreshSnapshot(context.Background(), uuid.New(), uuid.New())
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) != time.Second || len(cache.items) != 0 {
			t.Fatalf("shared query lost its bound: elapsed=%s err=%v", time.Since(started), err)
		}
	})
}
