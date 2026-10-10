package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog"
	"github.com/superserve-ai/sandbox/internal/auth"
)

type sandboxOwnerTestDB struct {
	calls           atomic.Int64
	principal, team *string
	err             error
	delay           time.Duration
}

func (d *sandboxOwnerTestDB) QueryRow(ctx context.Context, _ string, _ ...any) pgx.Row {
	d.calls.Add(1)
	return authorityTestRow{scan: func(dest ...any) error {
		if d.delay != 0 {
			time.Sleep(d.delay)
		}
		if d.err != nil {
			return d.err
		}
		*dest[0].(**string) = d.principal
		*dest[1].(**string) = d.team
		return nil
	}}
}

func TestOwnerlessLegacySandboxAdmissionRequiresDurableProof(t *testing.T) {
	seed := []byte("ownership-fallback-test-signing-key-00")
	sandbox, team, principal := uuid.NewString(), uuid.NewString(), uuid.NewString()
	wrongTeam := uuid.NewString()
	cases := []struct {
		name                              string
		db                                sandboxOwnerTestDB
		machine                           bool
		attestedPrincipal, creator, token string
		want                              int
		reads                             int64
	}{
		{name: "ordinary", want: 200, reads: 1},
		{name: "machine", db: sandboxOwnerTestDB{principal: &principal, team: &team}, want: 401, reads: 1},
		{name: "wrong team", db: sandboxOwnerTestDB{principal: &principal, team: &wrongTeam}, want: 503, reads: 1},
		{name: "missing row", db: sandboxOwnerTestDB{err: pgx.ErrNoRows}, want: 503, reads: 1},
		{name: "database unavailable", db: sandboxOwnerTestDB{err: errors.New("unavailable")}, want: 503, reads: 1},
		{name: "incomplete machine attestation", machine: true, want: 401},
		{name: "contradictory principal", attestedPrincipal: principal, want: 401},
		{name: "contradictory creator", creator: "creator", want: 401},
		{name: "unverified token", token: "invalid", want: 401},
	}
	for i := range cases {
		tc := &cases[i]
		t.Run(tc.name, func(t *testing.T) {
			server := newIPv4TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attestPreviewProtocol(w)
				_ = json.NewEncoder(w).Encode(map[string]any{"vm_ip": "10.0.0.2", "status": "running", "team_id": team, "owner_id": tc.creator, "machine_owned": tc.machine, "machine_owner_principal_id": tc.attestedPrincipal, "ownership_state": "unknown"})
			}))
			defer server.Close()
			store := NewCachedSandboxOwnership(nil)
			store.pool = &tc.db
			h := NewHandler(nil, NewVMDResolver(server.URL), zerolog.Nop()).WithAuth(seed).WithSandboxOwnership(store)
			token := tc.token
			if token == "" {
				token = auth.ComputeAccessToken(seed, sandbox)
			}
			info, failure := h.authorizeSandboxRequest(context.Background(), token, sandbox)
			code := 200
			if failure != nil {
				code = failure.Status
			}
			if code != tc.want {
				t.Fatalf("status = %d, failure = %#v", code, failure)
			}
			if tc.want == 200 && (info.OwnershipState != auth.OwnershipOrdinary || info.OwnerID != "") {
				t.Fatalf("ordinary result = %#v", info)
			}
			if n := tc.db.calls.Load(); n != tc.reads {
				t.Fatalf("durable reads = %d, want %d", n, tc.reads)
			}
		})
	}
}

func TestSandboxOwnershipCacheBoundedFreshness(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		db := &sandboxOwnerTestDB{delay: time.Millisecond}
		cache := NewCachedSandboxOwnership(nil)
		cache.pool = db
		sandbox, team := uuid.NewString(), uuid.NewString()
		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Go(func() {
				if _, err := cache.lookup(context.Background(), sandbox, team); err != nil {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		if n := db.calls.Load(); n != 1 {
			t.Fatalf("concurrent reads = %d", n)
		}
		time.Sleep(4 * time.Second)
		if _, err := cache.lookup(context.Background(), sandbox, team); err != nil {
			t.Fatal(err)
		}
		if n := db.calls.Load(); n != 1 {
			t.Fatalf("premature refresh = %d", n)
		}
		time.Sleep(time.Second)
		db.err = errors.New("offline")
		if _, err := cache.lookup(context.Background(), sandbox, team); err == nil {
			t.Fatal("expired classification survived database outage")
		}
		if n := db.calls.Load(); n != 2 {
			t.Fatalf("refresh reads = %d", n)
		}
	})
}

func TestLegacyVMDOrdinaryOwnershipProof(t *testing.T) {
	seed := []byte("legacy-vmd-ownership-test-signing-key")
	sandbox, team, creator, principal := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	cases := []struct {
		name    string
		creator string
		fields  map[string]any
		db      sandboxOwnerTestDB
		want    int
		reads   int64
	}{
		{name: "legacy creator", creator: creator, want: 200, reads: 1},
		{name: "legacy ownerless", want: 200, reads: 1},
		{name: "legacy machine association", creator: creator, db: sandboxOwnerTestDB{principal: &principal, team: &team}, want: 401, reads: 1},
		{name: "legacy unavailable proof", creator: creator, db: sandboxOwnerTestDB{err: errors.New("unavailable")}, want: 503, reads: 1},
		{name: "legacy missing sandbox", creator: creator, db: sandboxOwnerTestDB{err: pgx.ErrNoRows}, want: 503, reads: 1},
		{name: "explicit unknown creator", creator: creator, fields: map[string]any{"ownership_state": "unknown"}, want: 401},
		{name: "explicit empty state", creator: creator, fields: map[string]any{"ownership_state": ""}, want: 503},
		{name: "explicit null state", fields: map[string]any{"ownership_state": nil}, want: 503},
		{name: "explicit invalid state", fields: map[string]any{"ownership_state": "invalid"}, want: 503},
		{name: "machine flag", creator: creator, fields: map[string]any{"machine_owned": true}, want: 401},
		{name: "machine principal", creator: creator, fields: map[string]any{"machine_owner_principal_id": principal}, want: 401},
		{name: "reserved machine creator", creator: "machine:" + principal, want: 401},
	}
	for i := range cases {
		tc := &cases[i]
		t.Run(tc.name, func(t *testing.T) {
			server := newIPv4TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/instances/__healthcheck__" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				attestPreviewProtocol(w)
				body := map[string]any{"vm_ip": "10.0.0.2", "status": "running", "team_id": team, "owner_id": tc.creator}
				for field, value := range tc.fields {
					body[field] = value
				}
				_ = json.NewEncoder(w).Encode(body)
			}))
			defer server.Close()
			resolver := NewVMDResolver(server.URL)
			if ready, err := resolver.ReadyWithMachineIdentity(context.Background()); err != nil || ready {
				t.Fatalf("legacy VMD readiness = %v, %v", ready, err)
			}
			store := NewCachedSandboxOwnership(nil)
			store.pool = &tc.db
			h := NewHandler(nil, resolver, zerolog.Nop()).WithAuth(seed).WithSandboxOwnership(store)
			info, failure := h.authorizeSandboxRequest(context.Background(), auth.ComputeAccessToken(seed, sandbox), sandbox)
			code := http.StatusOK
			if failure != nil {
				code = failure.Status
			}
			if code != tc.want || tc.db.calls.Load() != tc.reads {
				t.Fatalf("status=%d reads=%d failure=%+v; want status=%d reads=%d", code, tc.db.calls.Load(), failure, tc.want, tc.reads)
			}
			if code == http.StatusOK && (info.OwnershipState != auth.OwnershipOrdinary || info.OwnerID != tc.creator) {
				t.Fatalf("ordinary proof changed creator attribution: %+v", info)
			}
		})
	}
}

func TestSandboxOwnershipRejectsDelayedResult(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cache := NewCachedSandboxOwnership(nil)
		cache.pool = &sandboxOwnerTestDB{delay: time.Second}
		if _, err := cache.lookup(context.Background(), uuid.NewString(), uuid.NewString()); err == nil {
			t.Fatal("late ordinary proof accepted")
		}
		if len(cache.items) != 0 {
			t.Fatal("late proof cached")
		}
	})
}

func TestSandboxOwnershipLeaderCancellationSparesWaiters(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cache := NewCachedSandboxOwnership(nil)
		db := &sandboxOwnerTestDB{delay: 100 * time.Millisecond}
		cache.pool = db
		sandbox, team := uuid.NewString(), uuid.NewString()
		leader, cancel := context.WithCancel(context.Background())
		leaderErr := make(chan error, 1)
		go func() {
			_, err := cache.lookup(leader, sandbox, team)
			leaderErr <- err
		}()
		synctest.Wait()
		siblingErr := make(chan error, 1)
		go func() {
			_, err := cache.lookup(context.Background(), sandbox, team)
			siblingErr <- err
		}()
		synctest.Wait()
		cancel()
		if err := <-leaderErr; !errors.Is(err, context.Canceled) {
			t.Fatalf("leader error = %v", err)
		}
		if err := <-siblingErr; err != nil {
			t.Fatalf("sibling failed with leader: %v", err)
		}
		if db.calls.Load() != 1 {
			t.Fatalf("queries = %d, want one shared lookup", db.calls.Load())
		}
	})
}
