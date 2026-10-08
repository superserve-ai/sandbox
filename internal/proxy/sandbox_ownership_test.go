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
