package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/rs/zerolog"
	"github.com/superserve-ai/sandbox/internal/auth"
)

type machineReadinessDB struct {
	calls        atomic.Int64
	err          error
	ownershipErr error
	wait         bool
}

func (d *machineReadinessDB) QueryRow(ctx context.Context, sql string, _ ...any) pgx.Row {
	d.calls.Add(1)
	return authorityTestRow{scan: func(dest ...any) error {
		if d.wait {
			<-ctx.Done()
			return ctx.Err()
		}
		if d.err != nil {
			return d.err
		}
		if sql == machineOwnershipReadinessSQL && d.ownershipErr != nil {
			return d.ownershipErr
		}
		*dest[0].(*bool) = false // zero-row probe still proves schema and permissions
		return nil
	}}
}

func machineReadinessHandler(store *machineReadinessDB) *Handler {
	authority := NewCachedMachineAuthority(nil, time.Second)
	authority.pool = store
	ownership := NewCachedSandboxOwnership(nil)
	ownership.pool = store
	return NewHandler(nil, nil, zerolog.Nop()).WithAuth([]byte("machine-readiness-test-key-0123456")).WithMachineAuthority(authority).WithSandboxOwnership(ownership)
}

func TestMachineReadinessFailsClosed(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Handler, *machineReadinessDB)
	}{
		{"missing signer", func(h *Handler, _ *machineReadinessDB) { h.seedKey = nil }},
		{"missing authority", func(h *Handler, _ *machineReadinessDB) { h.machineAuthority = nil }},
		{"missing ownership", func(h *Handler, _ *machineReadinessDB) { h.sandboxOwnership = nil }},
		{"missing database", func(h *Handler, _ *machineReadinessDB) {
			h.WithMachineAuthority(NewCachedMachineAuthority(nil, time.Second))
		}},
		{"missing schema", func(_ *Handler, d *machineReadinessDB) { d.err = &pgconn.PgError{Code: "42P01"} }},
		{"missing authority SELECT grant", func(_ *Handler, d *machineReadinessDB) { d.err = &pgconn.PgError{Code: "42501"} }},
		{"missing ownership SELECT grant", func(_ *Handler, d *machineReadinessDB) { d.ownershipErr = &pgconn.PgError{Code: "42501"} }},
		{"database outage", func(_ *Handler, d *machineReadinessDB) { d.err = errors.New("unavailable") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &machineReadinessDB{}
			h := machineReadinessHandler(store)
			tc.mutate(h, store)
			if h.MachineIdentityReady(context.Background()) {
				t.Fatal("incompatible serving instance reported machine readiness")
			}
		})
	}
}

func TestMachineReadinessRefreshesBoundedCache(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := &machineReadinessDB{}
		h := machineReadinessHandler(store)
		var wg sync.WaitGroup
		for i := 0; i < 32; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if !h.MachineIdentityReady(context.Background()) {
					t.Error("healthy serving instance not ready")
				}
			}()
		}
		wg.Wait()
		if calls := store.calls.Load(); calls != 2 {
			t.Fatalf("concurrent health requests made %d queries; want one authority and one ownership probe", calls)
		}
		store.err = errors.New("database went away")
		if !h.MachineIdentityReady(context.Background()) {
			t.Fatal("healthy observation not retained for its bounded cache lifetime")
		}
		time.Sleep(machineReadinessTTL)
		if h.MachineIdentityReady(context.Background()) {
			t.Fatal("old readiness survived outage beyond cache lifetime")
		}
		store.err = nil
		time.Sleep(machineReadinessTTL)
		if !h.MachineIdentityReady(context.Background()) {
			t.Fatal("readiness did not recover")
		}
	})
}

func TestMachineReadinessBoundsDatabaseProbe(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := machineReadinessHandler(&machineReadinessDB{wait: true})
		started := time.Now()
		if h.MachineIdentityReady(context.Background()) {
			t.Fatal("hung database reported ready")
		}
		if elapsed := time.Since(started); elapsed != machineReadinessTimeout {
			t.Fatalf("probe took %v", elapsed)
		}
	})
}

func TestMachineReadinessRequiresVMDProtocolInSameProbe(t *testing.T) {
	for _, tc := range []struct {
		name, revision    string
		status            int
		ordinary, machine bool
	}{
		{"old VMD 404", "", 404, true, false},
		{"old VMD 200", "", 200, true, false},
		{"current VMD 404", auth.MachineIdentityRevision, 404, true, true},
		{"current VMD 200", auth.MachineIdentityRevision, 200, true, true},
		{"unknown revision", "machine-identity-v99", 404, true, false},
		{"failed VMD", auth.MachineIdentityRevision, 503, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Header.Get(auth.ProxyMachineIdentityHeader) != auth.MachineIdentityRevision {
					t.Error("proxy failed to advertise ownership enforcement")
				}
				w.Header().Set(auth.VMDMachineIdentityHeader, tc.revision)
				w.WriteHeader(tc.status)
			}))
			defer server.Close()
			h := NewHandler(nil, NewVMDResolver(server.URL), zerolog.Nop())
			ordinary, machine := h.ResolverReadiness(context.Background())
			if ordinary != tc.ordinary || machine != tc.machine || calls.Load() != 1 {
				t.Fatalf("readiness=%v/%v calls=%d", ordinary, machine, calls.Load())
			}
		})
	}
}

func TestMachineReadinessProtocolSentOnInstanceLookup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(auth.ProxyMachineIdentityHeader) != auth.MachineIdentityRevision {
			t.Error("instance lookup omitted machine protocol")
		}
		attestPreviewProtocol(w)
		_, _ = w.Write([]byte(`{"vm_ip":"10.0.0.2","status":"running","ownership_state":"ordinary"}`))
	}))
	defer server.Close()
	_, err := NewVMDResolver(server.URL).Lookup(context.Background(), "example-sandbox")
	if err != nil {
		t.Fatal(err)
	}
}
