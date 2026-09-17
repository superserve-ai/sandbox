//go:build integration

package integration

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/preview"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

// Measure acquisition through transaction completion, including lock wait and
// the final round trip. This is an upper bound on server-side lock retention.
// Recognizing the former query also lets the runner use this same harness on
// the baseline revision for a before/after comparison.
type lifecycleLockTiming struct {
	mu         sync.Mutex
	locks      map[*pgx.Conn]time.Time
	statements int
	completed  int
	held       time.Duration
	maxHeld    time.Duration
}

func (m *lifecycleLockTiming) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.statements++
	isLock := strings.HasPrefix(data.SQL, "-- name: LockHostForCapabilities ") ||
		(strings.HasPrefix(data.SQL, "-- name: HostHasCapabilities ") && strings.Contains(data.SQL, "FOR SHARE"))
	if isLock {
		if _, exists := m.locks[conn]; !exists {
			m.locks[conn] = time.Now()
		}
	}
	return ctx
}

func (m *lifecycleLockTiming) TraceQueryEnd(_ context.Context, conn *pgx.Conn, _ pgx.TraceQueryEndData) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if started, ok := m.locks[conn]; ok && conn.PgConn().TxStatus() == 'I' {
		elapsed := time.Since(started)
		m.held += elapsed
		m.maxHeld = max(m.maxHeld, elapsed)
		m.completed++
		delete(m.locks, conn)
	}
}

func (m *lifecycleLockTiming) reset(t *testing.T) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.locks) != 0 {
		t.Fatal("host validation transaction remains open between requests")
	}
	m.statements, m.completed, m.held, m.maxHeld = 0, 0, 0, 0
}

func (m *lifecycleLockTiming) requireReleased(t *testing.T) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.locks) != 0 {
		t.Error("VMD called while a host validation transaction remains open")
	}
}

func TestIntegration_HostCapabilityLifecycleTiming(t *testing.T) {
	const samples = 20
	t.Setenv("HOST_CAPABILITY_CACHE_TTL", "0")
	ctx := t.Context()
	measurement := &lifecycleLockTiming{locks: make(map[*pgx.Conn]time.Time)}
	poolConfig := testPool.Config()
	poolConfig.ConnConfig.Tracer = measurement
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	vmd := &stubVMD{
		resumeFn: func() { measurement.requireReleased(t) },
		updatePreviewFn: func(context.Context, string, string, map[int32]vmdclient.PortPolicy, int64) error {
			measurement.requireReleased(t)
			return nil
		},
		updateNetworkFn: func(context.Context, string, []string, []string, []string) error {
			measurement.requireReleased(t)
			return nil
		},
	}
	h := api.NewHandlers(vmd, db.New(pool), &config.Config{
		SandboxAccessTokenSeed: []byte("integration-preview-seed-32-bytes!!"),
		DefaultHostID:          testDefaultHostID,
		SystemTeamID:           testSystemTeamID.String(),
	})
	h.Pool = pool
	registerTestHandlers(h)
	router := api.SetupRouter(ctx, h, pool)
	teamID, key := seedTeamAndKey(t)
	// Allow the create samples, one warmup, and two lifecycle fixtures.
	if _, err := testPool.Exec(ctx, `UPDATE team SET max_sandboxes = $2 WHERE id = $1`, teamID, samples+3); err != nil {
		t.Fatalf("set timing team sandbox quota: %v", err)
	}
	host := seedActivePreviewHost(t, preview.HostCapabilityPorts, preview.HostCapabilityPortAccess,
		preview.HostCapabilityPortTokens, preview.HostCapabilityPortBrowserAuth)

	t.Run("create", func(t *testing.T) {
		var elapsed time.Duration
		var statements int
		for i := 0; i <= samples; i++ {
			measurement.reset(t)
			started := time.Now()
			w := do(router, http.MethodPost, "/sandboxes", key, fmt.Sprintf(`{"name":"capability-timing-%d"}`, i))
			duration := time.Since(started)
			if w.Code != http.StatusCreated {
				t.Fatalf("create=%d %s", w.Code, w.Body.String())
			}
			measurement.requireReleased(t)
			measurement.mu.Lock()
			queries := measurement.statements
			measurement.mu.Unlock()
			if i > 0 {
				elapsed += duration
				statements += queries
			}
		}
		t.Logf("create: samples=%d mean handler+bookkeeping=%s mean DB statements=%.1f (stub VMD, uncontended DB)", samples, elapsed/samples, float64(statements)/samples)
	})

	for _, operation := range []string{"resume", "preview-mutation"} {
		t.Run(operation, func(t *testing.T) {
			sid := seedPrivatePreviewSandbox(t, teamID, host, "timing-"+operation)
			base := "/sandboxes/" + sid.String()
			var elapsed, held, maxHeld time.Duration
			var statements, transactions int
			// The first request warms the pool, SQL statements, and handler caches.
			for i := 0; i <= samples; i++ {
				path, body, want := base+"/resume", "", http.StatusOK
				if operation == "resume" {
					if w := do(router, http.MethodPost, base+"/pause", key, ""); w.Code != http.StatusNoContent {
						t.Fatalf("pause=%d %s", w.Code, w.Body.String())
					}
				} else {
					path, body, want = base+"/preview-ports", `{"port":4000,"access":"private"}`, http.StatusOK
				}
				measurement.reset(t)
				started := time.Now()
				w := do(router, http.MethodPost, path, key, body)
				duration := time.Since(started)
				if w.Code != want {
					t.Fatalf("%s=%d %s, want %d", operation, w.Code, w.Body.String(), want)
				}
				measurement.mu.Lock()
				count, queries, durationHeld, longest, open := measurement.completed, measurement.statements, measurement.held, measurement.maxHeld, len(measurement.locks)
				measurement.mu.Unlock()
				if count == 0 || open != 0 {
					t.Fatalf("host validation transactions: completed=%d open=%d", count, open)
				}
				if i > 0 {
					elapsed += duration
					held += durationHeld
					maxHeld = max(maxHeld, longest)
					statements += queries
					transactions += count
				}
			}
			t.Logf("%s: samples=%d mean handler+bookkeeping=%s mean DB statements=%.1f host transactions=%d mean lock acquisition through completion=%s max=%s (stub VMD, uncontended DB)",
				operation, samples, elapsed/samples, float64(statements)/samples, transactions, held/time.Duration(transactions), maxHeld)
		})
	}
}
