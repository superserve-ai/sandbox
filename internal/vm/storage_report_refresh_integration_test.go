//go:build integration

package vm

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestIntegration_StorageReportPeriodicRefresh(t *testing.T) {
	for _, boundary := range []string{"activation", "billing_enabled"} {
		t.Run(boundary, func(t *testing.T) {
			pool := storageRefreshPool(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			hostID, incarnation := "example-refresh-host", uuid.New()
			teamID, sandboxID := uuid.New(), uuid.New()
			exec := func(query string, args ...any) {
				t.Helper()
				if _, err := pool.Exec(ctx, query, args...); err != nil {
					t.Fatal(err)
				}
			}
			exec(`INSERT INTO host(id,vmd_addr,proxy_addr,region,capacity_memory_mib,capacity_vcpus,incarnation_id,peer_generation)
				VALUES ($1,'192.0.2.1:50051','192.0.2.1:5007','example-region',1024,1,$2,1)`, hostID, incarnation)
			exec(`INSERT INTO sandbox(id,team_id,name,status,host_id,vcpu_count,memory_mib,disk_mib)
				VALUES ($1,$2,'example-refresh','starting',$3,1,1024,8)`, sandboxID, teamID, hostID)
			exec(`INSERT INTO feature_flag(key,enabled) VALUES ('billing_metrics_write',true)`)
			activate := func() {
				t.Helper()
				if err := db.New(pool).ActivateSandbox(ctx, db.ActivateSandboxParams{
					ID: sandboxID, TeamID: teamID, VcpuCount: 1, MemoryMib: 1024,
				}); err != nil {
					t.Fatal(err)
				}
			}
			if boundary == "billing_enabled" {
				activate()
				exec(`UPDATE feature_flag SET enabled=false WHERE key='billing_metrics_write'`)
			}

			gin.SetMode(gin.TestMode)
			router := gin.New()
			router.POST("/internal/hosts/:host_id/storage-reports", (&api.Handlers{Pool: pool}).HostStorageReport)
			server := httptest.NewServer(router)
			defer server.Close()
			cache := newHeartbeatStorageCache(t.TempDir(), zerolog.Nop(), incarnation.String())
			measurements := []heartbeatStorageMeasurement{{SandboxID: sandboxID.String(), AllocatedBytes: 16 << 20}}
			if err := cache.store(measurements); err != nil {
				t.Fatal(err)
			}
			first := cache.pendingSnapshot()[0]
			kick := make(chan struct{}, 1)
			publisherDone := make(chan struct{})
			go func() {
				defer close(publisherDone)
				storageReportLoop(ctx, server.Client(), HeartbeatConfig{HostID: hostID, IncarnationID: incarnation.String()},
					server.URL+"/internal/hosts/"+hostID+"/storage-reports", "", cache, kick, zerolog.Nop())
			}()
			defer func() { cancel(); <-publisherDone }()
			waitStorageRefresh(t, "initial publication acknowledgement", func() bool {
				return len(cache.pendingSnapshot()) == 0
			})
			var receivedAt time.Time
			if err := pool.QueryRow(ctx, `SELECT received_at FROM host_storage_report WHERE report_id=$1`, first.reportID).Scan(&receivedAt); err != nil {
				t.Fatal(err)
			}
			if boundary == "activation" {
				activate()
				var activatedAt time.Time
				if err := pool.QueryRow(ctx, `SELECT started_at FROM sandbox_storage_interval WHERE sandbox_id=$1 AND ended_at IS NULL`, sandboxID).Scan(&activatedAt); err != nil {
					t.Fatal(err)
				}
				if !activatedAt.After(receivedAt) {
					t.Fatal("activation must open its logical interval after the first report receipt")
				}
			}
			api.StartStorageReportWorker(ctx, pool)
			waitStorageRefresh(t, "first report processing", func() bool {
				var state string
				if err := pool.QueryRow(ctx, `SELECT state FROM host_storage_report WHERE report_id=$1`, first.reportID).Scan(&state); err != nil {
					t.Fatal(err)
				}
				return state == "processed"
			})
			var diskMiB int
			if err := pool.QueryRow(ctx, `SELECT disk_mib FROM sandbox_storage_interval WHERE sandbox_id=$1 AND ended_at IS NULL`, sandboxID).Scan(&diskMiB); err != nil {
				t.Fatal(err)
			}
			if diskMiB != 8 {
				t.Fatalf("initial report should be skipped at %s boundary, got %d MiB", boundary, diskMiB)
			}
			if boundary == "billing_enabled" {
				exec(`UPDATE feature_flag SET enabled=true WHERE key='billing_metrics_write'`)
			}
			if err := cache.store(measurements); err != nil {
				t.Fatal(err)
			}
			cache.mu.Lock()
			cache.sentAt = time.Now().Add(-overlayStorageSampleInterval)
			cache.mu.Unlock()
			kick <- struct{}{}
			waitStorageRefresh(t, "periodic observation correcting the allocation", func() bool {
				var corrected bool
				if err := pool.QueryRow(ctx, `SELECT EXISTS (
					SELECT 1 FROM host_storage_report r JOIN sandbox_storage_interval i ON i.started_at=r.received_at
					WHERE r.host_id=$1 AND r.report_id<>$2 AND r.ingest_seq=2 AND r.state='processed'
					  AND r.received_at>$3 AND i.sandbox_id=$4 AND i.ended_at IS NULL AND i.disk_mib=16
				)`, hostID, first.reportID, receivedAt, sandboxID).Scan(&corrected); err != nil {
					t.Fatal(err)
				}
				return corrected
			})
		})
	}
}

func storageRefreshPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("DATABASE_URL must name a migrated disposable integration database")
	}
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	// Production queries operate on connection-local copies of the migrated
	// tables. No shared schema reset or persistent fixture cleanup is needed.
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	for _, table := range []string{"host", "sandbox", "sandbox_active_interval", "sandbox_compute_billing_interval", "sandbox_storage_interval", "host_storage_report", "legacy_host_storage_report", "feature_flag", "team_feature_flag"} {
		if _, err := pool.Exec(t.Context(), fmt.Sprintf(`CREATE TEMP TABLE %s (LIKE public.%s INCLUDING ALL)`, table, table)); err != nil {
			t.Fatal(err)
		}
	}
	// LIKE copies constraints and indexes but not the receipt's digest trigger.
	if _, err := pool.Exec(t.Context(), `CREATE TRIGGER refresh_report_payload_hash
		BEFORE INSERT OR UPDATE OF payload ON host_storage_report FOR EACH ROW
		EXECUTE FUNCTION public.set_host_storage_report_payload_hash()`); err != nil {
		t.Fatal(err)
	}
	return pool
}

func waitStorageRefresh(t *testing.T, operation string, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(12 * time.Second)
	for !ready() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", operation)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
