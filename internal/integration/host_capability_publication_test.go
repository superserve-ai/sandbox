//go:build integration

package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/preview"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

func TestIntegration_PublicationHeartbeatOverlap(t *testing.T) {
	t.Setenv("HOST_CAPABILITY_CACHE_TTL", "0")
	for _, withdrawal := range []string{"", preview.HostCapabilityPorts, preview.HostCapabilityPortAccess} {
		name := withdrawal
		if name == "" {
			name = "stable"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			team, key := seedTeamAndKey(t)
			caps := []string{preview.HostCapabilityPorts, preview.HostCapabilityPortAccess}
			host := seedActivePreviewHost(t, caps...)
			sid := seedPrivatePreviewSandbox(t, team, host, "publication-overlap")
			if _, err := testPool.Exec(ctx, `INSERT INTO team_feature_flag (team_id, key, enabled)
    VALUES ($1, 'billing_metrics_write', true)
    ON CONFLICT (team_id, key) DO UPDATE SET enabled = EXCLUDED.enabled`, team); err != nil {
				t.Fatal(err)
			}
			if _, err := testPool.Exec(ctx, `DELETE FROM sandbox_storage_interval WHERE sandbox_id=$1`, sid); err != nil {
				t.Fatal(err)
			}
			for _, sql := range []string{
				`UPDATE sandbox_preview_policy SET access='public', default_access='public' WHERE sandbox_id=$1`,
				`UPDATE sandbox_published_port SET access='public' WHERE sandbox_id=$1`,
			} {
				if _, err := testPool.Exec(ctx, sql, sid); err != nil {
					t.Fatal(err)
				}
			}
			var before int64
			if err := testPool.QueryRow(ctx, `SELECT revision FROM sandbox_preview_policy WHERE sandbox_id=$1`, sid).Scan(&before); err != nil {
				t.Fatal(err)
			}
			readPublicationState := func() string {
				t.Helper()
				var state string
				if err := testPool.QueryRow(ctx, `SELECT jsonb_build_object(
    'policy', to_jsonb(p),
    'ports', (SELECT jsonb_agg(to_jsonb(pp) ORDER BY pp.port)
              FROM sandbox_published_port pp WHERE pp.sandbox_id=p.sandbox_id)
   )::text FROM sandbox_preview_policy p WHERE p.sandbox_id=$1`, sid).Scan(&state); err != nil {
					t.Fatal(err)
				}
				return state
			}
			beforeState := readPublicationState()
			var pushes atomic.Int32
			vmd := &stubVMD{updatePreviewFn: func(ctx context.Context, instanceID, access string, ports map[int32]vmdclient.PortPolicy, revision int64) error {
				pushes.Add(1)
				if instanceID != sid.String() || access != preview.AccessPublic {
					t.Errorf("unexpected policy target/access: sandbox=%s access=%s", instanceID, access)
				}
				if len(ports) != 2 {
					t.Errorf("delivered ports=%v, want existing port 3000 and published port 4000", ports)
				}
				for _, port := range []int32{3000, 4000} {
					if policy, ok := ports[port]; !ok || policy != (vmdclient.PortPolicy{Access: preview.AccessPublic}) {
						t.Errorf("delivered port %d: policy=%+v present=%t", port, policy, ok)
					}
				}
				var committed int64
				var committedPorts int
				if err := testPool.QueryRow(ctx, `SELECT revision,
    (SELECT count(*) FROM sandbox_published_port
     WHERE sandbox_id=$1 AND port IN (3000, 4000) AND access='public')
    FROM sandbox_preview_policy WHERE sandbox_id=$1`, sid).Scan(&committed, &committedPorts); err != nil {
					return err
				}
				if committed != revision || committed != before+1 || committedPorts != 2 {
					t.Errorf("policy pushed before publication commit: committed=%d pushed=%d ports=%d", committed, revision, committedPorts)
				}
				return nil
			}}
			router := previewTokenIntegrationRouter(t, vmd, []byte("integration-preview-seed-32-bytes!!"))
			writer, err := testPool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Rollback(context.Background())
			if _, err := writer.Exec(ctx, `UPDATE host SET last_heartbeat_at=last_heartbeat_at+interval '1 second' WHERE id=$1`, host); err != nil {
				t.Fatal(err)
			}
			advertised := make([]string, 0, len(caps))
			for _, capability := range caps {
				if capability != withdrawal {
					advertised = append(advertised, capability)
				}
			}
			if err := db.New(writer).SyncHostCapabilities(ctx, db.SyncHostCapabilitiesParams{HostID: host, Capabilities: advertised}); err != nil {
				t.Fatal(err)
			}
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/sandboxes/"+sid.String()+"/preview-ports", strings.NewReader(`{"port":4000,"access":"public"}`))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-API-Key", key)
				response := httptest.NewRecorder()
				router.ServeHTTP(response, req)
				waitBookkeeping()
				done <- response
			}()
			// Preflight must read the old committed generation without blocking. Only
			// the mutation's host lock may wait on this heartbeat transaction.
			ticker := time.NewTicker(5 * time.Millisecond)
			defer ticker.Stop()
			for {
				var blocked bool
				err := testPool.QueryRow(ctx, `SELECT EXISTS (
     SELECT 1 FROM pg_stat_activity
     WHERE $1::int = ANY(pg_blocking_pids(pid))
       AND query LIKE '-- name: LockHostForCapabilities %'
    )`, writer.Conn().PgConn().PID()).Scan(&blocked)
				if err != nil {
					t.Fatal(err)
				}
				if blocked {
					break
				}
				select {
				case response := <-done:
					t.Fatalf("publication finished without waiting: %d %s", response.Code, response.Body.String())
				case <-ctx.Done():
					t.Fatal("publication lock wait not observed:", ctx.Err())
				case <-ticker.C:
				}
			}
			// The publication now holds the sandbox lock and waits on this host.
			// Both opening and replacing an interval must allow the heartbeat to
			// finish despite the interval's sandbox foreign-key check.
			for _, diskMiB := range []int32{256, 512} {
				rows, err := db.New(writer).UpdateHostSandboxStorageMeasurements(ctx, db.UpdateHostSandboxStorageMeasurementsParams{
					HostID: host, SandboxIds: []uuid.UUID{sid}, DiskMib: []int32{diskMiB},
				})
				if err != nil || rows != 1 {
					t.Fatalf("heartbeat storage measurement %d: rows=%d err=%v", diskMiB, rows, err)
				}
			}
			if err := writer.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			var intervals, activeIntervals int
			if err := testPool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE ended_at IS NULL AND disk_mib=512)
    FROM sandbox_storage_interval WHERE sandbox_id=$1`, sid).Scan(&intervals, &activeIntervals); err != nil {
				t.Fatal(err)
			}
			if intervals != 2 || activeIntervals != 1 {
				t.Fatalf("heartbeat storage intervals=%d active=%d, want 2 and 1", intervals, activeIntervals)
			}
			var response *httptest.ResponseRecorder
			select {
			case response = <-done:
			case <-ctx.Done():
				t.Fatal("publication failed to complete:", ctx.Err())
			}
			want := http.StatusOK
			if withdrawal != "" {
				want = http.StatusConflict
			}
			if response.Code != want {
				t.Fatalf("publication=%d %s, want %d", response.Code, response.Body.String(), want)
			}
			var after int64
			var ports int
			if err := testPool.QueryRow(ctx, `SELECT revision, (SELECT count(*) FROM sandbox_published_port WHERE sandbox_id=$1 AND port=4000) FROM sandbox_preview_policy WHERE sandbox_id=$1`, sid).Scan(&after, &ports); err != nil {
				t.Fatal(err)
			}
			if withdrawal != "" {
				if afterState := readPublicationState(); afterState != beforeState {
					t.Fatalf("rejected publication did not roll back policy and ports: before=%s after=%s", beforeState, afterState)
				}
				if after != before || ports != 0 || pushes.Load() != 0 {
					t.Fatalf("rejected publication changed state: revision %d -> %d, ports=%d pushes=%d", before, after, ports, pushes.Load())
				}
			} else if after != before+1 || ports != 1 || pushes.Load() != 1 {
				t.Fatalf("publication not committed/delivered: revision %d -> %d ports=%d pushes=%d", before, after, ports, pushes.Load())
			}
		})
	}
}
