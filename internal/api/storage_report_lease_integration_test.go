//go:build integration

package api

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type storageLeaseFixture struct {
	pool                    *pgxpool.Pool
	hostID                  string
	incarnationID, reportID uuid.UUID
	sandboxID               uuid.UUID
	receivedAt              time.Time
	measurements            []storageReportMeasurement
}

func newStorageLeaseFixture(t *testing.T) storageLeaseFixture {
	t.Helper()
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("DATABASE_URL must name the migrated disposable integration database")
	}
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	// All production SQL runs on one connection with isolated temporary tables.
	// This test never resets or writes the shared integration schema.
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	_, err = pool.Exec(t.Context(), `
		CREATE TEMP TABLE host (id text PRIMARY KEY, incarnation_id uuid);
		CREATE TEMP TABLE sandbox (id uuid PRIMARY KEY, team_id uuid NOT NULL, host_id text NOT NULL, created_at timestamptz NOT NULL, destroyed_at timestamptz);
		CREATE TEMP TABLE sandbox_storage_interval (
			id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
			sandbox_id uuid NOT NULL, team_id uuid NOT NULL, disk_mib int NOT NULL,
			started_at timestamptz NOT NULL, ended_at timestamptz, end_reason text);
		CREATE UNIQUE INDEX storage_lease_open_interval ON sandbox_storage_interval(sandbox_id) WHERE ended_at IS NULL;
		CREATE TEMP TABLE host_storage_report (
			host_id text NOT NULL, incarnation_id uuid NOT NULL, report_id uuid NOT NULL,
			ingest_seq bigint NOT NULL, received_at timestamptz NOT NULL, payload jsonb,
			state text NOT NULL, next_measurement_index int NOT NULL,
			next_attempt_at timestamptz NOT NULL DEFAULT now(), attempts int NOT NULL DEFAULT 0,
			processed_at timestamptz, last_error text, processing_generation bigint NOT NULL DEFAULT 0,
			PRIMARY KEY(host_id, incarnation_id, report_id));
		CREATE TEMP TABLE feature_flag (key text PRIMARY KEY, enabled boolean);
		CREATE TEMP TABLE team_feature_flag (team_id uuid, key text, enabled boolean);
		INSERT INTO feature_flag VALUES ('billing_metrics_write', true);`)
	if err != nil {
		t.Fatal(err)
	}
	fixture := storageLeaseFixture{
		pool: pool, hostID: "example-storage-lease", incarnationID: uuid.New(), reportID: uuid.New(),
		sandboxID: uuid.New(), receivedAt: time.Now().UTC().Truncate(time.Microsecond),
	}
	fixture.measurements = []storageReportMeasurement{{SandboxID: fixture.sandboxID.String(), AllocatedBytes: 16 << 20}}
	teamID := uuid.New()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(t.Context(), sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO host VALUES ($1,$2)`, fixture.hostID, fixture.incarnationID)
	exec(`INSERT INTO sandbox VALUES ($1,$2,$3,$4,NULL)`, fixture.sandboxID, teamID, fixture.hostID, fixture.receivedAt.Add(-time.Hour))
	exec(`INSERT INTO sandbox_storage_interval(sandbox_id,team_id,disk_mib,started_at) VALUES ($1,$2,8,$3)`, fixture.sandboxID, teamID, fixture.receivedAt.Add(-time.Minute))
	payload, err := json.Marshal(fixture.measurements)
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO host_storage_report(host_id,incarnation_id,report_id,ingest_seq,received_at,payload,state,next_measurement_index,processing_generation)
		VALUES ($1,$2,$3,1,$4,$5,'processing',2,2)`, fixture.hostID, fixture.incarnationID, fixture.reportID, fixture.receivedAt, payload)
	return fixture
}

func storageLeaseRow(t *testing.T, fixture storageLeaseFixture) string {
	t.Helper()
	var result string
	if err := fixture.pool.QueryRow(t.Context(), `SELECT row_to_json(r)::text FROM host_storage_report r WHERE report_id=$1`, fixture.reportID).Scan(&result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestIntegration_StorageReportLeaseRejectsStaleProgress(t *testing.T) {
	for _, completion := range []bool{false, true} {
		name := "partial"
		if completion {
			name = "completion"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newStorageLeaseFixture(t)
			before := storageLeaseRow(t, fixture)
			total := 3
			if completion {
				total = 1
			}
			err := applyStorageReport(t.Context(), fixture.pool, fixture.hostID, fixture.incarnationID, fixture.reportID, 1,
				fixture.receivedAt, fixture.measurements, 1, total)
			if err == nil {
				t.Fatal("stale processing generation advanced the report")
			}
			if after := storageLeaseRow(t, fixture); after != before {
				t.Fatalf("stale owner changed report: before=%s after=%s", before, after)
			}
			var totalIntervals, openDisk int
			if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*), max(disk_mib) FILTER (WHERE ended_at IS NULL) FROM sandbox_storage_interval`).Scan(&totalIntervals, &openDisk); err != nil {
				t.Fatal(err)
			}
			if totalIntervals != 1 || openDisk != 8 {
				t.Fatalf("stale interval writes escaped rollback: count=%d disk=%d", totalIntervals, openDisk)
			}
			if err := applyStorageReport(t.Context(), fixture.pool, fixture.hostID, fixture.incarnationID, fixture.reportID, 2,
				fixture.receivedAt, fixture.measurements, 3, 3); err != nil {
				t.Fatalf("current owner could not complete: %v", err)
			}
			var state string
			var cursor int
			if err := fixture.pool.QueryRow(t.Context(), `SELECT state,next_measurement_index FROM host_storage_report`).Scan(&state, &cursor); err != nil {
				t.Fatal(err)
			}
			if err := fixture.pool.QueryRow(t.Context(), `SELECT disk_mib FROM sandbox_storage_interval WHERE ended_at IS NULL`).Scan(&openDisk); err != nil {
				t.Fatal(err)
			}
			if state != "processed" || cursor != 3 || openDisk != 16 {
				t.Fatalf("current owner completion: state=%s cursor=%d disk=%d", state, cursor, openDisk)
			}
		})
	}
}

func TestIntegration_StorageReportLeaseRejectsStaleFinish(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		discard bool
	}{
		{name: "completion"},
		{name: "retry", err: errors.New("example database outage")},
		{name: "discard", err: errStorageReportInvalidPayload, discard: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newStorageLeaseFixture(t)
			before := storageLeaseRow(t, fixture)
			if finishStorageReport(t.Context(), fixture.pool, fixture.hostID, fixture.incarnationID, fixture.reportID, 1, tc.err, tc.discard) {
				t.Fatal("stale owner finished a newer processing lease")
			}
			if after := storageLeaseRow(t, fixture); after != before {
				t.Fatalf("stale result changed newer lease: before=%s after=%s", before, after)
			}
			if !finishStorageReport(t.Context(), fixture.pool, fixture.hostID, fixture.incarnationID, fixture.reportID, 2, tc.err, tc.discard) {
				t.Fatal("current owner could not finish its processing lease")
			}
		})
	}
}

func TestIntegration_StorageReportReclaimIncrementsProcessingGeneration(t *testing.T) {
	fixture := newStorageLeaseFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if _, err := fixture.pool.Exec(ctx, `UPDATE host_storage_report SET next_measurement_index=0,next_attempt_at=now()-interval '2 minutes'`); err != nil {
		t.Fatal(err)
	}
	if !processOneStorageReport(ctx, fixture.pool) {
		t.Fatal("expired processing lease was not reclaimed")
	}
	var generation int64
	var state string
	if err := fixture.pool.QueryRow(ctx, `SELECT processing_generation,state FROM host_storage_report`).Scan(&generation, &state); err != nil {
		t.Fatal(err)
	}
	if generation != 3 || state != "processed" {
		t.Fatalf("reclaimed report generation=%d state=%s, want 3 and processed", generation, state)
	}
}

func TestIntegration_StorageReportChunkTimeout(t *testing.T) {
	fixture := newStorageLeaseFixture(t)
	if _, err := fixture.pool.Exec(t.Context(), `
		CREATE FUNCTION pg_temp.delay_storage_interval() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			PERFORM pg_sleep(10);
			RETURN NEW;
		END $$;
		CREATE TRIGGER delay_storage_interval BEFORE INSERT ON sandbox_storage_interval
		FOR EACH ROW EXECUTE FUNCTION pg_temp.delay_storage_interval();`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	started := time.Now()
	err := applyStorageReport(ctx, fixture.pool, fixture.hostID, fixture.incarnationID, fixture.reportID, 2,
		fixture.receivedAt, fixture.measurements, 3, 3)
	if elapsed := time.Since(started); elapsed >= 4*time.Second {
		t.Fatalf("storage chunk exceeded its own deadline: elapsed=%s err=%v", elapsed, err)
	}
	if !errors.Is(err, context.DeadlineExceeded) || storageReportErrorIsTerminal(err) {
		t.Fatalf("slow interval write returned %v, want retryable deadline exceeded", err)
	}
}
