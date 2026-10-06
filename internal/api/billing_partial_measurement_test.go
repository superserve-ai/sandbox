//go:build integration

package api

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestIntegration_PartialMeasurementConsumer(t *testing.T) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL required")
	}
	pool, err := pgxpool.New(t.Context(), url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(t.Context(), sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Hour)
	start := now.Add(-2 * time.Hour)
	end := start.Add(time.Hour)
	h := &Handlers{Pool: pool, DB: db.New(pool), Now: func() time.Time { return now }}
	team, err := h.DB.CreateTeam(t.Context(), "partial-measurement-example")
	if err != nil {
		t.Fatal(err)
	}
	tpl, owner := uuid.New(), uuid.New()
	path := "/templates/" + tpl.String() + "/base.ext4"
	exec(`INSERT INTO template(id,team_id,name,status,build_spec,vcpu,memory_mib,disk_mib,rootfs_path) VALUES($1,$2,'partial-example','ready','{}',1,1024,1024,$3)`, tpl, team.ID, path)
	exec(`INSERT INTO sandbox(id,team_id,name,status,vcpu_count,memory_mib,host_id,template_id,base_path,created_at,destroyed_at) VALUES($1,$2,'partial-example','deleted',1,1024,'default',$3,$4,$5,$6)`, owner, team.ID, tpl, path, start, end)
	exec(`INSERT INTO sandbox_storage_interval(sandbox_id,team_id,host_id,disk_mib,started_at,ended_at,end_reason) VALUES($1,$2,'default',1024,$3,$4,'deleted')`, owner, team.ID, start, end)
	exec(`INSERT INTO sandbox_compute_billing_interval(sandbox_id,team_id,vcpu_count,memory_mib,started_at,ended_at,end_reason) VALUES($1,$2,1,1024,$3,$4,'paused')`, owner, team.ID, start, end)
	exec(`INSERT INTO team_storage_billing_activation(team_id,effective_at,approved_cutoff) VALUES($1,$2,$2)`, team.ID, start)
	exec(`INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_hourly_rollups',true) ON CONFLICT(team_id,key) DO UPDATE SET enabled=true`, team.ID)
	rollup := func() {
		t.Helper()
		if _, err := h.DB.UpsertTeamBillingUsageHour(t.Context(), db.UpsertTeamBillingUsageHourParams{TeamID: team.ID, HourStart: pgtype.Timestamptz{Time: start, Valid: true}, HourEnd: pgtype.Timestamptz{Time: end, Valid: true}}); err != nil {
			t.Fatal(err)
		}
	}
	seed := func() {
		t.Helper()
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, _, err = seedExportMeasurementPage(t.Context(), tx, team.ID, start.Add(-time.Hour), pgtype.Timestamptz{Time: end, Valid: true}); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	consume := func(wantComplete bool) {
		t.Helper()
		if found, err := h.consumeExportMeasurement(t.Context(), team.ID, start); err != nil || !found {
			t.Fatalf("consume found=%v err=%v", found, err)
		}
		var cpu, memory, storage float64
		var complete *bool
		if err := pool.QueryRow(t.Context(), `SELECT vcpu_seconds,memory_mib_seconds,storage_mib_seconds,storage_complete FROM billing_export_usage WHERE team_id=$1`, team.ID).Scan(&cpu, &memory, &storage, &complete); err != nil {
			t.Fatal(err)
		}
		if cpu != 3600 || memory != 3686400 || storage != 3686400 || complete == nil || *complete != wantComplete {
			t.Fatalf("consumer cpu=%v memory=%v storage=%v complete=%v", cpu, memory, storage, complete)
		}
	}
	rollup()
	seed()
	consume(false)
	// Restore historical zero evidence to model a status-only cache correction:
	// the known subtotal is unchanged, but discovery must enqueue the new status.
	exec(`INSERT INTO artifact_manifest(template_id,file_name,path,size_bytes,allocated_bytes,sha256) VALUES($1,'base.ext4',$2,0,0,repeat('0',64))`, tpl, path)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(t.Context(), `SET LOCAL session_replication_role=replica`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(t.Context(), `UPDATE artifact_manifest SET allocation_eligible_at=$2,allocation_measured_at=$2 WHERE template_id=$1`, tpl, start); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	rollup()
	seed()
	consume(true)
}
