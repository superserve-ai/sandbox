//go:build integration

package integration

import (
	"encoding/json"
	"math"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/superserve-ai/sandbox/internal/db"
)

func partialTemplate(t *testing.T, team uuid.UUID, path *string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	storageExec(t, `INSERT INTO template(id,team_id,name,status,build_spec,vcpu,memory_mib,disk_mib,rootfs_path)
 VALUES($1,$2,($1::uuid)::text,'ready','{}',1,1024,1024,$3)`, id, team, path)
	return id
}

func partialOwner(t *testing.T, team, template uuid.UUID, path *string, disk int, start, end time.Time) uuid.UUID {
	t.Helper()
	id := uuid.New()
	storageExec(t, `INSERT INTO sandbox(id,team_id,name,status,vcpu_count,memory_mib,host_id,template_id,base_path,created_at,destroyed_at)
 VALUES($1,$2,'partial-example','deleted',1,1024,'default',$3,$4,$5,$6)`, id, team, template, path, start, end)
	storageExec(t, `INSERT INTO sandbox_storage_interval(sandbox_id,team_id,host_id,disk_mib,started_at,ended_at,end_reason)
 VALUES($1,$2,'default',$3,$4,$5,'deleted')`, id, team, disk, start, end)
	return id
}

func TestIntegration_PartialStorageBillsKnownSharedAndPrivateUsage(t *testing.T) {
	for _, active := range []bool{false, true} {
		t.Run(map[bool]string{false: "tracking", true: "activated"}[active], func(t *testing.T) {
			team, key, _ := seedTeamAndKeyWithRole(t, "viewer")
			start := time.Now().UTC().Truncate(time.Hour).Add(-4 * time.Hour)
			end := start.Add(time.Hour)
			knownPath := "/templates/" + team.String() + "/known.ext4"
			unknownPath := "/templates/" + team.String() + "/unknown.ext4"
			known := partialTemplate(t, team, &knownPath)
			unknown := partialTemplate(t, team, &unknownPath)
			unidentified := partialTemplate(t, team, nil)
			storageExec(t, `INSERT INTO artifact_manifest(template_id,file_name,path,size_bytes,allocated_bytes,sha256)
 VALUES($1,'base.ext4',$2,1073741824,1073741824,repeat('0',64)),($3,'base.ext4',$4,0,0,repeat('0',64))`, known, knownPath, unknown, unknownPath)
			seedHistoricalTemplateEvidence(t, known, knownPath, start)
			cpuOwner := partialOwner(t, team, known, &knownPath, 1024, start, end)
			partialOwner(t, team, known, &knownPath, 1024, start, end)
			partialOwner(t, team, unknown, &unknownPath, 2048, start, end)
			partialOwner(t, team, unidentified, nil, 3072, start, end)
			storageExec(t, `INSERT INTO sandbox_compute_billing_interval(sandbox_id,team_id,vcpu_count,memory_mib,started_at,ended_at,end_reason)
 VALUES($1,$2,1,1024,$3,$4,'paused')`, cpuOwner, team, start, end)
			storageExec(t, `INSERT INTO team_billing_account(team_id) VALUES($1)`, team)
			storageExec(t, `INSERT INTO team_billing_period(team_id,period_start,period_end,status) VALUES($1,$2,$3,'open')`, team, start, end)
			storageExec(t, `INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_hourly_rollups',true) ON CONFLICT(team_id,key) DO UPDATE SET enabled=true`, team)
			if active {
				seedStorageActivation(t, team, start)
			}
			plan := "partial-" + team.String()
			insertPricingPlanForTest(t, t.Context(), plan, true)
			storageExec(t, `INSERT INTO pricing_rate(plan_key,resource,unit,price_usd,effective_from)
 VALUES($1,'vcpu','second',0,$2),($1,'memory_gib','second',0,$2),($1,'storage_gib','second',0.000001,$2)`, plan, start.Add(-time.Hour))
			storageExec(t, `INSERT INTO team_pricing_plan(team_id,plan_key,effective_from) VALUES($1,$2,$3)`, team, plan, start.Add(-time.Hour))
			usage, err := testQueries.GetTeamBillingUsage(t.Context(), db.GetTeamBillingUsageParams{TeamID: team, PeriodStart: start, PeriodEnd: end})
			if err != nil {
				t.Fatal(err)
			}
			if usage.StorageGibSeconds.Valid || usage.StorageComplete || usage.StorageBlocked || numericFloat64(t, usage.KnownStorageGibSeconds) != 28800 || numericFloat64(t, usage.VcpuSeconds) != 3600 {
				t.Fatalf("partial union discarded known usage or duplicated shared base: %+v", usage)
			}
			wantPayable := 0.0
			if active {
				wantPayable = 28800
			}
			if numericFloat64(t, usage.BillableStorageGibSeconds) != wantPayable {
				t.Fatalf("payable=%+v", usage.BillableStorageGibSeconds)
			}
			hour, err := testQueries.UpsertTeamBillingUsageHour(t.Context(), db.UpsertTeamBillingUsageHourParams{TeamID: team, HourStart: pgtype.Timestamptz{Time: start, Valid: true}, HourEnd: pgtype.Timestamptz{Time: end, Valid: true}})
			if err != nil || hour.StorageMibSeconds.Valid || hour.StorageComplete == nil || *hour.StorageComplete || numericFloat64(t, hour.KnownStorageMibSeconds) != 28800*1024 {
				t.Fatalf("hourly partial=%+v %v", hour, err)
			}
			// Old cache writers omit the status and submit their own quantity; DB
			// authority measures the same payable subtotal and completeness atomically.
			storageExec(t, `INSERT INTO billing_export_measurement(team_id,period_start,period_end,hour_start,vcpu_seconds,memory_mib_seconds,storage_mib_seconds)
 VALUES($1,$2,$3,$2,3600,3686400,0)`, team, start, end)
			storageExec(t, `INSERT INTO billing_export_usage(team_id,period_start,period_end,vcpu_seconds,memory_mib_seconds,storage_mib_seconds)
 VALUES($1,$2,$3,3600,3686400,0)`, team, start, end)
			var subtotal pgtype.Numeric
			var complete *bool
			if err := testPool.QueryRow(t.Context(), `SELECT storage_mib_seconds,storage_complete FROM billing_export_usage WHERE team_id=$1`, team).Scan(&subtotal, &complete); err != nil {
				t.Fatal(err)
			}
			if numericFloat64(t, subtotal) != wantPayable*1024 || complete == nil || *complete == active {
				t.Fatalf("export omitted partial status/quantity: %+v %v", subtotal, complete)
			}
			// Old period-close binaries do not send completeness either.
			storageExec(t, `INSERT INTO team_billing_usage(team_id,period_start,period_end,vcpu_seconds,memory_mib_seconds,storage_mib_seconds)
 VALUES($1,$2,$3,3600,3686400,0)`, team, start, end)
			if err := testPool.QueryRow(t.Context(), `SELECT storage_mib_seconds,storage_complete FROM team_billing_usage WHERE team_id=$1`, team).Scan(&subtotal, &complete); err != nil {
				t.Fatal(err)
			}
			if numericFloat64(t, subtotal) != wantPayable*1024 || complete == nil || *complete == active {
				t.Fatalf("old close omitted partial status: %+v %v", subtotal, complete)
			}
			router := newBillingRouter(t, &fakeStripeClient{})
			for _, path := range []string{"/billing/summary", "/billing/usage-series?start=" + start.Format(time.RFC3339) + "&end=" + end.Format(time.RFC3339) + "&granularity=day&timezone=UTC"} {
				w := do(router, http.MethodGet, path, key, "")
				if w.Code != http.StatusOK {
					t.Fatalf("partial endpoint %s: %d %s", path, w.Code, w.Body.String())
				}
				var body map[string]any
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				var storage map[string]any
				if path == "/billing/summary" {
					storage = body["resources_by_key"].(map[string]any)["storage_gib"].(map[string]any)
				} else {
					storage = body["buckets"].([]any)[0].(map[string]any)["storage"].(map[string]any)
				}
				if storage["usage"] != nil || storage["known_usage"] != float64(28800) || storage["measurement_status"] != "partial" {
					t.Fatalf("partial response hides unknowns: %s", w.Body.String())
				}
			}
			// Previously unidentified fallback is never retrospectively identified by
			// changing mutable template metadata, even to an already measured file.
			resolvedPath := unknownPath + ".resolved"
			storageExec(t, `INSERT INTO artifact_manifest(template_id,file_name,path,size_bytes,allocated_bytes,sha256)
 VALUES($1,'base.ext4',$2,1073741824,1073741824,repeat('1',64))`, unidentified, resolvedPath)
			seedHistoricalTemplateEvidence(t, unidentified, resolvedPath, start)
			storageExec(t, `UPDATE template SET rootfs_path=$2 WHERE id=$1`, unidentified, resolvedPath)
			storageExec(t, `UPDATE team_billing_period SET status='exported',exported_at=now() WHERE team_id=$1`, team)
			storageExec(t, `UPDATE billing_export_measurement SET storage_mib_seconds=999999,storage_complete=true WHERE team_id=$1`, team)
			storageExec(t, `UPDATE billing_export_usage SET storage_mib_seconds=999999,storage_complete=true WHERE team_id=$1`, team)
			storageExec(t, `UPDATE team_billing_usage SET storage_mib_seconds=999999,storage_complete=true WHERE team_id=$1`, team)
			if err := testPool.QueryRow(t.Context(), `SELECT storage_mib_seconds,storage_complete FROM team_billing_usage WHERE team_id=$1`, team).Scan(&subtotal, &complete); err != nil {
				t.Fatal(err)
			}
			if numericFloat64(t, subtotal) != wantPayable*1024 || complete == nil || *complete == active {
				t.Fatal("frozen quantity/status changed")
			}
			var after pgtype.Numeric
			if err := testPool.QueryRow(t.Context(), `SELECT billable_storage_mib_seconds($1,$2,$3)`, team, start, end).Scan(&after); err != nil {
				t.Fatal(err)
			}
			if numericFloat64(t, after) != wantPayable*1024 {
				t.Fatal("late reference resolution created historical debt")
			}
		})
	}
}

func TestIntegration_PartialStorageSplitsSharedMaximumAtEvidenceBoundary(t *testing.T) {
	team, _ := seedTeamAndKey(t)
	start := time.Now().UTC().Truncate(time.Hour).Add(-4 * time.Hour)
	end := start.Add(time.Hour)
	path := "/templates/" + team.String() + "/shared.ext4"
	first := partialTemplate(t, team, &path)
	second := partialTemplate(t, team, &path)
	storageExec(t, `INSERT INTO artifact_manifest(template_id,file_name,path,size_bytes,allocated_bytes,sha256)
 VALUES($1,'base.ext4',$3,1048576,1048576,repeat('0',64)),($2,'base.ext4',$3,2097152,2097152,repeat('0',64))`, first, second, path)
	seedHistoricalTemplateEvidence(t, first, path, start)
	seedHistoricalTemplateEvidence(t, second, path, start.Add(30*time.Minute))
	partialOwner(t, team, first, &path, 0, start, end)
	partialOwner(t, team, second, &path, 0, start, end)
	var known pgtype.Numeric
	var complete, blocked bool
	if err := testPool.QueryRow(t.Context(), `SELECT * FROM storage_usage_detail($1,$2,$3,false)`, team, start, end).Scan(&known, &complete, &blocked); err != nil {
		t.Fatal(err)
	}
	if blocked || complete || math.Abs(numericFloat64(t, known)-5400) > 1e-9 {
		t.Fatalf("later max backcharged earlier window: %+v complete=%v blocked=%v", known, complete, blocked)
	}
}

func TestIntegration_PartialStorageDistinguishesUnknownFromMeasuredZero(t *testing.T) {
	for _, measured := range []bool{false, true} {
		t.Run(map[bool]string{false: "unknown", true: "measured_zero"}[measured], func(t *testing.T) {
			team, _ := seedTeamAndKey(t)
			start := time.Now().UTC().Add(-2 * time.Hour)
			end := start.Add(time.Hour)
			path := "/templates/" + team.String() + "/zero.ext4"
			tpl := partialTemplate(t, team, &path)
			storageExec(t, `INSERT INTO artifact_manifest(template_id,file_name,path,size_bytes,allocated_bytes,sha256) VALUES($1,'base.ext4',$2,0,0,repeat('0',64))`, tpl, path)
			if measured {
				seedHistoricalTemplateEvidence(t, tpl, path, start)
			}
			partialOwner(t, team, tpl, &path, 0, start, end)
			var known pgtype.Numeric
			var complete, blocked bool
			if err := testPool.QueryRow(t.Context(), `SELECT * FROM storage_usage_detail($1,$2,$3,false)`, team, start, end).Scan(&known, &complete, &blocked); err != nil {
				t.Fatal(err)
			}
			if numericFloat64(t, known) != 0 || complete != measured || blocked {
				t.Fatalf("zero classification known=%+v complete=%v blocked=%v", known, complete, blocked)
			}
		})
	}
}

func TestIntegration_LegacyStorageReferenceAuthority(t *testing.T) {
	team, _ := seedTeamAndKey(t)
	original := "/templates/" + team.String() + "/old.ext4"
	next := original + ".new"
	tpl := partialTemplate(t, team, &original)
	storageExec(t, `UPDATE template SET snapshot_path=$2,mem_path=$3 WHERE id=$1`, tpl, original+".snap", original+".mem")
	create := func(snapshot, mem string) uuid.UUID {
		id := uuid.New()
		storageExec(t, `INSERT INTO sandbox(id,team_id,name,status,vcpu_count,memory_mib,host_id,template_id,snapshot_path,mem_path)
 VALUES($1,$2,'reference-example','paused',1,1024,'default',$3,$4,$5)`, id, team, tpl, snapshot, mem)
		return id
	}
	matched := create(original+".snap", original+".mem")
	stale := create("/older/snapshot", "/older/memory")
	read := func(id uuid.UUID) *string {
		var path *string
		if err := testPool.QueryRow(t.Context(), `SELECT legacy_storage_reference(template_id,base_path,delta_path,legacy_storage_refs)->>'rootfs_fallback' FROM sandbox WHERE id=$1`, id).Scan(&path); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if got := read(matched); got == nil || *got != original {
		t.Fatalf("matching creation lost reference: %v", got)
	}
	if got := read(stale); got != nil {
		t.Fatalf("stale snapshot acquired newer rootfs: %s", *got)
	}
	// Model a row created before reference capture was installed, without changing
	// database-wide trigger behavior for concurrent fixtures.
	tx, err := testPool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err = tx.Exec(t.Context(), `SET LOCAL session_replication_role=replica`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(t.Context(), `UPDATE sandbox SET legacy_storage_refs=NULL WHERE id=$1`, matched); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	storageExec(t, `UPDATE template SET rootfs_path=$2 WHERE id=$1`, tpl, next)
	if got := read(matched); got == nil || *got != original {
		t.Fatalf("template rebuild rewrote legacy identity: %v", got)
	}
	if got := read(stale); got != nil {
		t.Fatal("captured unknown was reconstructed retrospectively")
	}
	for _, assignment := range []string{"template_id=NULL", "base_path='/replacement/base'", "delta_path='/replacement/delta'"} {
		if _, err := testPool.Exec(t.Context(), `UPDATE sandbox SET `+assignment+` WHERE id=$1`, matched); err == nil {
			t.Fatalf("allowed identity mutation %s", assignment)
		}
	}
	storageExec(t, `UPDATE sandbox SET template_id=template_id,base_path=base_path,delta_path=delta_path,status='paused' WHERE id=$1`, matched)
}
