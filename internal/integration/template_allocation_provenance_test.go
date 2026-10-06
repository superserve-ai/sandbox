//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/superserve-ai/sandbox/internal/backup"
	"github.com/superserve-ai/sandbox/internal/db"
)

// Historical fixtures model evidence already present at the requested period.
// Runtime writers cannot backdate eligibility, so seed it in this connection
// only, without disabling the guard for concurrent tests or production paths.
func seedHistoricalTemplateEvidence(t *testing.T, template uuid.UUID, path string, at time.Time) {
	t.Helper()
	tx, err := testPool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	var build uuid.UUID
	err = tx.QueryRow(t.Context(), `INSERT INTO template_build(template_id,team_id,status,build_spec_hash)
 SELECT id,team_id,'ready','historical-fixture' FROM template WHERE id=$1 RETURNING id`, template).Scan(&build)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role=replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE artifact_manifest SET allocation_measured_at=$2,
 allocation_eligible_at=$2,allocation_build_id=$3 WHERE template_id=$1 AND path=$4`, template, at, build, path); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func allocationEligibility(t *testing.T, template uuid.UUID, path string) pgtype.Timestamptz {
	t.Helper()
	var at pgtype.Timestamptz
	if err := testPool.QueryRow(t.Context(), `SELECT allocation_eligible_at FROM artifact_manifest WHERE template_id=$1 AND path=$2`, template, path).Scan(&at); err != nil {
		t.Fatal(err)
	}
	return at
}

func TestIntegration_TemplateAllocationEvidenceIsProspective(t *testing.T) {
	b, _ := executionFixture(t)
	path := "/templates/" + b.ID.String() + "/base.ext4"
	storageExec(t, `UPDATE template SET rootfs_path=$2 WHERE id=$1`, b.TemplateID, path)
	sandbox := uuid.New()
	start := time.Now().UTC().Add(-time.Hour)
	storageExec(t, `INSERT INTO sandbox(id,team_id,name,status,vcpu_count,memory_mib,host_id,template_id,base_path,created_at)
 VALUES($1,$2,'allocation-example','paused',1,1024,'default',$3,$4,$5)`, sandbox, b.TeamID, b.TemplateID, path, start)
	storageExec(t, `INSERT INTO sandbox_storage_interval(sandbox_id,team_id,host_id,disk_mib,started_at)
 VALUES($1,$2,'default',0,$3)`, sandbox, b.TeamID, start)
	storageExec(t, `INSERT INTO artifact_manifest(template_id,file_name,path,size_bytes,allocated_bytes,sha256)
 VALUES($1,'base.ext4',$2,0,0,repeat('1',64))`, b.TemplateID, path)
	if allocationEligibility(t, b.TemplateID, path).Valid {
		t.Fatal("hash gave an unmeasured zero eligibility")
	}
	var raw pgtype.Numeric
	measure := func(from time.Time) pgtype.Numeric {
		t.Helper()
		if err := testPool.QueryRow(t.Context(), `SELECT storage_mib_seconds($1,$2,clock_timestamp())`, b.TeamID, from).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if measure(start).Valid {
		t.Fatal("placeholder is numeric instead of unknown")
	}
	// Supplying an old timestamp cannot retroactively certify the interval.
	storageExec(t, `UPDATE artifact_manifest SET allocation_measured_at=$3,allocation_eligible_at=$3,
 allocation_build_id=$4 WHERE template_id=$1 AND path=$2`, b.TemplateID, path, start, b.ID)
	measured := allocationEligibility(t, b.TemplateID, path)
	if !measured.Valid || !measured.Time.After(start) {
		t.Fatalf("caller backdated evidence: %+v", measured)
	}
	if measure(start).Valid {
		t.Fatal("new proof rewrote historical raw usage")
	}
	if got := measure(measured.Time); !got.Valid || numericFloat64(t, got) != 0 {
		t.Fatalf("verified zero unavailable prospectively: %+v", got)
	}
	// An old writer may issue a no-op assignment, or an upsert of the same zero.
	storageExec(t, `UPDATE artifact_manifest SET allocated_bytes=allocated_bytes WHERE template_id=$1 AND path=$2`, b.TemplateID, path)
	if allocationEligibility(t, b.TemplateID, path).Valid {
		t.Fatal("old no-op writer inherited proof")
	}
	storageExec(t, `UPDATE artifact_manifest SET allocation_measured_at=clock_timestamp(),allocation_build_id=$3 WHERE template_id=$1 AND path=$2`, b.TemplateID, path, b.ID)
	storageExec(t, `INSERT INTO artifact_manifest(template_id,file_name,path,size_bytes,allocated_bytes,sha256)
 VALUES($1,'base.ext4',$2,0,0,repeat('0',64)) ON CONFLICT(template_id,path) WHERE template_id IS NOT NULL DO UPDATE SET allocated_bytes=EXCLUDED.allocated_bytes`, b.TemplateID, path)
	if allocationEligibility(t, b.TemplateID, path).Valid {
		t.Fatal("old upsert inherited zero proof")
	}
	storageExec(t, `UPDATE artifact_manifest SET allocated_bytes=1048576 WHERE template_id=$1 AND path=$2`, b.TemplateID, path)
	positive := allocationEligibility(t, b.TemplateID, path)
	if !positive.Valid || measure(start).Valid {
		t.Fatal("new positive backfilled unknown history")
	}
	storageExec(t, `UPDATE artifact_manifest SET allocated_bytes=1048576 WHERE template_id=$1 AND path=$2`, b.TemplateID, path)
	if got := allocationEligibility(t, b.TemplateID, path); got != positive {
		t.Fatalf("unchanged known positive lost eligibility: %+v -> %+v", positive, got)
	}
	storageExec(t, `UPDATE artifact_manifest SET allocated_bytes=2097152 WHERE template_id=$1 AND path=$2`, b.TemplateID, path)
	if got := allocationEligibility(t, b.TemplateID, path); !got.Time.After(positive.Time) {
		t.Fatal("changed quantity inherited historical eligibility")
	}
}

func TestIntegration_TemplatePublicationPreservesOnlySameGenerationEvidence(t *testing.T) {
	for _, value := range []string{"missing", "null", "-1", "0", "512"} {
		for _, proof := range []string{"none", "same", "different"} {
			t.Run(value+"/"+proof, func(t *testing.T) {
				b, cell := executionFixture(t)
				executionHost(t, cell, "active")
				a := claimExecution(t, b, cell)
				admitExecution(t, a)
				path := "/artifacts/" + b.ID.String() + "/base.ext4"
				runtime, _ := json.Marshal(backup.TemplateRuntime{RootfsPath: path, SnapshotPath: path + ".snap", MemPath: path + ".mem", SizeBytes: 1024})
				var prior pgtype.Timestamptz
				if proof == "same" {
					ok, err := testQueries.FinalizeTemplateBuild(t.Context(), b.ID, a.ID, runtime, 0, 0, 0, true)
					if err != nil || !ok {
						t.Fatalf("finalize: %v %v", ok, err)
					}
					prior = allocationEligibility(t, b.TemplateID, path)
				} else if proof == "different" {
					var other uuid.UUID
					err := testPool.QueryRow(t.Context(), `INSERT INTO template_build(template_id,team_id,status,build_spec_hash)
 VALUES($1,$2,'ready','other-generation') RETURNING id`, b.TemplateID, b.TeamID).Scan(&other)
					if err != nil {
						t.Fatal(err)
					}
					storageExec(t, `INSERT INTO artifact_manifest(template_id,file_name,path,size_bytes,allocated_bytes,sha256,allocation_measured_at,allocation_build_id)
 VALUES($1,'base.ext4',$2,0,0,repeat('0',64),clock_timestamp(),$3)`, b.TemplateID, path, other)
				}
				file := map[string]any{"name": "base.ext4", "runtime_path": path, "size_bytes": 1024, "sha256": "1111111111111111111111111111111111111111111111111111111111111111"}
				if value != "missing" {
					file["allocated_bytes"] = json.RawMessage(value)
				}
				files, _ := json.Marshal([]any{file})
				ok, err := testQueries.RecordBuildPublication(t.Context(), a.ID, a.HostID, "example-bucket", "example-generation", "manifest.json", files, runtime, time.Now())
				if err != nil || !ok {
					t.Fatalf("record: %v %v", ok, err)
				}
				if proof != "same" {
					ok, err = testQueries.AcceptBuildPublication(t.Context(), b.ID, a.ID)
					if err != nil || !ok {
						t.Fatalf("accept: %v %v", ok, err)
					}
				}
				got := allocationEligibility(t, b.TemplateID, path)
				want := proof == "same" || value == "512"
				if got.Valid != want {
					t.Fatalf("eligibility=%+v want known=%v", got, want)
				}
				if proof == "same" && value != "512" && got != prior {
					t.Fatal("hash publication moved existing zero eligibility")
				}
				if proof == "same" && value == "512" && !got.Time.After(prior.Time) {
					t.Fatal("new publication quantity inherited old eligibility")
				}
			})
		}
	}
}

func TestIntegration_OldTemplateFinalizerCannotCertifyZero(t *testing.T) {
	b, cell := executionFixture(t)
	executionHost(t, cell, "active")
	a := claimExecution(t, b, cell)
	admitExecution(t, a)
	path := "/artifacts/" + b.ID.String() + "/base.ext4"
	runtime, _ := json.Marshal(backup.TemplateRuntime{RootfsPath: path, SizeBytes: 1024})
	var ok bool
	if err := testPool.QueryRow(t.Context(), `SELECT finalize_template_build($1,$2,$3,0,0,0)`, b.ID, a.ID, runtime).Scan(&ok); err != nil || !ok {
		t.Fatalf("old finalizer: %v %v", ok, err)
	}
	if allocationEligibility(t, b.TemplateID, path).Valid {
		t.Fatal("old six-argument call certified zero")
	}
	// The legacy query propagates the same explicit capability on a non-fenced build.
	legacy := uuid.New()
	legacyPath := path + ".legacy"
	// Non-pending inserts model imported builds whose submitted-input and
	// execution records predate the fenced-build protocol.
	storageExec(t, `INSERT INTO template_build(id,template_id,team_id,status,build_spec_hash)
 VALUES($1,$2,$3,'building','legacy-allocation-example')`, legacy, b.TemplateID, b.TeamID)
	_, err := testQueries.FinalizeBuild(t.Context(), db.FinalizeBuildParams{ID: legacy, RootfsPath: &legacyPath, AllocationsVerified: true})
	if err != nil {
		t.Fatal(err)
	}
	if !allocationEligibility(t, b.TemplateID, legacyPath).Valid {
		t.Fatal("legacy query lost measured-zero proof")
	}
}

func seedHistoricalPositiveTeamAllocations(t *testing.T, team uuid.UUID, at time.Time) {
	t.Helper()
	tx, err := testPool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(t.Context(), `SET LOCAL session_replication_role=replica`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(t.Context(), `UPDATE artifact_manifest a SET allocation_eligible_at=$2
 FROM template t WHERE t.id=a.template_id AND t.team_id=$1 AND a.allocated_bytes>0`, team, at); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestIntegration_PositivePublicationPreservesEarlierKnownAllocation(t *testing.T) {
	b, cell := executionFixture(t)
	executionHost(t, cell, "active")
	a := claimExecution(t, b, cell)
	admitExecution(t, a)
	path := "/artifacts/" + b.ID.String() + "/base.ext4"
	runtime, _ := json.Marshal(backup.TemplateRuntime{RootfsPath: path, SnapshotPath: path + ".snap", MemPath: path + ".mem", SizeBytes: 1048576})
	var ok bool
	if err := testPool.QueryRow(t.Context(), `SELECT finalize_template_build($1,$2,$3,1048576,0,0)`, b.ID, a.ID, runtime).Scan(&ok); err != nil || !ok {
		t.Fatalf("old positive finalizer: %v %v", ok, err)
	}
	prior := allocationEligibility(t, b.TemplateID, path)
	if !prior.Valid {
		t.Fatal("old positive finalizer must retain numeric compatibility")
	}
	sandbox := uuid.New()
	storageExec(t, `INSERT INTO sandbox(id,team_id,name,status,vcpu_count,memory_mib,host_id,template_id,base_path,created_at)
 VALUES($1,$2,'positive-allocation-example','paused',1,1024,'default',$3,$4,$5)`, sandbox, b.TeamID, b.TemplateID, path, prior.Time)
	storageExec(t, `INSERT INTO sandbox_storage_interval(sandbox_id,team_id,host_id,disk_mib,started_at)
 VALUES($1,$2,'default',0,$3)`, sandbox, b.TeamID, prior.Time)
	seedStorageActivation(t, b.TeamID, prior.Time)
	files, _ := json.Marshal([]backup.PublicationFile{{Name: "base.ext4", RuntimePath: path, SizeBytes: 1048576, AllocatedBytes: 1048576, SHA256: "1111111111111111111111111111111111111111111111111111111111111111"}})
	ok, err := testQueries.RecordBuildPublication(t.Context(), a.ID, a.HostID, "example-bucket", "example-generation", "manifest.json", files, runtime, time.Now())
	if err != nil || !ok {
		t.Fatalf("publication: %v %v", ok, err)
	}
	if got := allocationEligibility(t, b.TemplateID, path); got != prior {
		t.Fatalf("publication revoked known positive history: %+v -> %+v", prior, got)
	}
	var amount pgtype.Numeric
	if err := testPool.QueryRow(t.Context(), `SELECT billable_storage_mib_seconds($1,$2,clock_timestamp())`, b.TeamID, prior.Time).Scan(&amount); err != nil {
		t.Fatal(err)
	}
	if !amount.Valid || numericFloat64(t, amount) <= 0 {
		t.Fatalf("earlier known positive allocation became unavailable: %+v", amount)
	}
}
