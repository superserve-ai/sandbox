//go:build integration

package main

import (
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"reflect"
	"strings"
	"testing"
)

func TestLegacyStorageReferenceCopyPreservesUncapturedSource(t *testing.T) {
	team, tpl, owner := uuid.New(), uuid.New(), uuid.New()
	oldPath := "/templates/" + tpl.String() + "/original.ext4"
	for _, pool := range []*pgxpool.Pool{srcPool, dstPool} {
		mustExec(t, pool, `INSERT INTO team(id,name) VALUES($1,'reference-copy-example')`, team)
	}
	mustExec(t, srcPool, `INSERT INTO template(id,team_id,name,status,build_spec,vcpu,memory_mib,disk_mib,rootfs_path,snapshot_path,mem_path) VALUES($1,$2,'reference-copy-example','ready','{}',1,1024,1024,$3,$3||'.snap',$3||'.mem')`, tpl, team, oldPath)
	mustExec(t, srcPool, `INSERT INTO sandbox(id,team_id,name,status,vcpu_count,memory_mib,host_id,template_id,snapshot_path,mem_path) VALUES($1,$2,'reference-copy-example','paused',1,1024,'default',$3,$4,$5)`, owner, team, tpl, oldPath+".snap", oldPath+".mem")
	tx, err := srcPool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err = tx.Exec(t.Context(), `SET LOCAL session_replication_role=replica`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(t.Context(), `UPDATE sandbox SET legacy_storage_refs=NULL WHERE id=$1`, owner); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	for retry := 0; retry < 2; retry++ {
		for _, name := range []string{"template", "sandbox"} {
			spec, ok := tableByName(name)
			if !ok {
				t.Fatal(name)
			}
			if _, _, err := copyTable(t.Context(), srcPool, dstPool, spec, team, nil); err != nil {
				t.Fatalf("copy %s retry %d: %v", name, retry, err)
			}
			src, err := rowChecksums(t.Context(), srcPool, spec, team, nil)
			if err != nil {
				t.Fatal(err)
			}
			dst, err := rowChecksums(t.Context(), dstPool, spec, team, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(src, dst) {
				t.Fatalf("materialized %s checksum differs on retry %d", name, retry)
			}
		}
		got := scanString(t, dstPool, `SELECT legacy_storage_refs->>'rootfs_fallback' FROM sandbox WHERE id=$1`, owner)
		if got != oldPath {
			t.Fatalf("destination guessed reference %q", got)
		}
	}
	mustExec(t, dstPool, `UPDATE template SET rootfs_path=$2 WHERE id=$1`, tpl, oldPath+".rebuilt")
	if got := scanString(t, dstPool, `SELECT legacy_storage_reference(template_id,base_path,delta_path,legacy_storage_refs,snapshot_path,mem_path)->>'rootfs_fallback' FROM sandbox WHERE id=$1`, owner); got != oldPath {
		t.Fatal("destination rebuild changed imported authority")
	}
}

func TestFrozenStorageCloseImportPreservesQuantityAndClassification(t *testing.T) {
	for _, status := range []string{"exporting", "exported", "finalized"} {
		t.Run(status, func(t *testing.T) {
			team := uuid.New()
			for _, pool := range []*pgxpool.Pool{srcPool, dstPool} {
				mustExec(t, pool, `INSERT INTO team(id,name) VALUES($1,$2)`, team, "frozen-import-"+team.String())
			}
			mustExec(t, srcPool, `INSERT INTO team_billing_period(team_id,period_start,period_end,status) VALUES($1,'2026-07-01 00:00Z','2026-08-01 00:00Z',$2)`, team, status)
			mustExec(t, srcPool, `INSERT INTO team_billing_usage(team_id,period_start,period_end,vcpu_seconds,memory_mib_seconds,storage_mib_seconds,storage_complete) VALUES($1,'2026-07-01 00:00Z','2026-08-01 00:00Z',0,0,12345,NULL)`, team)
			// Use actual copy order: the period itself can carry the freeze before
			// close-row timestamps have been written by the exporting worker.
			for retry := 0; retry < 2; retry++ {
				if err := checkFrozenStorageUsageCopySupported(t.Context(), srcPool, dstPool, team); err != nil {
					t.Fatal(err)
				}
				for _, spec := range migratedTables {
					if spec.name != "team_billing_period" && spec.name != "team_billing_usage" {
						continue
					}
					if _, _, err := copyTable(t.Context(), srcPool, dstPool, spec, team, nil); err != nil {
						t.Fatal(err)
					}
				}
				if got := scanString(t, dstPool, `SELECT jsonb_build_array(storage_mib_seconds,storage_complete)::text FROM team_billing_usage WHERE team_id=$1`, team); got != "[12345, null]" {
					t.Fatalf("frozen import reclassified: %s", got)
				}
			}
		})
	}
}

func TestFrozenStorageCopyRefusesConflictingPriorOpenCopy(t *testing.T) {
	for _, kind := range []string{"quantity", "classification", "source-close-only", "mutable-identical"} {
		t.Run(kind, func(t *testing.T) {
			team := uuid.New()
			for _, pool := range []*pgxpool.Pool{srcPool, dstPool} {
				mustExec(t, pool, `INSERT INTO team(id,name) VALUES($1,$2)`, team, "frozen-conflict-"+team.String())
			}
			mustExec(t, dstPool, `INSERT INTO team_billing_period(team_id,period_start,period_end,status) VALUES($1,'2026-07-01 00:00Z','2026-08-01 00:00Z','open')`, team)
			mustExec(t, dstPool, `INSERT INTO team_billing_usage(team_id,period_start,period_end,storage_mib_seconds) VALUES($1,'2026-07-01 00:00Z','2026-08-01 00:00Z',0)`, team)
			if kind != "source-close-only" && kind != "mutable-identical" {
				mustExec(t, srcPool, `INSERT INTO team_billing_period(team_id,period_start,period_end,status) VALUES($1,'2026-07-01 00:00Z','2026-08-01 00:00Z','exporting')`, team)
			}
			var quantity int
			var complete *bool
			if kind == "quantity" {
				quantity = 12345
				known := true
				complete = &known
			}
			mustExec(t, srcPool, `INSERT INTO team_billing_usage(team_id,period_start,period_end,storage_mib_seconds,storage_complete,exported_at) VALUES($1,'2026-07-01 00:00Z','2026-08-01 00:00Z',$2,$3,CASE WHEN $4 THEN now() END)`, team, quantity, complete, kind == "source-close-only")
			before := scanString(t, dstPool, `SELECT jsonb_build_array(p.status,u.storage_mib_seconds,u.storage_complete,u.exported_at)::text FROM team_billing_period p JOIN team_billing_usage u USING(team_id,period_start,period_end) WHERE p.team_id=$1`, team)
			for retry := 0; retry < 2; retry++ {
				err := checkFrozenStorageUsageCopySupported(t.Context(), srcPool, dstPool, team)
				if err == nil || !strings.Contains(err.Error(), "destination storage close") {
					t.Fatalf("conflicting copy was not refused: %v", err)
				}
				after := scanString(t, dstPool, `SELECT jsonb_build_array(p.status,u.storage_mib_seconds,u.storage_complete,u.exported_at)::text FROM team_billing_period p JOIN team_billing_usage u USING(team_id,period_start,period_end) WHERE p.team_id=$1`, team)
				if before != after {
					t.Fatal("refusal froze or partially mutated the destination")
				}
			}
		})
	}
}
