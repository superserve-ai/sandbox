//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/backup"
	"github.com/superserve-ai/sandbox/internal/db"
)

func executionFixture(t *testing.T) (db.TemplateBuild, string) {
	t.Helper()
	ctx := context.Background()
	team, _ := seedTeamAndKey(t)
	tpl, err := testQueries.CreateTemplate(ctx, db.CreateTemplateParams{TeamID: team, Name: "build-" + uuid.NewString(),
		BuildSpec: []byte(`{"from":"example/image:stable"}`), Vcpu: 2, MemoryMib: 2048, DiskMib: 4096})
	if err != nil {
		t.Fatal(err)
	}
	b, err := testQueries.CreateTemplateBuild(ctx, db.CreateTemplateBuildParams{TemplateID: tpl.ID, TeamID: team, BuildSpecHash: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	cell := "cell-" + uuid.NewString()
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `UPDATE template_build SET status='cancelled' WHERE template_id=$1 AND status IN ('pending','building','snapshotting')`, tpl.ID)
	})
	return b, cell
}
func executionHost(t *testing.T, cell, status string) string {
	t.Helper()
	id := "host-" + uuid.NewString()
	ctx := context.Background()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	incarnation := uuid.New()
	if _, err := tx.Exec(ctx, `SELECT prepare_host_heartbeat($1,$2)`, id, incarnation.String()); err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO host(id,vmd_addr,proxy_addr,region,status,capacity_memory_mib,capacity_vcpus,last_heartbeat_at,incarnation_id)
 VALUES($1,'192.0.2.1:50051','192.0.2.1:5007',$2,$3,65536,32,now(),$4)`, id, cell, status, incarnation)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO host_capability(host_id,capability,heartbeat_at) SELECT id,'template_build_v1',last_heartbeat_at FROM host WHERE id=$1`, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO host_pressure(host_id,running_sandboxes,provisioning_sandboxes,paused_sandboxes,allocated_memory_mib,allocated_vcpus,used_net_slots,provisioning_net_slots,warm_net_slots,net_slot_ceiling)
 VALUES($1,0,0,0,0,0,0,0,0,65000)`, id); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	cleanupHost(t, id)
	return id
}
func claimExecution(t *testing.T, b db.TemplateBuild, cell string) db.BuildAttempt {
	t.Helper()
	ctx := context.Background()
	id, err := testQueries.ClaimBuildAttempt(ctx, b.ID, cell, 10000)
	if err != nil || id == nil {
		t.Fatalf("claim: %v, %v", id, err)
	}
	a, err := testQueries.GetBuildAttempt(ctx, *id)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func admitExecution(t *testing.T, a db.BuildAttempt) {
	t.Helper()
	ok, err := testQueries.AdmitBuildAttempt(context.Background(), a.ID, a.HostID, a.IncarnationID)
	if err != nil || !ok {
		t.Fatalf("admit: %v, %v", ok, err)
	}
}
func recordExecution(t *testing.T, a db.BuildAttempt) bool {
	t.Helper()
	root := "/artifacts/" + a.TemplateID.String() + "/" + a.VMID + "/"
	files := []backup.PublicationFile{}
	for _, name := range []string{"base.ext4", "vmstate.snap", "mem.snap", "rootfs.delta", "build.meta.json"} {
		files = append(files, backup.PublicationFile{Name: name, RuntimePath: root + name, SHA256: "1111111111111111111111111111111111111111111111111111111111111111", SizeBytes: 1024, AllocatedBytes: 512})
	}
	runtime := backup.TemplateRuntime{RootfsPath: root + "base.ext4", BasePath: root + "base.ext4", SnapshotPath: root + "vmstate.snap", MemPath: root + "mem.snap", DeltaPath: root + "rootfs.delta", SizeBytes: 1024}
	f, _ := json.Marshal(files)
	r, _ := json.Marshal(runtime)
	ok, err := testQueries.RecordBuildPublication(context.Background(), a.ID, a.HostID, "example-bucket", "generation", root+"manifest.json", f, r, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

func TestIntegration_BuildStatusExposesExecutionMetadata(t *testing.T) {
	ctx := context.Background()
	b, cell := executionFixture(t)
	key := seedKeyForExistingTeamWithRole(t, b.TeamID, "viewer")
	executionHost(t, cell, "active")
	executionHost(t, cell, "active")

	first := claimExecution(t, b, cell)
	admitExecution(t, first)
	if ok, err := testQueries.TransitionBuildAttempt(ctx, b.ID, &first.ID, "retry", "owner lost"); err != nil || !ok {
		t.Fatalf("retry first attempt: %v, %v", ok, err)
	}
	current := claimExecution(t, b, cell)
	admitExecution(t, current)

	getStatus := func() (map[string]any, map[string]any) {
		t.Helper()
		path := "/templates/" + b.TemplateID.String() + "/builds/" + b.ID.String()
		resp := do(newRouter(t), http.MethodGet, path, key, "")
		if resp.Code != http.StatusOK {
			t.Fatalf("get build status: %d %s", resp.Code, resp.Body.String())
		}
		body := mustJSON(t, resp)
		execution, ok := body["execution"].(map[string]any)
		if !ok {
			t.Fatalf("missing execution metadata: %s", resp.Body.String())
		}
		return body, execution
	}

	body, execution := getStatus()
	if body["id"] != b.ID.String() || body["host_id"] != current.HostID ||
		execution["attempt_id"] != current.ID.String() || execution["attempt_count"] != float64(2) ||
		execution["retry_reason"] != "owner lost" || execution["publication_verified"] != false {
		t.Fatalf("in-flight build status: %v", body)
	}

	if !recordExecution(t, current) {
		t.Fatal("current attempt publication rejected")
	}
	if accepted, err := testQueries.AcceptBuildPublication(ctx, b.ID, current.ID); err != nil || !accepted {
		t.Fatalf("accept publication: %v, %v", accepted, err)
	}
	body, execution = getStatus()
	if body["status"] != "ready" || body["host_id"] != current.HostID ||
		execution["attempt_id"] != current.ID.String() || execution["attempt_count"] != float64(2) ||
		execution["retry_reason"] != "owner lost" || execution["publication_verified"] != true {
		t.Fatalf("published build status: %v", body)
	}
}

func TestIntegration_BuildClaimFencesConcurrentSupervisors(t *testing.T) {
	b, cell := executionFixture(t)
	executionHost(t, cell, "active")
	executionHost(t, cell, "active")
	var wg sync.WaitGroup
	results := make(chan *uuid.UUID, 2)
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, err := testQueries.ClaimBuildAttempt(context.Background(), b.ID, cell, 10000)
			results <- id
			errs <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	n := 0
	for id := range results {
		if id != nil {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("accepted %d concurrent claims", n)
	}
	e, err := testQueries.GetBuildExecution(context.Background(), b.ID)
	if err != nil || e.Attempts != 1 {
		t.Fatalf("execution %+v: %v", e, err)
	}
}

func TestIntegration_BuildReconciliationAdvancesPastBlockedBatch(t *testing.T) {
	ctx := context.Background()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	// Prior tests can retain nonterminal builds. Mark those as already checked
	// in this transaction so this fixture exercises one full unchecked batch.
	if _, err := tx.Exec(ctx, `UPDATE template_build_execution SET reconcile_checked_at=clock_timestamp()`); err != nil {
		t.Fatal(err)
	}
	blocked := make(map[uuid.UUID]bool)
	for range 20 {
		b, _ := executionFixture(t)
		blocked[b.ID] = true
	}
	next, cell := executionFixture(t)
	executionHost(t, cell, "active")
	q := db.New(tx)
	first, err := q.ListResilientBuildIDs(ctx, 20)
	if err != nil || len(first) != 20 {
		t.Fatalf("first batch: %v %v", first, err)
	}
	for _, id := range first {
		if !blocked[id] {
			t.Fatalf("unexpected build in oldest batch: %s", id)
		}
	}
	// Leave every older build nonterminal, as when all are waiting for capacity.
	second, err := q.ListResilientBuildIDs(ctx, 1)
	if err != nil || len(second) != 1 || second[0] != next.ID {
		t.Fatalf("later build was starved by nonterminal batch: %v %v; want %s", second, err, next.ID)
	}
	if id, err := q.ClaimBuildAttempt(ctx, next.ID, cell, 10000); err != nil || id == nil {
		t.Fatalf("later build could not claim available capacity: %v %v", id, err)
	}
	var pending int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM template_build WHERE id=ANY($1::uuid[]) AND status='pending'`, first).Scan(&pending); err != nil || pending != 20 {
		t.Fatalf("older builds were not left pending: %d %v", pending, err)
	}
}

func TestIntegration_BuildReconciliationSkipsConcurrentSelection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	// Keep unrelated fixtures locked while the two selectors compete for these builds.
	if _, err := tx.Exec(ctx, `UPDATE template_build_execution SET reconcile_checked_at=clock_timestamp()`); err != nil {
		t.Fatal(err)
	}
	first, _ := executionFixture(t)
	second, _ := executionFixture(t)
	selected, err := db.New(tx).ListResilientBuildIDs(ctx, 1)
	if err != nil || len(selected) != 1 || selected[0] != first.ID {
		t.Fatalf("first selector: %v %v; want %s", selected, err, first.ID)
	}
	// The first selection is still uncommitted; another replica must make progress.
	other, err := testQueries.ListResilientBuildIDs(ctx, 1)
	if err != nil || len(other) != 1 || other[0] != second.ID {
		t.Fatalf("concurrent selector: %v %v; want %s", other, err, second.ID)
	}
}

func TestIntegration_BuildEligibilityAndDrainAdmission(t *testing.T) {
	b, cell := executionFixture(t)
	executionHost(t, cell, "provisioning")
	executionHost(t, cell+"-other", "active")
	stale := executionHost(t, cell, "active")
	staleTx, err := testPool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer staleTx.Rollback(context.Background())
	if _, err := staleTx.Exec(context.Background(), `SELECT prepare_host_heartbeat(id,incarnation_id::text) FROM host WHERE id=$1`, stale); err != nil {
		t.Fatal(err)
	}
	if _, err := staleTx.Exec(context.Background(), `UPDATE host SET last_heartbeat_at=now()-interval '3 minutes' WHERE id=$1`, stale); err != nil {
		t.Fatal(err)
	}
	if err := staleTx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	id, err := testQueries.ClaimBuildAttempt(context.Background(), b.ID, cell, 10000)
	if err != nil || id != nil {
		t.Fatalf("ineligible claim: %v %v", id, err)
	}
	host := executionHost(t, cell, "active")
	a := claimExecution(t, b, cell)
	if a.HostID != host {
		t.Fatal("wrong cell or ineligible host selected")
	}
	if _, err := testPool.Exec(context.Background(), `UPDATE host SET status='draining' WHERE id=$1`, host); err != nil {
		t.Fatal(err)
	}
	ok, err := testQueries.AdmitBuildAttempt(context.Background(), a.ID, host, a.IncarnationID)
	if err != nil || ok {
		t.Fatalf("drain lost admission: %v %v", ok, err)
	}
	e, err := testQueries.GetBuildExecution(context.Background(), b.ID)
	if err != nil || e.Attempts != 0 || e.CurrentAttempt != nil || e.FirstStartedAt != nil {
		t.Fatalf("rejection consumed attempt/budget: %+v %v", e, err)
	}
}

func TestIntegration_BuildRequiresCurrentCapability(t *testing.T) {
	for _, capability := range []string{"missing", "mismatched_heartbeat"} {
		for _, stage := range []string{"claim", "admission"} {
			t.Run(capability+"/"+stage, func(t *testing.T) {
				ctx := context.Background()
				b, cell := executionFixture(t)
				host := executionHost(t, cell, "active")
				var a db.BuildAttempt
				if stage == "admission" {
					a = claimExecution(t, b, cell)
				}
				var mutation string
				if capability == "missing" {
					mutation = `DELETE FROM host_capability WHERE host_id=$1 AND capability='template_build_v1'`
				} else {
					mutation = `UPDATE host_capability SET heartbeat_at=heartbeat_at-interval '1 second' WHERE host_id=$1 AND capability='template_build_v1'`
				}
				if _, err := testPool.Exec(ctx, mutation, host); err != nil {
					t.Fatal(err)
				}
				if stage == "claim" {
					id, err := testQueries.ClaimBuildAttempt(ctx, b.ID, cell, 10000)
					if err != nil || id != nil {
						t.Fatalf("incompatible host claimed: %v %v", id, err)
					}
				} else {
					ok, err := testQueries.AdmitBuildAttempt(ctx, a.ID, host, a.IncarnationID)
					if err != nil || ok {
						t.Fatalf("incompatible host admitted: %v %v", ok, err)
					}
				}
				e, err := testQueries.GetBuildExecution(ctx, b.ID)
				if err != nil || e.Attempts != 0 || e.CurrentAttempt != nil || e.FirstStartedAt != nil {
					t.Fatalf("capability rejection spent execution budget: %+v %v", e, err)
				}
			})
		}
	}
}
func TestIntegration_BuildDrainSerializesWithClaim(t *testing.T) {
	b, cell := executionFixture(t)
	host := executionHost(t, cell, "active")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	drain, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer drain.Rollback(context.Background())
	if _, err = drain.Exec(ctx, `UPDATE host SET status='draining' WHERE id=$1`, host); err != nil {
		t.Fatal(err)
	}
	conn, err := testPool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	type result struct {
		id  *uuid.UUID
		err error
	}
	done := make(chan result, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		id, err := db.New(conn).ClaimBuildAttempt(ctx, b.ID, cell, 10000)
		done <- result{id, err}
	}()
	defer func() {
		cancel()
		<-finished
	}()
	waitForHostBlocker(t, ctx, conn.Conn().PgConn().PID(), drain.Conn().PgConn().PID())
	if err = drain.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	r := <-done
	if r.err != nil || r.id != nil {
		t.Fatalf("drained host claimed: %+v", r)
	}
}
func TestIntegration_BuildRetryFencesOldPublicationAndKeepsBudget(t *testing.T) {
	b, cell := executionFixture(t)
	executionHost(t, cell, "active")
	executionHost(t, cell, "active")
	a := claimExecution(t, b, cell)
	admitExecution(t, a)
	before, _ := testQueries.GetBuildExecution(context.Background(), b.ID)
	ok, err := testQueries.TransitionBuildAttempt(context.Background(), b.ID, &a.ID, "retry", "owner lost")
	if err != nil || !ok {
		t.Fatal(err)
	}
	next := claimExecution(t, b, cell)
	admitExecution(t, next)
	if next.HostID == a.HostID || next.VMID == a.VMID {
		t.Fatal("retry reused failed owner or artifact identity")
	}
	after, _ := testQueries.GetBuildExecution(context.Background(), b.ID)
	if before.FirstStartedAt == nil || after.FirstStartedAt == nil || !before.FirstStartedAt.Equal(*after.FirstStartedAt) {
		t.Fatal("retry reset deadline")
	}
	if recordExecution(t, a) {
		t.Fatal("old attempt published")
	}
	if ok, err := testQueries.TransitionBuildAttempt(context.Background(), b.ID, &a.ID, "fail", "late failure"); err != nil || ok {
		t.Fatal("stale failure changed current attempt")
	}
	if !recordExecution(t, next) || !recordExecution(t, next) {
		t.Fatal("current publication not idempotent")
	}
	if _, err := testPool.Exec(context.Background(), `UPDATE host SET status='unhealthy' WHERE id=$1`, next.HostID); err != nil {
		t.Fatal(err)
	}
	accepted, err := testQueries.AcceptBuildPublication(context.Background(), b.ID, next.ID)
	if err != nil || !accepted {
		t.Fatalf("durable completion after host loss: %v %v", accepted, err)
	}
	protected, err := testQueries.BuildArtifactProtected(context.Background(), next.VMID)
	if err != nil || !protected {
		t.Fatal("accepted version not protected")
	}
}
func TestIntegration_BuildCancellationAndDeletionFencePublication(t *testing.T) {
	for _, action := range []string{"cancel", "delete"} {
		t.Run(action, func(t *testing.T) {
			b, cell := executionFixture(t)
			executionHost(t, cell, "active")
			a := claimExecution(t, b, cell)
			admitExecution(t, a)
			if action == "cancel" {
				if _, err := testQueries.CancelBuild(context.Background(), db.CancelBuildParams{ID: b.ID, TemplateID: b.TemplateID, TeamID: b.TeamID}); err != nil {
					t.Fatal(err)
				}
			} else {
				r, err := testQueries.SoftDeleteTemplateIfUnused(context.Background(), db.SoftDeleteTemplateIfUnusedParams{ID: b.TemplateID, TeamID: b.TeamID})
				if err != nil || !r.Deleted {
					t.Fatalf("delete: %+v %v", r, err)
				}
			}
			if recordExecution(t, a) {
				t.Fatal("terminal build published")
			}
			if id, err := testQueries.ClaimBuildAttempt(context.Background(), b.ID, cell, 10000); err != nil || id != nil {
				t.Fatal("terminal build revived")
			}
			var cleanup bool
			if err := testPool.QueryRow(context.Background(), `SELECT cleanup_pending FROM template_build_attempt WHERE id=$1`, a.ID).Scan(&cleanup); err != nil || !cleanup {
				t.Fatal("lost cancellation cleanup ownership")
			}
		})
	}
}
func TestIntegration_BuildPublicationSubmissionOrdering(t *testing.T) {
	b, cell := executionFixture(t)
	executionHost(t, cell, "active")
	old := claimExecution(t, b, cell)
	admitExecution(t, old)
	if _, err := testPool.Exec(context.Background(), `UPDATE template SET build_spec='{"from":"example/image:new"}',vcpu=8 WHERE id=$1`, b.TemplateID); err != nil {
		t.Fatal(err)
	}
	newer, err := testQueries.CreateTemplateBuild(context.Background(), db.CreateTemplateBuildParams{TemplateID: b.TemplateID, TeamID: b.TeamID, BuildSpecHash: "new-input"})
	if err != nil {
		t.Fatal(err)
	}
	next := claimExecution(t, newer, cell)
	admitExecution(t, next)
	if !recordExecution(t, next) {
		t.Fatal("record new")
	}
	if ok, err := testQueries.AcceptBuildPublication(context.Background(), newer.ID, next.ID); err != nil || !ok {
		t.Fatalf("accept new: %v %v", ok, err)
	}
	if !recordExecution(t, old) {
		t.Fatal("record older result")
	}
	if ok, err := testQueries.AcceptBuildPublication(context.Background(), b.ID, old.ID); err != nil || ok {
		t.Fatalf("older result replaced newer: %v %v", ok, err)
	}
	tpl, err := testQueries.GetTemplateForOwner(context.Background(), db.GetTemplateForOwnerParams{ID: b.TemplateID, TeamID: b.TeamID})
	if err != nil || tpl.Vcpu != 8 || tpl.Status != "ready" {
		t.Fatalf("new ready version changed: %+v %v", tpl, err)
	}
}

func TestIntegration_FailedOrCancelledRebuildPreservesAcceptedVersion(t *testing.T) {
	for _, outcome := range []string{"fail", "cancel"} {
		t.Run(outcome, func(t *testing.T) {
			ctx := context.Background()
			original, cell := executionFixture(t)
			executionHost(t, cell, "active")
			first := claimExecution(t, original, cell)
			admitExecution(t, first)
			if !recordExecution(t, first) {
				t.Fatal("record original publication")
			}
			if ok, err := testQueries.AcceptBuildPublication(ctx, original.ID, first.ID); err != nil || !ok {
				t.Fatalf("accept original publication: %v %v", ok, err)
			}

			var before struct {
				status, rootfs, snapshot, mem, base, delta string
			}
			readTemplate := func() (string, string, string, string, string, string) {
				t.Helper()
				var status, rootfs, snapshot, mem, base, delta string
				if err := testPool.QueryRow(ctx, `SELECT status,rootfs_path,snapshot_path,mem_path,base_path,delta_path FROM template WHERE id=$1`, original.TemplateID).
					Scan(&status, &rootfs, &snapshot, &mem, &base, &delta); err != nil {
					t.Fatal(err)
				}
				return status, rootfs, snapshot, mem, base, delta
			}
			before.status, before.rootfs, before.snapshot, before.mem, before.base, before.delta = readTemplate()
			if before.status != "ready" || before.rootfs == "" {
				t.Fatalf("original version not ready: %+v", before)
			}

			if _, err := testPool.Exec(ctx, `UPDATE template SET build_spec='{"from":"example/image:rebuild"}' WHERE id=$1`, original.TemplateID); err != nil {
				t.Fatal(err)
			}
			rebuild, err := testQueries.CreateTemplateBuild(ctx, db.CreateTemplateBuildParams{TemplateID: original.TemplateID, TeamID: original.TeamID, BuildSpecHash: "rebuild-input"})
			if err != nil {
				t.Fatal(err)
			}
			second := claimExecution(t, rebuild, cell)
			admitExecution(t, second)
			if outcome == "fail" {
				if ok, err := testQueries.TransitionBuildAttempt(ctx, rebuild.ID, &second.ID, "fail", "build step failed"); err != nil || !ok {
					t.Fatalf("fail rebuild: %v %v", ok, err)
				}
			} else {
				if _, err := testQueries.CancelBuild(ctx, db.CancelBuildParams{ID: rebuild.ID, TemplateID: rebuild.TemplateID, TeamID: rebuild.TeamID}); err != nil {
					t.Fatal(err)
				}
			}

			status, rootfs, snapshot, mem, base, delta := readTemplate()
			if status != before.status || rootfs != before.rootfs || snapshot != before.snapshot || mem != before.mem || base != before.base || delta != before.delta {
				t.Fatalf("rebuild changed accepted paths: before=%+v after=%q %q %q %q %q %q", before, status, rootfs, snapshot, mem, base, delta)
			}
			var acceptedBuild, acceptedAttempt uuid.UUID
			if err := testPool.QueryRow(ctx, `SELECT build_id,attempt_id FROM template_build_publication WHERE template_id=$1 AND accepted_at IS NOT NULL`, original.TemplateID).
				Scan(&acceptedBuild, &acceptedAttempt); err != nil || acceptedBuild != original.ID || acceptedAttempt != first.ID {
				t.Fatalf("accepted version changed: build=%s attempt=%s err=%v", acceptedBuild, acceptedAttempt, err)
			}
			protected, err := testQueries.BuildArtifactProtected(ctx, first.VMID)
			if err != nil || !protected {
				t.Fatalf("original artifact unprotected: %v %v", protected, err)
			}
			referenced, err := testQueries.BuildAttemptReferenced(ctx, first.ID)
			if err != nil || !referenced {
				t.Fatalf("original publication not retained as cleanup reference: %v %v", referenced, err)
			}
			var originalCleanup, rebuildCleanup bool
			if err := testPool.QueryRow(ctx, `SELECT cleanup_pending FROM template_build_attempt WHERE id=$1`, first.ID).Scan(&originalCleanup); err != nil {
				t.Fatal(err)
			}
			if err := testPool.QueryRow(ctx, `SELECT cleanup_pending FROM template_build_attempt WHERE id=$1`, second.ID).Scan(&rebuildCleanup); err != nil {
				t.Fatal(err)
			}
			if originalCleanup || !rebuildCleanup {
				t.Fatalf("cleanup ownership changed: accepted=%v rebuild=%v", originalCleanup, rebuildCleanup)
			}
		})
	}
}

func TestIntegration_NewBuildRejectsLegacyLocalFinalization(t *testing.T) {
	b, _ := executionFixture(t)
	host := "missing-host"
	vm := "build-" + b.ID.String()
	if _, err := testQueries.TryDispatchBuild(context.Background(), db.TryDispatchBuildParams{ID: b.ID, VmdHostID: &host, VmdBuildVmID: &vm}); err == nil {
		t.Fatal("old binary claimed new contract row")
	}
}

func TestIntegration_BuildAdmissionPreservesAlreadyAdmittedDrain(t *testing.T) {
	b, cell := executionFixture(t)
	executionHost(t, cell, "active")
	a := claimExecution(t, b, cell)
	admitExecution(t, a)
	if _, err := testPool.Exec(context.Background(), `UPDATE host SET status='draining' WHERE id=$1`, a.HostID); err != nil {
		t.Fatal(err)
	}
	lost, err := testQueries.BuildAttemptHostLost(context.Background(), a)
	if err != nil || lost {
		t.Fatal("draining admitted work treated as host loss")
	}
	if !recordExecution(t, a) {
		t.Fatal("drained admitted attempt cannot publish")
	}
	ok, err := testQueries.AcceptBuildPublication(context.Background(), b.ID, a.ID)
	if err != nil || !ok {
		t.Fatalf("accept after drain: %v %v", ok, err)
	}
}

func TestIntegration_BuildChangedHostIncarnationRetriesOnAnotherHost(t *testing.T) {
	ctx := context.Background()
	b, cell := executionFixture(t)
	host := executionHost(t, cell, "active")
	a := claimExecution(t, b, cell)
	admitExecution(t, a)
	if a.HostID != host {
		t.Fatalf("attempt owner = %q, want %q", a.HostID, host)
	}
	if lost, err := testQueries.BuildAttemptHostLost(ctx, a); err != nil || lost {
		t.Fatalf("current incarnation lost = %v, err = %v", lost, err)
	}
	newIncarnation := uuid.New()
	if _, err := testPool.Exec(ctx, `SELECT rebind_host_incarnation($1,$2,$3)`, host, a.IncarnationID, newIncarnation); err != nil {
		t.Fatal(err)
	}
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT prepare_host_heartbeat($1,$2)`, host, newIncarnation.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE host SET status='active',last_heartbeat_at=now() WHERE id=$1`, host); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if lost, err := testQueries.BuildAttemptHostLost(ctx, a); err != nil || !lost {
		t.Fatalf("replaced incarnation lost = %v, err = %v", lost, err)
	}
	if ok, err := testQueries.TransitionBuildAttempt(ctx, b.ID, &a.ID, "retry", "host incarnation replaced"); err != nil || !ok {
		t.Fatalf("fence old attempt: %v, %v", ok, err)
	}
	replacementHost := executionHost(t, cell, "active")
	next := claimExecution(t, b, cell)
	if next.HostID != replacementHost || next.ID == a.ID || next.VMID == a.VMID {
		t.Fatalf("replacement reused old owner or identity: old=%+v next=%+v", a, next)
	}
	e, err := testQueries.GetBuildExecution(ctx, b.ID)
	if err != nil || e.CurrentAttempt == nil || *e.CurrentAttempt != next.ID || e.Attempts != 2 {
		t.Fatalf("retry execution = %+v, err = %v", e, err)
	}
	if recordExecution(t, a) {
		t.Fatal("replaced incarnation published its old attempt")
	}
}

func TestIntegration_BuildThreeAttemptsAndImmutableInputIdentity(t *testing.T) {
	b, cell := executionFixture(t)
	for range 4 {
		executionHost(t, cell, "active")
	}
	for range 3 {
		a := claimExecution(t, b, cell)
		admitExecution(t, a)
		if _, err := testQueries.TransitionBuildAttempt(context.Background(), b.ID, &a.ID, "retry", "host lost"); err != nil {
			t.Fatal(err)
		}
	}
	if id, err := testQueries.ClaimBuildAttempt(context.Background(), b.ID, cell, 10000); err != nil || id != nil {
		t.Fatal("fourth execution accepted")
	}
	// Even an old submitter hashing only the spec cannot duplicate an input.
	if _, err := testQueries.CreateTemplateBuild(context.Background(), db.CreateTemplateBuildParams{TemplateID: b.TemplateID, TeamID: b.TeamID, BuildSpecHash: "legacy-format-hash"}); err == nil {
		t.Fatal("mixed hash formats duplicated logical build")
	}
}
func TestIntegration_BuildReadyRequiresPublication(t *testing.T) {
	b, cell := executionFixture(t)
	executionHost(t, cell, "active")
	a := claimExecution(t, b, cell)
	admitExecution(t, a)
	if ok, err := testQueries.AcceptBuildPublication(context.Background(), b.ID, a.ID); err != nil || ok {
		t.Fatal("accepted local-only build")
	}
	if _, err := testPool.Exec(context.Background(), `UPDATE template_build SET status='ready' WHERE id=$1`, b.ID); err == nil {
		t.Fatal("old finalizer bypassed durable gate")
	}
	if _, err := testQueries.TransitionBuildAttempt(context.Background(), b.ID, &a.ID, "uploading", ""); err != nil {
		t.Fatal(err)
	}
	e, _ := testQueries.GetBuildExecution(context.Background(), b.ID)
	if e.Publication {
		t.Fatal("uploading is publication proof")
	}
	if !recordExecution(t, a) {
		t.Fatal("record publication")
	}
	// Cancellation wins against a stored but not accepted publication.
	if _, err := testQueries.CancelBuild(context.Background(), db.CancelBuildParams{ID: b.ID, TemplateID: b.TemplateID, TeamID: b.TeamID}); err != nil {
		t.Fatal(err)
	}
	if ok, err := testQueries.AcceptBuildPublication(context.Background(), b.ID, a.ID); err != nil || ok {
		t.Fatal("publication revived cancelled build")
	}
}

func TestIntegration_BuildCancelRacesRetry(t *testing.T) {
	b, cell := executionFixture(t)
	executionHost(t, cell, "active")
	executionHost(t, cell, "active")
	a := claimExecution(t, b, cell)
	admitExecution(t, a)
	start := make(chan struct{})
	errs := make(chan error, 2)
	go func() {
		<-start
		_, err := testQueries.CancelBuild(context.Background(), db.CancelBuildParams{ID: b.ID, TemplateID: b.TemplateID, TeamID: b.TeamID})
		errs <- err
	}()
	go func() {
		<-start
		_, err := testQueries.TransitionBuildAttempt(context.Background(), b.ID, &a.ID, "retry", "host lost")
		errs <- err
	}()
	close(start)
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if id, err := testQueries.ClaimBuildAttempt(context.Background(), b.ID, cell, 10000); err != nil || id != nil {
		t.Fatal("retry revived cancelled logical build")
	}
	var state string
	if err := testPool.QueryRow(context.Background(), `SELECT status FROM template_build WHERE id=$1`, b.ID).Scan(&state); err != nil || state != "cancelled" {
		t.Fatalf("state=%s err=%v", state, err)
	}
}
func TestIntegration_BuildCancellationRacesPublication(t *testing.T) {
	b, cell := executionFixture(t)
	executionHost(t, cell, "active")
	a := claimExecution(t, b, cell)
	admitExecution(t, a)
	if !recordExecution(t, a) {
		t.Fatal("record")
	}
	start := make(chan struct{})
	errs := make(chan error, 2)
	go func() {
		<-start
		_, err := testQueries.CancelBuild(context.Background(), db.CancelBuildParams{ID: b.ID, TemplateID: b.TemplateID, TeamID: b.TeamID})
		errs <- err
	}()
	go func() {
		<-start
		_, err := testQueries.AcceptBuildPublication(context.Background(), b.ID, a.ID)
		errs <- err
	}()
	close(start)
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	var state string
	var accepted bool
	if err := testPool.QueryRow(context.Background(), `SELECT b.status,p.accepted_at IS NOT NULL FROM template_build b JOIN template_build_publication p ON p.build_id=b.id WHERE b.id=$1`, b.ID).Scan(&state, &accepted); err != nil {
		t.Fatal(err)
	}
	if (state == "ready" && !accepted) || (state == "cancelled" && accepted) || (state != "ready" && state != "cancelled") {
		t.Fatalf("torn terminal outcome: %s accepted=%v", state, accepted)
	}
}
func TestIntegration_BuildClaimHonorsGlobalLimit(t *testing.T) {
	b, cell := executionFixture(t)
	executionHost(t, cell, "active")
	// Use the current cross-test active count as the existing occupancy. The
	// next claim must fail at that exact bound, regardless of its own cell.
	var occupied int32
	if err := testPool.QueryRow(context.Background(), `SELECT count(*) FROM template_build_execution e JOIN template_build b ON b.id=e.build_id WHERE e.first_started_at IS NOT NULL AND b.status IN ('pending','building','snapshotting')`).Scan(&occupied); err != nil {
		t.Fatal(err)
	}
	id, err := testQueries.ClaimBuildAttempt(context.Background(), b.ID, cell, occupied)
	if err != nil || id != nil {
		t.Fatalf("global cap bypassed: %v %v", id, err)
	}
	e, err := testQueries.GetBuildExecution(context.Background(), b.ID)
	if err != nil || e.Attempts != 0 {
		t.Fatal("capacity scan consumed an attempt")
	}
}

func TestIntegration_BuildSubmissionHonorsTeamLimit(t *testing.T) {
	ctx := context.Background()
	team, key := seedTeamAndKey(t)
	if _, err := testPool.Exec(ctx, `UPDATE team SET build_concurrency=1 WHERE id=$1`, team); err != nil {
		t.Fatal(err)
	}
	tpl, err := testQueries.CreateTemplate(ctx, db.CreateTemplateParams{TeamID: team, Name: "occupied-" + uuid.NewString(),
		BuildSpec: []byte(`{"from":"example/image:stable"}`), Vcpu: 2, MemoryMib: 2048, DiskMib: 4096})
	if err != nil {
		t.Fatal(err)
	}
	build, err := testQueries.CreateTemplateBuild(ctx, db.CreateTemplateBuildParams{TemplateID: tpl.ID, TeamID: team, BuildSpecHash: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `UPDATE template_build SET status='cancelled' WHERE id=$1 AND status IN ('pending','building','snapshotting')`, build.ID)
	})
	r := newRouter(t)
	name := "blocked-" + uuid.NewString()
	body := `{"name":"` + name + `","build_spec":{"from":"example/image:stable"}}`
	resp := do(r, http.MethodPost, "/templates", key, body)
	if resp.Code != http.StatusTooManyRequests {
		t.Fatalf("team cap response: %d %s", resp.Code, resp.Body.String())
	}
	if got := mustJSON(t, resp)["error"].(map[string]interface{})["code"]; got != "too_many_builds" {
		t.Fatalf("team cap error code: %v", got)
	}
	var count int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM template_build WHERE team_id=$1`, team).Scan(&count); err != nil || count != 1 {
		t.Fatalf("team build count=%d err=%v", count, err)
	}
}

func TestIntegration_BuildNoCapacityDoesNotConsumeAttempt(t *testing.T) {
	b, cell := executionFixture(t)
	host := executionHost(t, cell, "active")
	if _, err := testPool.Exec(context.Background(), `UPDATE host_pressure SET running_sandboxes=1,allocated_memory_mib=1024,allocated_vcpus=1,used_net_slots=1,net_slot_ceiling=1 WHERE host_id=$1`, host); err != nil {
		t.Fatal(err)
	}
	if id, err := testQueries.ClaimBuildAttempt(context.Background(), b.ID, cell, 10000); err != nil || id != nil {
		t.Fatalf("full allocator selected: %v %v", id, err)
	}
	e, err := testQueries.GetBuildExecution(context.Background(), b.ID)
	if err != nil || e.Attempts != 0 || e.FirstStartedAt != nil {
		t.Fatalf("scan spent execution budget: %+v %v", e, err)
	}
}

func TestIntegration_BuildHostAdmissionLimits(t *testing.T) {
	cases := []struct {
		name   string
		change string
		allow  bool
	}{
		{"sandbox_limit", "UPDATE host_pressure SET max_sandboxes=3,running_sandboxes=1,provisioning_sandboxes=1,paused_sandboxes=1 WHERE host_id=$1", false},
		{"network_operator_limit", "UPDATE host_pressure SET max_network_slots=2,used_net_slots=1,provisioning_net_slots=1 WHERE host_id=$1", false},
		{"network_allocator_limit", "UPDATE host_pressure SET max_network_slots=10,net_slot_ceiling=2,used_net_slots=2 WHERE host_id=$1", false},
		{"warm_slots_need_fresh_capacity", "UPDATE host_pressure SET max_network_slots=2,used_net_slots=1,warm_net_slots=1 WHERE host_id=$1", false},
		{"stale_pressure", "UPDATE host_pressure SET reported_at=now()-interval '91 seconds' WHERE host_id=$1", false},
		{"missing_pressure", "DELETE FROM host_pressure WHERE host_id=$1", false},
		{"unknown_allocations", "UPDATE host_pressure SET unknown_allocation_vms=1 WHERE host_id=$1", false},
		{"last_available_capacity", "UPDATE host_pressure SET max_sandboxes=2,running_sandboxes=1,max_network_slots=2,used_net_slots=1 WHERE host_id=$1", true},
		{"unlimited_operator_limits", "UPDATE host_pressure SET running_sandboxes=100,used_net_slots=100 WHERE host_id=$1", true},
		{"cpu_memory_overcommit", "UPDATE host_pressure SET allocated_memory_mib=131072,allocated_vcpus=64 WHERE host_id=$1", true},
	}
	for _, tc := range cases {
		for _, stage := range []string{"claim", "acceptance"} {
			t.Run(tc.name+"/"+stage, func(t *testing.T) {
				ctx := context.Background()
				b, cell := executionFixture(t)
				host := executionHost(t, cell, "active")
				var a db.BuildAttempt
				if stage == "acceptance" {
					a = claimExecution(t, b, cell)
				}
				if _, err := testPool.Exec(ctx, tc.change, host); err != nil {
					t.Fatal(err)
				}
				if stage == "claim" {
					id, err := testQueries.ClaimBuildAttempt(ctx, b.ID, cell, 10000)
					if err != nil || (id != nil) != tc.allow {
						t.Fatalf("claim=%v err=%v, want allowed=%v", id, err, tc.allow)
					}
				} else {
					ok, err := testQueries.AdmitBuildAttempt(ctx, a.ID, host, a.IncarnationID)
					if err != nil || ok != tc.allow {
						t.Fatalf("admit=%v err=%v, want allowed=%v", ok, err, tc.allow)
					}
				}
				if !tc.allow {
					e, err := testQueries.GetBuildExecution(ctx, b.ID)
					if err != nil || e.Attempts != 0 || e.CurrentAttempt != nil || e.FirstStartedAt != nil {
						t.Fatalf("rejection spent execution budget: %+v %v", e, err)
					}
				}
			})
		}
	}
}

func TestIntegration_BuildClaimsChargeUnreportedAttempts(t *testing.T) {
	for _, admitted := range []bool{false, true} {
		t.Run(map[bool]string{false: "claimed", true: "admitted"}[admitted], func(t *testing.T) {
			ctx := context.Background()
			b, cell := executionFixture(t)
			host := executionHost(t, cell, "active")
			if _, err := testPool.Exec(ctx, `UPDATE host_pressure SET max_sandboxes=1,max_network_slots=1 WHERE host_id=$1`, host); err != nil {
				t.Fatal(err)
			}
			a := claimExecution(t, b, cell)
			if admitted {
				admitExecution(t, a)
			}
			next, _ := executionFixture(t)
			if id, err := testQueries.ClaimBuildAttempt(ctx, next.ID, cell, 10000); err != nil || id != nil {
				t.Fatalf("unreported attempt bypassed host limits: %v %v", id, err)
			}
			if !admitted {
				admitExecution(t, a)
			}
			// A delayed pre-registration sample can arrive after admission.
			if _, err := testPool.Exec(ctx, `UPDATE host_pressure SET reported_at=now(),max_sandboxes=1,max_network_slots=2 WHERE host_id=$1`, host); err != nil {
				t.Fatal(err)
			}
			if id, err := testQueries.ClaimBuildAttempt(ctx, next.ID, cell, 10000); err != nil || id != nil {
				t.Fatalf("delayed pre-registration report lost the attempt charge: %v %v", id, err)
			}
			// Receipt after admission is still not evidence of inclusion.
			if _, err := testPool.Exec(ctx, `UPDATE host_pressure SET max_sandboxes=2,provisioning_sandboxes=1,used_net_slots=1 WHERE host_id=$1`, host); err != nil {
				t.Fatal(err)
			}
			if id, err := testQueries.ClaimBuildAttempt(ctx, next.ID, cell, 10000); err != nil || id != nil {
				t.Fatalf("delayed sample hid the admitted attempt: %v %v", id, err)
			}
			// An explicit sample containing the build removes its delta.
			if _, err := testPool.Exec(ctx, `UPDATE host_pressure SET included_build_vm_ids=ARRAY[$2]::text[] WHERE host_id=$1`, host, a.VMID); err != nil {
				t.Fatal(err)
			}
			second := claimExecution(t, next, cell)
			admitExecution(t, second)
		})
	}
}

func TestIntegration_BuildClaimsCountStoppingCancelledWorkerOnce(t *testing.T) {
	ctx := context.Background()
	b, cell := executionFixture(t)
	host := executionHost(t, cell, "active")
	a := claimExecution(t, b, cell)
	admitExecution(t, a)
	if _, err := testPool.Exec(ctx, `UPDATE template_build SET status='cancelled' WHERE id=$1`, b.ID); err != nil {
		t.Fatal(err)
	}
	var cleanupPending bool
	if err := testPool.QueryRow(ctx, `SELECT cleanup_pending FROM template_build_attempt WHERE id=$1`, a.ID).Scan(&cleanupPending); err != nil || !cleanupPending {
		t.Fatalf("cancelled attempt must await cleanup: %v %v", cleanupPending, err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE host_pressure SET max_sandboxes=1,provisioning_sandboxes=1,
		included_build_vm_ids=ARRAY[$2]::text[] WHERE host_id=$1`, host, a.VMID); err != nil {
		t.Fatal(err)
	}
	next, _ := executionFixture(t)
	if id, err := testQueries.ClaimBuildAttempt(ctx, next.ID, cell, 10000); err != nil || id != nil {
		t.Fatalf("stopping worker must retain its slot: %v %v", id, err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE host_pressure SET max_sandboxes=2 WHERE host_id=$1`, host); err != nil {
		t.Fatal(err)
	}
	second := claimExecution(t, next, cell)
	admitExecution(t, second)
}

func TestIntegration_BuildAdmissionCountsOwnReservedNetworkSlotOnce(t *testing.T) {
	for _, tc := range []struct {
		name          string
		used          int
		included      string
		wantAdmission bool
	}{
		{name: "own reservation in intervening report", used: 1, included: "own", wantAdmission: true},
		{name: "different reservation in report", used: 1, included: "other", wantAdmission: false},
		{name: "report predates reservation", used: 0, wantAdmission: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			b, cell := executionFixture(t)
			host := executionHost(t, cell, "active")
			if _, err := testPool.Exec(ctx, `UPDATE host_pressure SET max_network_slots=1,net_slot_ceiling=1 WHERE host_id=$1`, host); err != nil {
				t.Fatal(err)
			}
			a := claimExecution(t, b, cell)
			included := ""
			switch tc.included {
			case "own":
				included = a.VMID
			case "other":
				included = "build-" + uuid.NewString()
			}
			if _, err := testPool.Exec(ctx, `UPDATE host_pressure SET used_net_slots=$2,included_build_slot_vm_ids=CASE WHEN $3='' THEN '{}'::text[] ELSE ARRAY[$3]::text[] END,reported_at=now() WHERE host_id=$1`, host, tc.used, included); err != nil {
				t.Fatal(err)
			}
			ok, err := testQueries.AdmitBuildAttempt(ctx, a.ID, host, a.IncarnationID)
			if err != nil || ok != tc.wantAdmission {
				t.Fatalf("admit=%v err=%v, want %v", ok, err, tc.wantAdmission)
			}
		})
	}
}

func TestIntegration_BuildAdmissionCountsOtherReservedNetworkSlotOnce(t *testing.T) {
	for _, tc := range []struct {
		name          string
		used          int
		included      bool
		stale         bool
		limit         int
		wantAdmission bool
	}{
		{name: "other reservation in sample", used: 1, included: true, limit: 2, wantAdmission: true},
		{name: "sample before other reservation", used: 0, limit: 2, wantAdmission: true},
		{name: "capacity genuinely full", used: 2, included: true, limit: 2},
		{name: "unproven reservation", used: 1, limit: 2},
		{name: "stale reservation evidence", used: 1, included: true, stale: true, limit: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			first, cell := executionFixture(t)
			host := executionHost(t, cell, "active")
			if _, err := testPool.Exec(ctx, `UPDATE host_pressure SET max_sandboxes=2,max_network_slots=$2,net_slot_ceiling=$2 WHERE host_id=$1`, host, tc.limit); err != nil {
				t.Fatal(err)
			}
			other := claimExecution(t, first, cell)
			second, _ := executionFixture(t)
			a := claimExecution(t, second, cell)
			if tc.included {
				if _, err := testPool.Exec(ctx, `UPDATE host_pressure SET used_net_slots=$2,included_build_slot_vm_ids=ARRAY[$3]::text[],reported_at=CASE WHEN $4 THEN (SELECT claimed_at - interval '1 second' FROM template_build_attempt WHERE id=$5) ELSE now() END WHERE host_id=$1`, host, tc.used, other.VMID, tc.stale, other.ID); err != nil {
					t.Fatal(err)
				}
			} else if _, err := testPool.Exec(ctx, `UPDATE host_pressure SET used_net_slots=$2,included_build_slot_vm_ids='{}'::text[] WHERE host_id=$1`, host, tc.used); err != nil {
				t.Fatal(err)
			}
			ok, err := testQueries.AdmitBuildAttempt(ctx, a.ID, host, a.IncarnationID)
			if err != nil || ok != tc.wantAdmission {
				t.Fatalf("admit=%v err=%v, want %v", ok, err, tc.wantAdmission)
			}
		})
	}
}

func TestIntegration_BuildSlotEvidenceRequiresCurrentIncarnation(t *testing.T) {
	ctx := context.Background()
	b, cell := executionFixture(t)
	host := executionHost(t, cell, "active")
	if _, err := testPool.Exec(ctx, `UPDATE host_pressure SET max_network_slots=1,net_slot_ceiling=1 WHERE host_id=$1`, host); err != nil {
		t.Fatal(err)
	}
	a := claimExecution(t, b, cell)
	if _, err := testPool.Exec(ctx, `UPDATE host_pressure SET used_net_slots=1,included_build_slot_vm_ids=ARRAY[$2]::text[] WHERE host_id=$1`, host, a.VMID); err != nil {
		t.Fatal(err)
	}
	var capacity bool
	if err := testPool.QueryRow(ctx, `SELECT template_build_host_has_capacity($1,$2,$3)`, host, uuid.New(), a.ID).Scan(&capacity); err != nil {
		t.Fatal(err)
	}
	if capacity {
		t.Fatal("foreign incarnation used the attempt's reservation evidence")
	}
}

func TestTemplateBuildMigrationOrder(t *testing.T) {
	input := "20260924000013_template_build_input.sql"
	execution := "20260924000014_template_build_execution.sql"
	const latestMainVersion = "20260924000012"
	if input[:14] <= latestMainVersion || execution[:14] <= input[:14] {
		t.Fatal("template build migrations must follow main and apply input before execution")
	}
	migrationsDir, err := findMigrationsDir()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{input, execution} {
		if _, err := os.Stat(filepath.Join(migrationsDir, name)); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]string)
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".sql") || len(name) < 15 {
			continue
		}
		version := name[:14]
		if previous := seen[version]; previous != "" {
			t.Fatalf("duplicate migration version %s: %s and %s", version, previous, name)
		}
		seen[version] = name
	}
}
