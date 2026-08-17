//go:build integration

package integration

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/telemetry"
)

const coverageGenA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const coverageGenB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

type coverageRow struct {
	region    string
	uncovered int64
	oldestAge float64
}

// The coverage query drives from sandbox rows, so paused sandboxes on a
// missing host row still surface, hosts whose paused population is
// fully covered emit an explicit zero, and the oldest-uncovered age is
// anchored on the snapshot behind sandbox.snapshot_id with clock skew
// clamped to zero. Assertions are keyed by this test's own host ids;
// the query is global and other suites seed sandboxes too.
func TestIntegration_BackupCoverageQuery(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedTeamAndKey(t)

	seedHost := func(id, region string) {
		t.Helper()
		if _, err := testPool.Exec(ctx, `
			INSERT INTO host (id, vmd_addr, proxy_addr, region, capacity_memory_mib, capacity_vcpus)
			VALUES ($1, 'vmd:5000', 'proxy:8080', $2, 65536, 64)
			ON CONFLICT (id) DO NOTHING`, id, region); err != nil {
			t.Fatalf("seed host %s: %v", id, err)
		}
	}
	seedHost("cov-a", "us-west2")
	seedHost("cov-b", "us-west2")
	// cov-missing gets no host row on purpose.

	seedSandbox := func(name, hostID, status string, destroyed bool) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		var destroyedAt *time.Time
		if destroyed {
			now := time.Now()
			destroyedAt = &now
		}
		if err := testPool.QueryRow(ctx, `
			INSERT INTO sandbox (team_id, name, status, host_id, destroyed_at)
			VALUES ($1, $2, $3::sandbox_status, $4, $5)
			RETURNING id`, teamID, name, status, hostID, destroyedAt).Scan(&id); err != nil {
			t.Fatalf("seed sandbox %s: %v", name, err)
		}
		return id
	}
	attachSnapshot := func(sandboxID uuid.UUID, createdAt time.Time) {
		t.Helper()
		var snapID uuid.UUID
		if err := testPool.QueryRow(ctx, `
			INSERT INTO snapshot (sandbox_id, team_id, path, trigger, created_at)
			VALUES ($1, $2, '/snapshots/cov/vmstate.snap', 'manual', $3)
			RETURNING id`, sandboxID, teamID, createdAt).Scan(&snapID); err != nil {
			t.Fatalf("seed snapshot: %v", err)
		}
		if _, err := testPool.Exec(ctx,
			`UPDATE sandbox SET snapshot_id = $1 WHERE id = $2`, snapID, sandboxID); err != nil {
			t.Fatalf("attach snapshot: %v", err)
		}
	}
	cover := func(sandboxID uuid.UUID, generation string) {
		t.Helper()
		if _, err := testPool.Exec(ctx, `
			INSERT INTO backup_generation (sandbox_id, generation, bucket, completed_at, files)
			VALUES ($1, $2, 'cov-bucket', now(), '[]'::jsonb)`, sandboxID, generation); err != nil {
			t.Fatalf("seed backup_generation: %v", err)
		}
	}

	// cov-a: two uncovered paused sandboxes survive the filters; the
	// covered, destroyed, and non-paused ones do not.
	oldUncovered := seedSandbox("cov-old-uncovered", "cov-a", "paused", false)
	attachSnapshot(oldUncovered, time.Now().Add(-2*time.Hour))
	seedSandbox("cov-no-snapshot", "cov-a", "paused", false) // NULL snapshot_id: uncovered, no age
	covered := seedSandbox("cov-covered", "cov-a", "paused", false)
	attachSnapshot(covered, time.Now().Add(-3*time.Hour))
	cover(covered, coverageGenA)
	cover(covered, coverageGenB) // a second generation must not double count anything
	destroyed := seedSandbox("cov-destroyed", "cov-a", "paused", true)
	attachSnapshot(destroyed, time.Now().Add(-4*time.Hour))
	seedSandbox("cov-active", "cov-a", "active", false)

	// cov-b: fully covered, must still emit an explicit zero row.
	convergedB := seedSandbox("cov-b-covered", "cov-b", "paused", false)
	cover(convergedB, coverageGenA)

	// cov-missing: no host row; a future snapshot timestamp (clock skew)
	// must clamp the age to zero, not go negative.
	future := seedSandbox("cov-orphan", "cov-missing", "paused", false)
	attachSnapshot(future, time.Now().Add(time.Hour))

	rows, err := testPool.Query(ctx, telemetry.BackupCoverageQuery)
	if err != nil {
		t.Fatalf("coverage query: %v", err)
	}
	defer rows.Close()

	got := map[string]coverageRow{}
	for rows.Next() {
		var region, hostID string
		var r coverageRow
		if err := rows.Scan(&region, &hostID, &r.uncovered, &r.oldestAge); err != nil {
			t.Fatalf("scan: %v", err)
		}
		r.region = region
		got[hostID] = r
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}

	a, ok := got["cov-a"]
	if !ok {
		t.Fatal("no row for cov-a")
	}
	if a.region != "us-west2" || a.uncovered != 2 {
		t.Fatalf("cov-a = %+v, want region us-west2 uncovered 2", a)
	}
	// Oldest uncovered pause is ~2h old; the covered 3h and destroyed 4h
	// snapshots must not stretch it, and the NULL-snapshot sandbox must
	// not shrink it.
	if a.oldestAge < 7100 || a.oldestAge > 7500 {
		t.Fatalf("cov-a oldest age = %v, want ~7200", a.oldestAge)
	}

	b, ok := got["cov-b"]
	if !ok {
		t.Fatal("no row for cov-b: a fully covered host must emit an explicit zero")
	}
	if b.uncovered != 0 || b.oldestAge != 0 {
		t.Fatalf("cov-b = %+v, want uncovered 0 age 0", b)
	}

	m, ok := got["cov-missing"]
	if !ok {
		t.Fatal("no row for cov-missing: paused sandboxes on a missing host row must surface")
	}
	if m.region != "unknown" || m.uncovered != 1 || m.oldestAge != 0 {
		t.Fatalf("cov-missing = %+v, want region unknown uncovered 1 age 0 (future timestamp clamps)", m)
	}
}

// The lease claim is the mutual-exclusion primitive under the sampler
// election, so its invariants are proven here deterministically, with
// no running samplers and no timing assumptions: expiry is forced by
// rewriting locked_until rather than by waiting.
func TestIntegration_BackupCoverageLeaseClaim(t *testing.T) {
	ctx := context.Background()
	if _, err := testPool.Exec(ctx, `DELETE FROM telemetry_sampler_lease`); err != nil {
		t.Fatalf("reset lease table: %v", err)
	}

	claim := func(holder string) bool {
		t.Helper()
		got, err := telemetry.ClaimBackupCoverageLease(ctx, testPool, holder, 10*time.Second)
		if err != nil {
			t.Fatalf("claim as %s: %v", holder, err)
		}
		return got
	}
	expire := func() {
		t.Helper()
		if _, err := testPool.Exec(ctx,
			`UPDATE telemetry_sampler_lease SET locked_until = now() - interval '1 second'`); err != nil {
			t.Fatalf("force lease expiry: %v", err)
		}
	}

	if !claim("lease-a") {
		t.Fatal("first claim on an empty table must win")
	}
	// The follower-silence invariant: while another holder's lease is
	// valid, a claim must fail, every time.
	for i := 0; i < 3; i++ {
		if claim("lease-b") {
			t.Fatal("claim won against another holder's valid lease")
		}
	}
	if !claim("lease-a") {
		t.Fatal("holder failed to renew its own valid lease")
	}
	if claim("lease-b") {
		t.Fatal("claim won against a freshly renewed lease")
	}

	expire()
	if !claim("lease-b") {
		t.Fatal("claim failed against an expired lease")
	}
	if claim("lease-a") {
		t.Fatal("previous holder reclaimed a lease now validly held by another")
	}

	// Concurrent contention for an expired lease: exactly one contender
	// may conclude it won. This is the arbitration that keeps two
	// replicas from both believing they lead; the sampler separately
	// bounds its claim-to-publish window to a third of the lease (see
	// backupCoverageTickTimeout) so a stalled leader cannot publish on
	// a lease that has already been handed over.
	expire()
	var wins atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got, err := telemetry.ClaimBackupCoverageLease(ctx, testPool, fmt.Sprintf("contender-%d", i), 10*time.Second)
			if err != nil {
				t.Errorf("contender %d claim: %v", i, err)
				return
			}
			if got {
				wins.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if got := wins.Load(); got != 1 {
		t.Fatalf("concurrent contention produced %d winners, want exactly 1", got)
	}
}

// coverageCountRecorder counts non-empty snapshot publications from a
// sampler goroutine (a follower publishes empty snapshots, which do not
// count as sampling); everything else no-ops via the embedded recorder.
type coverageCountRecorder struct {
	telemetry.Recorder
	n atomic.Int64
}

func (r *coverageCountRecorder) RecordBackupCoverage(_ context.Context, snapshot []telemetry.BackupCoverage) {
	if len(snapshot) > 0 {
		r.n.Add(1)
	}
}

func waitForRecords(t *testing.T, rec *coverageCountRecorder, within time.Duration, msg string) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if rec.n.Load() > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal(msg)
}

// A replica running with the noop recorder (OTel init failed) must not
// contend for the lease at all: if it could win, it would renew forever
// while publishing nothing, black-holing the cell's coverage series
// and locking out replicas that can export.
func TestIntegration_BackupCoverageSamplerNoopRecorderNeverClaims(t *testing.T) {
	ctx := context.Background()
	if _, err := testPool.Exec(ctx, `DELETE FROM telemetry_sampler_lease`); err != nil {
		t.Fatalf("reset lease table: %v", err)
	}

	samplerCtx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	telemetry.StartBackupCoverageSampler(samplerCtx, testPool, telemetry.NewNoopRecorder(), 50*time.Millisecond)

	// Outlast the startup jitter (bounded by 1s) plus many ticks.
	time.Sleep(1600 * time.Millisecond)
	var leases int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM telemetry_sampler_lease`).Scan(&leases); err != nil {
		t.Fatalf("count leases: %v", err)
	}
	if leases != 0 {
		t.Fatalf("noop-recorder replica claimed the sampler lease (%d rows)", leases)
	}
}

// End-to-end election: a sampler wins the lease and publishes, and when
// it stops renewing, the lease lapses and a follower takes over without
// any coordination beyond the lease row. Follower silence while a valid
// lease is held is deliberately NOT asserted here: with the short lease
// this test runs on, a scheduler stall in the leader's goroutine can
// legitimately lapse the lease mid-window and hand it over, so that
// invariant is only honest at the claim level, where the lease-claim
// test above proves it deterministically.
func TestIntegration_BackupCoverageSamplerElection(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedTeamAndKey(t)

	// Clear any lease left by earlier tests so A does not have to wait
	// out a stale deadline before winning.
	if _, err := testPool.Exec(ctx, `DELETE FROM telemetry_sampler_lease`); err != nil {
		t.Fatalf("reset lease table: %v", err)
	}
	// At least one paused sandbox so a leader's sample records rows.
	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox (team_id, name, status, host_id)
		VALUES ($1, 'cov-elect', 'paused', 'cov-elect-host')`, teamID); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	ctxA, cancelA := context.WithCancel(ctx)
	t.Cleanup(cancelA)
	ctxB, cancelB := context.WithCancel(ctx)
	t.Cleanup(cancelB)

	recA := &coverageCountRecorder{Recorder: telemetry.NewNoopRecorder()}
	recB := &coverageCountRecorder{Recorder: telemetry.NewNoopRecorder()}

	// 100ms ticks clamp the tick budget to a third of the 300ms lease,
	// which still leaves a loaded CI runner room to finish a claim and
	// a scan inside one budget on some tick within the wait windows.
	telemetry.StartBackupCoverageSampler(ctxA, testPool, recA, 100*time.Millisecond)
	// A's startup jitter is bounded by 1s; give it time to win and run.
	waitForRecords(t, recA, 5*time.Second, "first sampler never became leader")

	// Leader shutdown stops A's renewals; once the lease lapses, B must
	// take over.
	cancelA()
	telemetry.StartBackupCoverageSampler(ctxB, testPool, recB, 100*time.Millisecond)
	waitForRecords(t, recB, 10*time.Second, "follower never took over after the leader exited")
}
