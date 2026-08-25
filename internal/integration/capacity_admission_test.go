//go:build integration

package integration

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/scheduler"
)

// seedPressureHost creates an active host with a pressure report of the
// given age and limits, and cleans both up. Everything the admission
// fence reads lives in these two rows.
func seedPressureHost(t *testing.T, hostID string, reportAge time.Duration, apply func(*db.UpsertHostPressureParams)) {
	t.Helper()
	ctx := context.Background()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO host (id, vmd_addr, proxy_addr, region, capacity_memory_mib, capacity_vcpus, status)
		VALUES ($1, $2, $3, 'test-region', 65536, 64, 'active')`,
		hostID, hostID+":50051", hostID+":5007"); err != nil {
		t.Fatalf("seed host: %v", err)
	}
	t.Cleanup(func() {
		if _, err := testPool.Exec(context.Background(), `DELETE FROM host WHERE id = $1`, hostID); err != nil {
			t.Errorf("cleanup host %s: %v", hostID, err)
		}
	})

	p := db.UpsertHostPressureParams{
		HostID:         hostID,
		VmdAddr:        hostID + ":50051",
		MaxSandboxes:   100,
		NetSlotCeiling: 200,
		LeaseSecs:      scheduler.ReservationLeaseSecs,
		SlackSecs:      scheduler.ReservationRetireSlackSecs,
	}
	if apply != nil {
		apply(&p)
	}
	if _, err := testQueries.UpsertHostPressure(ctx, p); err != nil {
		t.Fatalf("seed pressure: %v", err)
	}
	// reported_at comes from the database clock inside the upsert; age it
	// afterwards so freshness tests do not depend on the test's clock.
	if reportAge > 0 {
		if _, err := testPool.Exec(ctx,
			`UPDATE host_pressure SET reported_at = now() - $2::interval WHERE host_id = $1`,
			hostID, fmt.Sprintf("%d seconds", int(reportAge.Seconds()))); err != nil {
			t.Fatalf("age pressure: %v", err)
		}
	}
}

func reserve(t *testing.T, hostID string, sandboxID uuid.UUID) bool {
	t.Helper()
	_, err := testQueries.ReserveHostCapacity(context.Background(), db.ReserveHostCapacityParams{
		SandboxID:     sandboxID,
		MemoryMib:     512,
		Vcpus:         1,
		HostID:        hostID,
		FreshnessSecs: scheduler.PressureFreshnessSecs,
	})
	if err != nil && !strings.Contains(err.Error(), "no rows") {
		t.Fatalf("reserve on %s: %v", hostID, err)
	}
	return err == nil
}

// report re-runs the pressure upsert exactly as the report handler
// does, which is the fence's reconciliation point: the charge counters
// are recomputed from the ledger against the new reported_at.
func report(t *testing.T, hostID string, apply func(*db.UpsertHostPressureParams)) {
	t.Helper()
	p := db.UpsertHostPressureParams{
		HostID:         hostID,
		VmdAddr:        hostID + ":50051",
		MaxSandboxes:   100,
		NetSlotCeiling: 200,
		LeaseSecs:      scheduler.ReservationLeaseSecs,
		SlackSecs:      scheduler.ReservationRetireSlackSecs,
	}
	if apply != nil {
		apply(&p)
	}
	rows, err := testQueries.UpsertHostPressure(context.Background(), p)
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if rows != 1 {
		t.Fatalf("report wrote %d rows, want 1", rows)
	}
}

func chargedCount(t *testing.T, hostID string) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(context.Background(),
		`SELECT charged_count FROM host_pressure WHERE host_id = $1`, hostID).Scan(&n); err != nil {
		t.Fatalf("read charged_count: %v", err)
	}
	return n
}

func reservationCount(t *testing.T, hostID string) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM host_reservation WHERE host_id = $1`, hostID).Scan(&n); err != nil {
		t.Fatalf("count reservations: %v", err)
	}
	return n
}

func hostSuffix(t *testing.T) string {
	t.Helper()
	name := strings.ToLower(t.Name())
	if len(name) > 12 {
		name = name[len(name)-12:]
	}
	return strings.ReplaceAll(name, "_", "-")
}

// The admission fence is the whole point of the ledger: concurrent
// replicas racing between pressure reports must not both spend the same
// headroom. With room for exactly 3 more sandboxes and 20 simultaneous
// admissions, exactly 3 may win.
func TestIntegration_CapacityAdmission_ConcurrentReplicasCannotOverPlace(t *testing.T) {
	hostID := "cap-" + hostSuffix(t)
	seedPressureHost(t, hostID, 0, func(p *db.UpsertHostPressureParams) {
		p.MaxSandboxes = 10
		p.RunningSandboxes = 7 // room for exactly 3
	})

	const racers = 20
	var wg sync.WaitGroup
	results := make([]bool, racers)
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := uuid.New()
			<-start
			_, err := testQueries.ReserveHostCapacity(context.Background(), db.ReserveHostCapacityParams{
				SandboxID:     id,
				MemoryMib:     512,
				Vcpus:         1,
				HostID:        hostID,
				FreshnessSecs: scheduler.PressureFreshnessSecs,
			})
			results[i] = err == nil
		}(i)
	}
	close(start)
	wg.Wait()

	admitted := 0
	for _, ok := range results {
		if ok {
			admitted++
		}
	}
	if admitted != 3 {
		t.Fatalf("admitted %d of %d racers, want exactly 3 (limit 10, running 7)", admitted, racers)
	}
	if got := reservationCount(t, hostID); got != 3 {
		t.Fatalf("ledger rows = %d, want 3", got)
	}
}

// Network slots are their own limit, and warm slots are already-prepared
// inventory: a reservation only implies a NEW slot once the warm pool is
// exhausted.
func TestIntegration_CapacityAdmission_SlotCeilingCountsWarmInventory(t *testing.T) {
	hostID := "slot-" + hostSuffix(t)
	seedPressureHost(t, hostID, 0, func(p *db.UpsertHostPressureParams) {
		p.MaxSandboxes = 0 // unset: only the slot limit applies
		p.MaxNetworkSlots = 10
		p.NetSlotCeiling = 10
		p.UsedNetSlots = 8
		p.WarmNetSlots = 2 // 8 used + 2 warm = 10 prepared, at the ceiling
	})

	// The first two creates consume warm inventory: no new slot implied.
	for i := 0; i < 2; i++ {
		if !reserve(t, hostID, uuid.New()) {
			t.Fatalf("create %d rejected; warm inventory should absorb it", i)
		}
	}
	// The third would need a slot beyond the ceiling.
	if reserve(t, hostID, uuid.New()) {
		t.Fatal("admitted a create past the slot ceiling with no warm inventory left")
	}
}

// Fail-closed on stale pressure, enforced by the statement itself (not
// just the scheduler's cached pre-filter): a report older than the
// freshness window admits nothing, whatever the numbers say.
func TestIntegration_CapacityAdmission_StaleReportAdmitsNothing(t *testing.T) {
	hostID := "stale-" + hostSuffix(t)
	seedPressureHost(t, hostID, (scheduler.PressureFreshnessSecs+60)*time.Second, nil)

	if reserve(t, hostID, uuid.New()) {
		t.Fatal("admitted against a stale pressure report")
	}
	// Refreshing the report re-opens admission with no other change.
	if _, err := testPool.Exec(context.Background(),
		`UPDATE host_pressure SET reported_at = now() WHERE host_id = $1`, hostID); err != nil {
		t.Fatalf("refresh report: %v", err)
	}
	if !reserve(t, hostID, uuid.New()) {
		t.Fatal("rejected against a fresh report with capacity to spare")
	}
}

// A host with no pressure row at all (never published) and a host that is
// not active both admit nothing: the fence has nothing to charge against.
func TestIntegration_CapacityAdmission_UnpublishedAndInactiveHostsAdmitNothing(t *testing.T) {
	ctx := context.Background()
	bare := "bare-" + hostSuffix(t)
	if _, err := testPool.Exec(ctx, `
		INSERT INTO host (id, vmd_addr, proxy_addr, region, capacity_memory_mib, capacity_vcpus, status)
		VALUES ($1, $2, $3, 'test-region', 65536, 64, 'active')`,
		bare, bare+":50051", bare+":5007"); err != nil {
		t.Fatalf("seed bare host: %v", err)
	}
	t.Cleanup(func() { testPool.Exec(context.Background(), `DELETE FROM host WHERE id = $1`, bare) })
	if reserve(t, bare, uuid.New()) {
		t.Fatal("admitted against a host that has never published pressure")
	}

	draining := "drain-" + hostSuffix(t)
	seedPressureHost(t, draining, 0, nil)
	if _, err := testPool.Exec(ctx, `UPDATE host SET status = 'draining' WHERE id = $1`, draining); err != nil {
		t.Fatalf("drain host: %v", err)
	}
	if reserve(t, draining, uuid.New()) {
		t.Fatal("admitted onto a draining host")
	}
}

// Reservations are keyed by sandbox id: a control-plane retry of the same
// create re-admits without double-charging, and re-admitting against a
// different host MOVES the row (the sandbox can only dispatch to the last
// admitted host).
func TestIntegration_CapacityAdmission_IsIdempotentPerSandbox(t *testing.T) {
	hostA := "idem-a-" + hostSuffix(t)
	hostB := "idem-b-" + hostSuffix(t)
	seedPressureHost(t, hostA, 0, nil)
	seedPressureHost(t, hostB, 0, nil)

	id := uuid.New()
	for i := 0; i < 3; i++ {
		if !reserve(t, hostA, id) {
			t.Fatalf("retry %d rejected; a repeated admission must return the reservation it already holds", i)
		}
	}
	if got := reservationCount(t, hostA); got != 1 {
		t.Fatalf("ledger rows for one sandbox = %d, want 1", got)
	}
	if got := chargedCount(t, hostA); got != 1 {
		t.Fatalf("charged_count = %d after 3 retries, want 1 (retries must not charge twice)", got)
	}

	// A sandbox is bound to the host its first admission chose:
	// re-admitting elsewhere is refused, never silently moved, so no two
	// hosts can ever charge for the same sandbox.
	if reserve(t, hostB, id) {
		t.Fatal("admitted an already-reserved sandbox onto a second host")
	}
	if got := reservationCount(t, hostB); got != 0 {
		t.Fatalf("host B holds %d ledger rows for a sandbox reserved on host A", got)
	}
}

// The retirement contract: a materialized reservation keeps charging
// until a report lands slack-clear of the moment the VM materialized —
// because a report SAMPLED before that moment can ARRIVE after it, and
// retiring on arrival order alone would free capacity the report does
// not yet account for.
func TestIntegration_CapacityAdmission_MaterializedRowsRetireOnlyAfterSlack(t *testing.T) {
	ctx := context.Background()
	hostID := "retire-" + hostSuffix(t)
	tight := func(p *db.UpsertHostPressureParams) {
		p.MaxSandboxes = 5
		p.RunningSandboxes = 4 // room for exactly one
	}
	seedPressureHost(t, hostID, 0, tight)

	id := uuid.New()
	if !reserve(t, hostID, id) {
		t.Fatal("first reservation rejected")
	}
	if err := testQueries.MaterializeHostReservation(ctx, id); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	// The VM exists but the last report predates it, so the reservation
	// is still the only record of it: the next create must be refused.
	if reserve(t, hostID, uuid.New()) {
		t.Fatal("admitted a second create while a materialized reservation still charged")
	}

	// A report arriving without clearing the slack window must keep the
	// charge: it may have been SAMPLED before the VM materialized, so
	// its counts cannot be trusted to include it yet.
	report(t, hostID, tight)
	if got := chargedCount(t, hostID); got != 1 {
		t.Fatalf("charged_count = %d after an early report, want 1", got)
	}
	if reserve(t, hostID, uuid.New()) {
		t.Fatal("admitted on a report that had not cleared the slack window")
	}

	// Once materialization is slack-clear, the next report provably
	// counts the VM itself and the reservation stops charging.
	if _, err := testPool.Exec(ctx, `
		UPDATE host_reservation SET materialized_at = now() - $2::interval WHERE sandbox_id = $1`,
		id, fmt.Sprintf("%d seconds", scheduler.ReservationRetireSlackSecs+5)); err != nil {
		t.Fatalf("age materialization: %v", err)
	}
	report(t, hostID, tight)
	if got := chargedCount(t, hostID); got != 0 {
		t.Fatalf("charged_count = %d after a slack-clear report, want 0", got)
	}
	if !reserve(t, hostID, uuid.New()) {
		t.Fatal("still charging a reservation the fresh report provably covers")
	}
}

// A create that dies between admission and dispatch (no release, no
// materialization) stops charging when its lease lapses, so a crashed
// replica cannot strand capacity forever.
func TestIntegration_CapacityAdmission_AbandonedReservationsExpire(t *testing.T) {
	ctx := context.Background()
	hostID := "lease-" + hostSuffix(t)
	tight := func(p *db.UpsertHostPressureParams) {
		p.MaxSandboxes = 5
		p.RunningSandboxes = 4
	}
	seedPressureHost(t, hostID, 0, tight)

	abandoned := uuid.New()
	if !reserve(t, hostID, abandoned) {
		t.Fatal("first reservation rejected")
	}
	if reserve(t, hostID, uuid.New()) {
		t.Fatal("admitted past the limit while a live reservation charged")
	}
	if _, err := testPool.Exec(ctx, `
		UPDATE host_reservation SET created_at = now() - $2::interval WHERE sandbox_id = $1`,
		abandoned, fmt.Sprintf("%d seconds", scheduler.ReservationLeaseSecs+5)); err != nil {
		t.Fatalf("age reservation: %v", err)
	}
	// The lease lapses at the reconciliation point, so a replica that
	// died between admission and dispatch strands capacity for at most
	// one heartbeat interval past its lease.
	report(t, hostID, tight)
	if got := chargedCount(t, hostID); got != 0 {
		t.Fatalf("charged_count = %d after an expired lease was reconciled, want 0", got)
	}
	if !reserve(t, hostID, uuid.New()) {
		t.Fatal("an expired-lease reservation is still charging capacity")
	}
}

// Release frees capacity immediately — the path every failed create
// takes, so a rejected boot does not cost the host a slot until the next
// report.
func TestIntegration_CapacityAdmission_ReleaseFreesCapacityImmediately(t *testing.T) {
	hostID := "rel-" + hostSuffix(t)
	seedPressureHost(t, hostID, 0, func(p *db.UpsertHostPressureParams) {
		p.MaxSandboxes = 5
		p.RunningSandboxes = 4
	})

	id := uuid.New()
	if !reserve(t, hostID, id) {
		t.Fatal("first reservation rejected")
	}
	if reserve(t, hostID, uuid.New()) {
		t.Fatal("admitted past the limit")
	}
	if err := testQueries.ReleaseHostReservation(context.Background(), id); err != nil {
		t.Fatalf("release: %v", err)
	}
	if !reserve(t, hostID, uuid.New()) {
		t.Fatal("capacity was not freed by release")
	}
}

// A duplicated abort (the handler's deferred release plus any explicit
// one) must not decrement twice: the second delete removes nothing, so
// it decrements nothing, and the counter cannot drift below the truth.
func TestIntegration_CapacityAdmission_DoubleReleaseDoesNotUnderCount(t *testing.T) {
	ctx := context.Background()
	hostID := "dbl-" + hostSuffix(t)
	seedPressureHost(t, hostID, 0, nil)

	keep, drop := uuid.New(), uuid.New()
	if !reserve(t, hostID, keep) || !reserve(t, hostID, drop) {
		t.Fatal("reservations rejected")
	}
	if got := chargedCount(t, hostID); got != 2 {
		t.Fatalf("charged_count = %d, want 2", got)
	}
	for i := 0; i < 3; i++ {
		if err := testQueries.ReleaseHostReservation(ctx, drop); err != nil {
			t.Fatalf("release %d: %v", i, err)
		}
	}
	if got := chargedCount(t, hostID); got != 1 {
		t.Fatalf("charged_count = %d after three releases of one reservation, want 1", got)
	}
	if got := reservationCount(t, hostID); got != 1 {
		t.Fatalf("ledger rows = %d, want 1", got)
	}
}

// The counters are recomputed from the ledger on every report, so drift
// from any missed decrement heals within one heartbeat interval rather
// than stranding capacity until an operator notices.
func TestIntegration_CapacityAdmission_ReportHealsCounterDrift(t *testing.T) {
	ctx := context.Background()
	hostID := "drift-" + hostSuffix(t)
	seedPressureHost(t, hostID, 0, nil)
	if !reserve(t, hostID, uuid.New()) {
		t.Fatal("reservation rejected")
	}

	// Simulate drift: a charge with no ledger row behind it (the shape a
	// lost decrement leaves).
	if _, err := testPool.Exec(ctx,
		`UPDATE host_pressure SET charged_count = charged_count + 7 WHERE host_id = $1`, hostID); err != nil {
		t.Fatalf("inject drift: %v", err)
	}
	report(t, hostID, nil)
	if got := chargedCount(t, hostID); got != 1 {
		t.Fatalf("charged_count = %d after reconciliation, want 1 (the one live ledger row)", got)
	}
}

// Retirement hygiene deletes exactly the rows the charge predicate
// already ignores, and never a row that is still charging.
func TestIntegration_CapacityAdmission_RetireDropsOnlySettledRows(t *testing.T) {
	ctx := context.Background()
	hostID := "hyg-" + hostSuffix(t)
	seedPressureHost(t, hostID, 0, nil)

	live := uuid.New()      // fresh, unmaterialized: still charging
	settled := uuid.New()   // materialized and slack-clear: retire
	abandoned := uuid.New() // lease lapsed, never materialized: retire
	for _, id := range []uuid.UUID{live, settled, abandoned} {
		if !reserve(t, hostID, id) {
			t.Fatalf("reserve %s rejected", id)
		}
	}
	if _, err := testPool.Exec(ctx, `
		UPDATE host_reservation SET materialized_at = now() - $2::interval WHERE sandbox_id = $1`,
		settled, fmt.Sprintf("%d seconds", scheduler.ReservationRetireSlackSecs+5)); err != nil {
		t.Fatalf("age materialization: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		UPDATE host_reservation SET created_at = now() - $2::interval WHERE sandbox_id = $1`,
		abandoned, fmt.Sprintf("%d seconds", scheduler.ReservationLeaseSecs+5)); err != nil {
		t.Fatalf("age reservation: %v", err)
	}

	if err := testQueries.RetireHostReservations(ctx, db.RetireHostReservationsParams{
		HostID:    hostID,
		SlackSecs: scheduler.ReservationRetireSlackSecs,
		LeaseSecs: scheduler.ReservationLeaseSecs,
	}); err != nil {
		t.Fatalf("retire: %v", err)
	}

	var remaining []uuid.UUID
	rows, err := testPool.Query(ctx, `SELECT sandbox_id FROM host_reservation WHERE host_id = $1`, hostID)
	if err != nil {
		t.Fatalf("list remaining: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan: %v", err)
		}
		remaining = append(remaining, id)
	}
	if len(remaining) != 1 || remaining[0] != live {
		t.Fatalf("remaining rows = %v, want only the still-charging reservation %v", remaining, live)
	}
}

// Reclaiming a host identity cascades its reservations away with the
// host row: the new machine must never inherit the old one's charges.
func TestIntegration_CapacityAdmission_ReservationsCascadeWithHost(t *testing.T) {
	ctx := context.Background()
	hostID := "casc-" + hostSuffix(t)
	seedPressureHost(t, hostID, 0, nil)
	if !reserve(t, hostID, uuid.New()) {
		t.Fatal("reservation rejected")
	}
	if _, err := testPool.Exec(ctx, `DELETE FROM host WHERE id = $1`, hostID); err != nil {
		t.Fatalf("delete host: %v", err)
	}
	if got := reservationCount(t, hostID); got != 0 {
		t.Fatalf("reservations survived their host row: %d", got)
	}
}

// Drain tooling must see reservations: during the reservation-to-dispatch
// gap a create is invisible in every other count, and retiring the host
// then would strand a VM that is about to launch.
func TestIntegration_CapacityAdmission_ReservedCountVisibleToDrain(t *testing.T) {
	ctx := context.Background()
	hostID := "drain-vis-" + hostSuffix(t)
	seedPressureHost(t, hostID, 0, nil)

	id := uuid.New()
	if !reserve(t, hostID, id) {
		t.Fatal("reservation rejected")
	}
	adminRow := func() db.ListHostsAdminRow {
		t.Helper()
		rows, err := testQueries.ListHostsAdmin(ctx, db.ListHostsAdminParams{
			ID:                   &hostID,
			ReservationLeaseSecs: scheduler.ReservationLeaseSecs,
		})
		if err != nil {
			t.Fatalf("ListHostsAdmin: %v", err)
		}
		if len(rows) != 1 {
			t.Fatalf("admin rows = %d, want 1", len(rows))
		}
		return rows[0]
	}
	if got := adminRow().ReservedCount; got != 1 {
		t.Fatalf("reserved_count = %d, want 1 (drain must see the gap)", got)
	}

	// Once the VM exists its sandbox row carries the count, so the
	// reservation stops being separately visible.
	if err := testQueries.MaterializeHostReservation(ctx, id); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if got := adminRow().ReservedCount; got != 0 {
		t.Fatalf("reserved_count = %d after materialization, want 0", got)
	}
}
