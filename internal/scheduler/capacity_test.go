package scheduler

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/db"
)

// candidateRows serves db.ListCapacityCandidatesRow values through the
// pgx.Rows surface sqlc scans, in the generated column order.
type candidateRows struct {
	rows []db.ListCapacityCandidatesRow
	idx  int
}

func (r *candidateRows) Close()                                       {}
func (r *candidateRows) Err() error                                   { return nil }
func (r *candidateRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *candidateRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *candidateRows) Values() ([]any, error)                       { return nil, nil }
func (r *candidateRows) RawValues() [][]byte                          { return nil }
func (r *candidateRows) Conn() *pgx.Conn                              { return nil }

func (r *candidateRows) Next() bool {
	if r.idx >= len(r.rows) {
		return false
	}
	r.idx++
	return true
}

func (r *candidateRows) Scan(dest ...any) error {
	row := r.rows[r.idx-1]
	vals := []any{
		row.ID, row.Region, row.CapacityMemoryMib, row.CapacityVcpus,
		row.PressureCapable, row.ReportedAt, row.RunningSandboxes,
		row.ProvisioningSandboxes, row.PausedSandboxes, row.AllocatedMemoryMib,
		row.AllocatedVcpus, row.UsedNetSlots, row.ProvisioningNetSlots,
		row.WarmNetSlots, row.NetSlotCeiling, row.MaxNetworkSlots,
		row.MaxSandboxes, row.UnknownAllocationVms,
		row.ChargedCount, row.ChargedMemoryMib,
		row.ChargedVcpus, row.ActiveSandboxCount,
	}
	if len(dest) != len(vals) {
		return fmt.Errorf("scan arity: got %d dests, have %d values", len(dest), len(vals))
	}
	for i, v := range vals {
		switch d := dest[i].(type) {
		case *string:
			*d = v.(string)
		case *int32:
			*d = v.(int32)
		case *int64:
			*d = v.(int64)
		case *bool:
			*d = v.(bool)
		case *pgtype.Timestamptz:
			*d = v.(pgtype.Timestamptz)
		default:
			return fmt.Errorf("scan dest %d: unexpected type %T", i, dest[i])
		}
	}
	return nil
}

// capacityMock answers the three statements the capacity scheduler runs:
// the candidate list, the admission fence, and the reservation
// lifecycle. admit decides per host whether the fence accepts.
type capacityMock struct {
	rows  []db.ListCapacityCandidatesRow
	admit func(hostID string) bool

	listCalls     atomic.Int64
	attempted     []string
	materialized  atomic.Int64
	released      atomic.Int64
	retired       atomic.Int64
	defaultStatus string // "" = no GetHost answer configured
}

func (m *capacityMock) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	switch {
	case strings.Contains(sql, "-- name: MaterializeHostReservation"):
		m.materialized.Add(1)
	case strings.Contains(sql, "-- name: ReleaseHostReservation"):
		m.released.Add(1)
	case strings.Contains(sql, "-- name: RetireHostReservations"):
		m.retired.Add(1)
	default:
		return pgconn.CommandTag{}, fmt.Errorf("unexpected Exec: %s", sql)
	}
	return pgconn.CommandTag{}, nil
}

func (m *capacityMock) Query(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
	if !strings.Contains(sql, "-- name: ListCapacityCandidates") {
		return nil, fmt.Errorf("unexpected Query: %s", sql)
	}
	m.listCalls.Add(1)
	return &candidateRows{rows: m.rows}, nil
}

func (m *capacityMock) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	switch {
	case strings.Contains(sql, "-- name: ReserveHostCapacity"):
		// Located by type, not position: the admission statement's
		// parameter order is an artifact of the SQL, and a test that
		// pins it breaks on every harmless rewrite. host_id is its only
		// string parameter and sandbox_id its only uuid.
		var hostID string
		var id uuid.UUID
		for _, a := range args {
			switch v := a.(type) {
			case string:
				hostID = v
			case uuid.UUID:
				id = v
			}
		}
		m.attempted = append(m.attempted, hostID)
		if m.admit != nil && m.admit(hostID) {
			return schedulerScanRow{scan: func(dest ...any) error {
				*dest[0].(*uuid.UUID) = id
				return nil
			}}
		}
		// 0 rows: the fence rejected (limit hit, stale report, or a
		// racing replica took the headroom).
		return schedulerErrorRow{err: pgx.ErrNoRows}
	case strings.Contains(sql, "-- name: GetHost :one"):
		if m.defaultStatus == "" {
			return schedulerErrorRow{err: pgx.ErrNoRows}
		}
		return schedulerHostRow(args[0].(string), m.defaultStatus)
	}
	return schedulerErrorRow{err: fmt.Errorf("unexpected QueryRow: %s", sql)}
}

// candidate builds a pressure-capable row with a fresh report and no
// configured limits; tests override the fields they exercise.
func candidate(id string) db.ListCapacityCandidatesRow {
	return db.ListCapacityCandidatesRow{
		ID:                id,
		Region:            "region-a",
		CapacityMemoryMib: 64 * 1024,
		CapacityVcpus:     64,
		PressureCapable:   true,
		ReportedAt:        pgtype.Timestamptz{Time: time.Now(), Valid: true},
		MaxSandboxes:      100,
		NetSlotCeiling:    200,
	}
}

func newCapacityScheduler(m *capacityMock) *CapacityAware {
	return &CapacityAware{DB: db.New(m), DefaultHostID: "default", TTL: time.Minute}
}

func placeOnce(t *testing.T, s *CapacityAware) (Placement, error) {
	t.Helper()
	return s.PlaceSandbox(context.Background(), PlacementRequest{
		SandboxID: uuid.New(), MemoryMib: 512, Vcpus: 1,
	})
}

// A host that advertises capacity_pressure_v1 but has no fresh report is
// EXCLUDED, never placed on. This is the review's fail-closed rule: a
// broken publisher under a healthy heartbeat would otherwise take
// unbounded placements on counts the admission fence cannot see.
func TestCapacityStalePressureFailsClosed(t *testing.T) {
	stale := candidate("stale")
	stale.ReportedAt = pgtype.Timestamptz{
		Time:  time.Now().Add(-(PressureFreshnessSecs + 30) * time.Second),
		Valid: true,
	}
	missing := candidate("never-published")
	missing.ReportedAt = pgtype.Timestamptz{}

	for _, row := range []db.ListCapacityCandidatesRow{stale, missing} {
		m := &capacityMock{rows: []db.ListCapacityCandidatesRow{row}, admit: func(string) bool { return true }}
		s := newCapacityScheduler(m)
		if _, err := placeOnce(t, s); err == nil {
			t.Fatalf("%s: placement succeeded, want failure (fail closed)", row.ID)
		}
		if len(m.attempted) != 0 {
			t.Fatalf("%s: attempted admission on %v, want none", row.ID, m.attempted)
		}
	}
}

// A host that never advertises the capability is a legacy vmd: it keeps
// taking placements the old way (unfenced), which is what makes a mixed
// fleet safe to roll through.
func TestCapacityLegacyHostPlacedUnfenced(t *testing.T) {
	legacy := candidate("legacy")
	legacy.PressureCapable = false
	legacy.ReportedAt = pgtype.Timestamptz{}
	m := &capacityMock{rows: []db.ListCapacityCandidatesRow{legacy}}
	s := newCapacityScheduler(m)

	var obs PlacementObservation
	s.Observe = func(o PlacementObservation) { obs = o }

	p, err := placeOnce(t, s)
	if err != nil || p.HostID != "legacy" {
		t.Fatalf("got (%q, %v), want (legacy, nil)", p.HostID, err)
	}
	if len(m.attempted) != 0 {
		t.Fatalf("legacy placement ran the admission fence: %v", m.attempted)
	}
	if p.Confirm != nil || p.Abort != nil {
		t.Fatal("legacy placement returned reservation hooks; nothing was reserved")
	}
	if obs.Mode != "legacy" || obs.Result != "placed" {
		t.Fatalf("observation = %+v, want mode=legacy result=placed", obs)
	}
}

// Capable-but-stale hosts must not consume the retry budget or block
// overflow: a legacy host in the same set still takes the create.
func TestCapacityStaleFallsThroughToLegacyNotToStaleHost(t *testing.T) {
	stale := candidate("stale")
	stale.ReportedAt = pgtype.Timestamptz{
		Time:  time.Now().Add(-10 * time.Minute),
		Valid: true,
	}
	legacy := candidate("legacy")
	legacy.PressureCapable = false
	m := &capacityMock{rows: []db.ListCapacityCandidatesRow{stale, legacy}}
	s := newCapacityScheduler(m)

	p, err := placeOnce(t, s)
	if err != nil || p.HostID != "legacy" {
		t.Fatalf("got (%q, %v), want (legacy, nil)", p.HostID, err)
	}
}

// The happy path: a fresh capable host is admitted through the fence and
// comes back with both lifecycle hooks wired to the ledger row.
func TestCapacityPlacesAndWiresReservationHooks(t *testing.T) {
	m := &capacityMock{
		rows:  []db.ListCapacityCandidatesRow{candidate("h1")},
		admit: func(string) bool { return true },
	}
	s := newCapacityScheduler(m)
	var obs PlacementObservation
	s.Observe = func(o PlacementObservation) { obs = o }

	p, err := placeOnce(t, s)
	if err != nil || p.HostID != "h1" {
		t.Fatalf("got (%q, %v), want (h1, nil)", p.HostID, err)
	}
	if obs.Mode != "capacity" || obs.Result != "placed" || obs.Attempts != 1 {
		t.Fatalf("observation = %+v, want capacity/placed/1 attempt", obs)
	}
	p.Confirm(context.Background())
	if got := m.materialized.Load(); got != 1 {
		t.Fatalf("materialize calls = %d, want 1", got)
	}
	p.Abort(context.Background())
	if got := m.released.Load(); got != 1 {
		t.Fatalf("release calls = %d, want 1", got)
	}
}

// Rejections walk down the ranked list, and the walk is bounded: a burst
// against a saturated cell must not turn one create into an unbounded
// series of round trips.
func TestCapacityRetriesAreBounded(t *testing.T) {
	var rows []db.ListCapacityCandidatesRow
	for i := 0; i < 10; i++ {
		rows = append(rows, candidate(fmt.Sprintf("h%d", i)))
	}
	m := &capacityMock{rows: rows, admit: func(string) bool { return false }}
	s := newCapacityScheduler(m)
	var obs PlacementObservation
	s.Observe = func(o PlacementObservation) { obs = o }

	if _, err := placeOnce(t, s); err == nil {
		t.Fatal("placement succeeded with every host rejecting")
	}
	if len(m.attempted) != admissionMaxAttempts {
		t.Fatalf("attempts = %d, want %d", len(m.attempted), admissionMaxAttempts)
	}
	if obs.Result != "exhausted" || obs.Attempts != admissionMaxAttempts {
		t.Fatalf("observation = %+v, want exhausted with %d attempts", obs, admissionMaxAttempts)
	}
}

// A host the cached view already knows is full costs no round trip: the
// fence would reject it, and the retry budget is better spent elsewhere.
func TestCapacitySkipsObviouslyFullHosts(t *testing.T) {
	full := candidate("full")
	full.MaxSandboxes = 10
	full.RunningSandboxes = 10
	room := candidate("room")

	m := &capacityMock{
		rows:  []db.ListCapacityCandidatesRow{full, room},
		admit: func(string) bool { return true },
	}
	s := newCapacityScheduler(m)
	p, err := placeOnce(t, s)
	if err != nil || p.HostID != "room" {
		t.Fatalf("got (%q, %v), want (room, nil)", p.HostID, err)
	}
	for _, id := range m.attempted {
		if id == "full" {
			t.Fatalf("attempted admission on a host the cache knew was full: %v", m.attempted)
		}
	}
}

// Live reservations count toward the limit in the cached view too, so a
// burst stops targeting a host once its charged reservations fill it —
// without waiting for the next pressure report to reflect them.
func TestCapacityChargedReservationsCountTowardCachedLimit(t *testing.T) {
	row := candidate("h1")
	row.MaxSandboxes = 10
	row.RunningSandboxes = 8
	row.ChargedCount = 2 // 8 + 2 + 1 > 10

	m := &capacityMock{rows: []db.ListCapacityCandidatesRow{row}, admit: func(string) bool { return true }}
	s := newCapacityScheduler(m)
	var obs PlacementObservation
	s.Observe = func(o PlacementObservation) { obs = o }

	if _, err := placeOnce(t, s); err == nil {
		t.Fatal("placed onto a host whose limit was filled by live reservations")
	}
	if len(m.attempted) != 0 {
		t.Fatalf("attempted admission anyway: %v", m.attempted)
	}
	if obs.Reason != "sandbox_limit" {
		t.Fatalf("reason = %q, want sandbox_limit", obs.Reason)
	}
}

// Ranking picks by dominant pressure across resources — here the
// least-loaded-by-count host is the WORST choice because its memory is
// nearly spent, which is exactly what the legacy count-only scheduler
// could not see.
func TestCapacityRanksByDominantResource(t *testing.T) {
	memHeavy := candidate("mem-heavy")
	memHeavy.RunningSandboxes = 1
	memHeavy.AllocatedMemoryMib = 62 * 1024 // of 64 GiB

	balanced := candidate("balanced")
	balanced.RunningSandboxes = 40
	balanced.AllocatedMemoryMib = 8 * 1024

	m := &capacityMock{
		rows:  []db.ListCapacityCandidatesRow{memHeavy, balanced},
		admit: func(string) bool { return true },
	}
	s := newCapacityScheduler(m)
	p, err := placeOnce(t, s)
	if err != nil || p.HostID != "balanced" {
		t.Fatalf("got (%q, %v), want (balanced, nil) — memory pressure must outrank sandbox count", p.HostID, err)
	}
}

// Comparable hosts are chosen at random, never in a fixed order: a fixed
// order would point every replica at one host's reservation row and
// serialize the fleet's creates behind it.
func TestCapacityRandomizesAmongComparableHosts(t *testing.T) {
	rows := []db.ListCapacityCandidatesRow{candidate("a"), candidate("b"), candidate("c")}
	seen := map[string]int{}
	for i := 0; i < 200; i++ {
		m := &capacityMock{rows: rows, admit: func(string) bool { return true }}
		s := newCapacityScheduler(m)
		p, err := placeOnce(t, s)
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		seen[p.HostID]++
	}
	if len(seen) != 3 {
		t.Fatalf("only %d of 3 comparable hosts were ever chosen: %v", len(seen), seen)
	}
	for id, n := range seen {
		if n < 20 {
			t.Fatalf("host %s chosen %d/200 times; distribution is not uniform: %v", id, n, seen)
		}
	}
}

// Warm slots break ties among comparable hosts, but must never pull a
// genuinely more-loaded host ahead: the bonus is smaller than the
// tolerance band by construction.
func TestCapacityWarmSlotsBreakTiesButDoNotOutrankPressure(t *testing.T) {
	cold := candidate("cold")
	warm := candidate("warm")
	warm.WarmNetSlots = 8
	warm.UsedNetSlots = 0

	// Tie on every other axis: the warm host wins.
	m := &capacityMock{
		rows:  []db.ListCapacityCandidatesRow{cold, warm},
		admit: func(string) bool { return true },
	}
	s := newCapacityScheduler(m)
	if p, err := placeOnce(t, s); err != nil || p.HostID != "warm" {
		t.Fatalf("tie: got (%q, %v), want warm", p.HostID, err)
	}

	// Now the warm host is heavily loaded: warmth must not rescue it.
	loadedWarm := warm
	loadedWarm.ID = "loaded-warm"
	loadedWarm.RunningSandboxes = 90 // of MaxSandboxes 100
	m = &capacityMock{
		rows:  []db.ListCapacityCandidatesRow{cold, loadedWarm},
		admit: func(string) bool { return true },
	}
	s = newCapacityScheduler(m)
	if p, err := placeOnce(t, s); err != nil || p.HostID != "cold" {
		t.Fatalf("loaded: got (%q, %v), want cold — warm slots must not outvote real pressure", p.HostID, err)
	}
}

// AllowedHosts is the template-locality hook: placement is restricted to
// the named hosts, and a constraint that matches nothing FAILS rather
// than silently placing elsewhere — dispatching a template restore to a
// host without the artifacts would fail the boot on the host instead.
func TestCapacityHonorsAllowedHostsConstraint(t *testing.T) {
	m := &capacityMock{
		rows:  []db.ListCapacityCandidatesRow{candidate("h1"), candidate("h2"), candidate("h3")},
		admit: func(string) bool { return true },
	}
	s := newCapacityScheduler(m)
	for i := 0; i < 20; i++ {
		p, err := s.PlaceSandbox(context.Background(), PlacementRequest{
			SandboxID: uuid.New(), MemoryMib: 512, Vcpus: 1,
			AllowedHosts: []string{"h2"},
		})
		if err != nil || p.HostID != "h2" {
			t.Fatalf("iteration %d: got (%q, %v), want h2", i, p.HostID, err)
		}
	}

	// A constraint naming a host that is not a candidate must not fall
	// back to the default host.
	s = newCapacityScheduler(&capacityMock{
		rows:  []db.ListCapacityCandidatesRow{candidate("h1")},
		admit: func(string) bool { return true },
	})
	if p, err := s.PlaceSandbox(context.Background(), PlacementRequest{
		SandboxID: uuid.New(), MemoryMib: 512, Vcpus: 1,
		AllowedHosts: []string{"absent-host"},
	}); err == nil {
		t.Fatalf("unsatisfiable constraint placed on %q, want an error", p.HostID)
	}
}

// Same-region hosts win when any exist; a remote host still beats a
// failed create when the local region has nothing eligible.
func TestCapacityPrefersSameRegion(t *testing.T) {
	local := candidate("local")
	local.Region = "region-a"
	remote := candidate("remote")
	remote.Region = "region-b"
	remote.RunningSandboxes = 0
	local.RunningSandboxes = 50 // more loaded, still preferred: region wins

	m := &capacityMock{
		rows:  []db.ListCapacityCandidatesRow{remote, local},
		admit: func(string) bool { return true },
	}
	s := newCapacityScheduler(m)
	s.Region = "region-a"
	if p, err := placeOnce(t, s); err != nil || p.HostID != "local" {
		t.Fatalf("got (%q, %v), want local", p.HostID, err)
	}

	// Region with no candidates: the remote host is still placed on.
	m = &capacityMock{rows: []db.ListCapacityCandidatesRow{remote}, admit: func(string) bool { return true }}
	s = newCapacityScheduler(m)
	s.Region = "region-a"
	if p, err := placeOnce(t, s); err != nil || p.HostID != "remote" {
		t.Fatalf("got (%q, %v), want remote", p.HostID, err)
	}
}

// The candidate set is cached like the legacy scheduler's: creates cost
// the admission statement, never a fleet-wide candidate query.
func TestCapacityCandidateSetIsCached(t *testing.T) {
	m := &capacityMock{
		rows:  []db.ListCapacityCandidatesRow{candidate("h1")},
		admit: func(string) bool { return true },
	}
	s := newCapacityScheduler(m)
	for i := 0; i < 25; i++ {
		if _, err := placeOnce(t, s); err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
	}
	if got := m.listCalls.Load(); got != 1 {
		t.Fatalf("candidate queries = %d, want 1 (per fill, not per create)", got)
	}
	if len(m.attempted) != 25 {
		t.Fatalf("admission statements = %d, want 25 (one per create)", len(m.attempted))
	}
}

// Empty candidate set keeps the legacy bootstrap semantics: an
// unpopulated host table still creates against the default host, and a
// non-active default row still refuses.
func TestCapacityBootstrapFallback(t *testing.T) {
	m := &capacityMock{} // no candidates, GetHost answers ErrNoRows
	s := newCapacityScheduler(m)
	var obs PlacementObservation
	s.Observe = func(o PlacementObservation) { obs = o }
	if p, err := placeOnce(t, s); err != nil || p.HostID != "default" {
		t.Fatalf("bootstrap: got (%q, %v), want (default, nil)", p.HostID, err)
	}
	if obs.Mode != "fallback" {
		t.Fatalf("observation mode = %q, want fallback", obs.Mode)
	}

	for _, status := range []string{"provisioning", "draining", "unhealthy"} {
		s := newCapacityScheduler(&capacityMock{defaultStatus: status})
		if p, err := placeOnce(t, s); err == nil {
			t.Fatalf("default host %s: placed on %q, want an error", status, p.HostID)
		}
	}
}

// A database failure during admission fails the placement rather than
// silently placing unfenced — the create's own INSERT is about to hit
// the same database anyway.
func TestCapacityAdmissionErrorFailsPlacement(t *testing.T) {
	m := &errorAdmissionMock{rows: []db.ListCapacityCandidatesRow{candidate("h1")}}
	s := newCapacityScheduler(nil)
	s.DB = db.New(m)
	var obs PlacementObservation
	s.Observe = func(o PlacementObservation) { obs = o }
	if p, err := placeOnce(t, s); err == nil {
		t.Fatalf("placed on %q despite an admission error", p.HostID)
	}
	if obs.Result != "error" {
		t.Fatalf("observation result = %q, want error", obs.Result)
	}
}

type errorAdmissionMock struct {
	rows []db.ListCapacityCandidatesRow
}

func (m *errorAdmissionMock) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, fmt.Errorf("unexpected Exec")
}
func (m *errorAdmissionMock) Query(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
	if !strings.Contains(sql, "-- name: ListCapacityCandidates") {
		return nil, fmt.Errorf("unexpected Query: %s", sql)
	}
	return &candidateRows{rows: m.rows}, nil
}
func (m *errorAdmissionMock) QueryRow(context.Context, string, ...any) pgx.Row {
	return schedulerErrorRow{err: fmt.Errorf("connection reset")}
}

// The legacy scheduler keeps its exact behavior through the placement
// interface: same host choice, and no reservation hooks (nothing was
// fenced, so nothing may be confirmed or released).
func TestLeastLoadedPlaceSandboxHasNoReservationHooks(t *testing.T) {
	mock := &fallbackProbe{row: schedulerErrorRow{err: pgx.ErrNoRows}}
	s := &LeastLoaded{DB: db.New(mock), DefaultHostID: "default"}
	p, err := s.PlaceSandbox(context.Background(), PlacementRequest{SandboxID: uuid.New()})
	if err != nil || p.HostID != "default" {
		t.Fatalf("got (%q, %v), want (default, nil)", p.HostID, err)
	}
	if p.Confirm != nil || p.Abort != nil {
		t.Fatal("legacy placement exposed reservation hooks")
	}
}

// A host reporting unsized VMs is under-described: its allocation
// columns are a known undercount, so it looks emptier than it is.
// Ranking must never let that shortfall win against a host whose
// numbers are complete — otherwise the scheduler systematically prefers
// exactly the hosts whose true load it cannot see.
func TestCapacityPrefersFullyDescribedHosts(t *testing.T) {
	// The under-described host reports almost no memory used, which
	// would make it the obvious winner on the numbers alone.
	unsized := candidate("under-described")
	unsized.AllocatedMemoryMib = 512
	unsized.UnknownAllocationVms = 3

	described := candidate("described")
	described.AllocatedMemoryMib = 32 * 1024 // genuinely half full

	for i := 0; i < 25; i++ {
		m := &capacityMock{
			rows:  []db.ListCapacityCandidatesRow{unsized, described},
			admit: func(string) bool { return true },
		}
		s := newCapacityScheduler(m)
		p, err := placeOnce(t, s)
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		if p.HostID != "described" {
			t.Fatalf("placed on the under-described host; its allocation is an undercount, not free capacity")
		}
	}
}

// Under-described hosts stay USABLE — they are ordered behind, not
// excluded. Every host carries unsized VMs until its pre-declaration
// sandboxes cycle out, so excluding them would empty the candidate set
// the day this is first enabled.
func TestCapacityStillPlacesWhenEveryHostIsUnderDescribed(t *testing.T) {
	a := candidate("a")
	a.UnknownAllocationVms = 2
	b := candidate("b")
	b.UnknownAllocationVms = 5

	seen := map[string]int{}
	for i := 0; i < 40; i++ {
		m := &capacityMock{
			rows:  []db.ListCapacityCandidatesRow{a, b},
			admit: func(string) bool { return true },
		}
		s := newCapacityScheduler(m)
		p, err := placeOnce(t, s)
		if err != nil {
			t.Fatalf("iteration %d: placement failed with only under-described hosts: %v", i, err)
		}
		seen[p.HostID]++
	}
	if len(seen) != 2 {
		t.Fatalf("only %v was ever chosen; under-described hosts must stay in rotation", seen)
	}
}

// The tiering must not override a hard limit: a fully-described host
// that is genuinely full still loses to an under-described one with
// room, because exhausted capacity is a fact and an undercount is only
// an uncertainty.
func TestCapacityFallsBackToUnderDescribedWhenDescribedIsFull(t *testing.T) {
	full := candidate("described-full")
	full.MaxSandboxes = 10
	full.RunningSandboxes = 10

	spare := candidate("under-described-spare")
	spare.UnknownAllocationVms = 1

	m := &capacityMock{
		rows:  []db.ListCapacityCandidatesRow{full, spare},
		admit: func(string) bool { return true },
	}
	s := newCapacityScheduler(m)
	p, err := placeOnce(t, s)
	if err != nil || p.HostID != "under-described-spare" {
		t.Fatalf("got (%q, %v), want the under-described host with room", p.HostID, err)
	}
}
