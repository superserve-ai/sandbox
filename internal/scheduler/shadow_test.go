package scheduler

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

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

// rankerMock answers the candidate query and counts how often it runs.
type rankerMock struct {
	mu       sync.Mutex
	rows     []db.ListCapacityCandidatesRow
	queries  int
	block    chan struct{} // when non-nil, the query waits on it
	failWith error
}

func (m *rankerMock) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, fmt.Errorf("unexpected Exec")
}

func (m *rankerMock) Query(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
	if !strings.Contains(sql, "-- name: ListCapacityCandidates") {
		return nil, fmt.Errorf("unexpected Query: %s", sql)
	}
	m.mu.Lock()
	m.queries++
	block, failWith, rows := m.block, m.failWith, m.rows
	m.mu.Unlock()
	if block != nil {
		<-block
	}
	if failWith != nil {
		return nil, failWith
	}
	return &candidateRows{rows: rows}, nil
}

func (m *rankerMock) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	return errRow{err: fmt.Errorf("unexpected QueryRow: %s", sql)}
}

func (m *rankerMock) queryCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.queries
}

type errRow struct{ err error }

func (r errRow) Scan(...any) error { return r.err }

// candidate builds a pressure-capable host with a fresh, complete report.
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

func newShadow(t *testing.T, m *rankerMock) (*ShadowEvaluator, chan ShadowObservation) {
	t.Helper()
	// Most tests exercise behavior, not pacing, so the rate limit is
	// removed for them; TestShadowRateLimitsSamples covers it directly.
	prev := shadowSampleInterval
	shadowSampleInterval = 0
	t.Cleanup(func() { shadowSampleInterval = prev })

	obs := make(chan ShadowObservation, 64)
	s := NewShadowEvaluator(&CapacityRanker{DB: db.New(m)}, func(o ShadowObservation) { obs <- o })
	return s, obs
}

// The contract that makes this safe to ship: offering a sample costs a
// create nothing it can wait on. Proven against a ranker whose query is
// wedged — the worker is stuck inside it, the queue fills, and Offer
// must still return promptly rather than block behind either.
func TestShadowOfferNeverBlocksARequest(t *testing.T) {
	block := make(chan struct{})
	m := &rankerMock{rows: []db.ListCapacityCandidatesRow{candidate("h1")}, block: block}
	s, _ := newShadow(t, m)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	// Far more than the queue holds, against a wedged evaluator.
	done := make(chan time.Duration)
	go func() {
		started := time.Now()
		for i := 0; i < shadowQueueDepth*20; i++ {
			s.Offer([]string{"preview_ports_v1"}, 512, 1, "h1")
		}
		done <- time.Since(started)
	}()

	select {
	case elapsed := <-done:
		// Generous: the point is "does not wait on the worker", not a
		// benchmark. A blocking Offer would never finish at all here.
		if elapsed > 2*time.Second {
			t.Fatalf("offering %d samples took %v; the request path is waiting on the evaluator",
				shadowQueueDepth*20, elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Offer blocked behind a wedged evaluator; a create would have blocked with it")
	}
	close(block)
}

// Dropping under load is the design, not a defect: the queue is the
// sampler. What must never happen is unbounded growth or backpressure.
func TestShadowDropsSamplesWhenSaturated(t *testing.T) {
	block := make(chan struct{})
	m := &rankerMock{rows: []db.ListCapacityCandidatesRow{candidate("h1")}, block: block}
	s, _ := newShadow(t, m)

	for i := 0; i < shadowQueueDepth*5; i++ {
		s.Offer(nil, 512, 1, "h1")
	}
	if got := len(s.samples); got > shadowQueueDepth {
		t.Fatalf("queue holds %d samples, cap is %d; it must drop rather than grow", got, shadowQueueDepth)
	}
	close(block)
}

// Shadow evaluation must report whether ranking agrees with the live
// scheduler — that comparison is the entire reason to run it.
func TestShadowReportsAgreementWithLivePlacement(t *testing.T) {
	loaded := candidate("loaded")
	loaded.RunningSandboxes = 90 // clearly the worse choice
	idle := candidate("idle")

	m := &rankerMock{rows: []db.ListCapacityCandidatesRow{loaded, idle}}
	s, obs := newShadow(t, m)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	// The live scheduler picked the loaded host; ranking prefers idle.
	s.Offer(nil, 512, 1, "loaded")
	o := awaitObservation(t, obs)
	if o.Result != "ranked" || o.Agreement != "out_of_band" {
		t.Fatalf("observation = %+v, want ranked/out_of_band", o)
	}

	// A choice inside the comparable set is agreement, even though the
	// ranking's own first pick is drawn from that set at random.
	s.Offer(nil, 512, 1, "idle")
	o = awaitObservation(t, obs)
	if o.Agreement != "in_band" {
		t.Fatalf("agreement = %q, want in_band", o.Agreement)
	}
}

// Fleet composition is what tells an operator whether enforcement is
// even viable yet: ranking on a fleet that is mostly legacy or stale
// would be ranking on numbers that barely exist.
func TestShadowReportsFleetComposition(t *testing.T) {
	fresh := candidate("fresh")

	unsized := candidate("unsized")
	unsized.UnknownAllocationVms = 2

	stale := candidate("stale")
	stale.ReportedAt = pgtype.Timestamptz{Time: time.Now().Add(-10 * time.Minute), Valid: true}

	legacy := candidate("legacy")
	legacy.PressureCapable = false
	legacy.ReportedAt = pgtype.Timestamptz{}

	m := &rankerMock{rows: []db.ListCapacityCandidatesRow{fresh, unsized, stale, legacy}}
	s, obs := newShadow(t, m)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	s.Offer(nil, 512, 1, "fresh")
	o := awaitObservation(t, obs)
	if o.Described != 1 || o.UnderDescribed != 1 || o.Stale != 1 || o.Legacy != 1 {
		t.Fatalf("composition = %+v, want one of each", o)
	}
}

// A failed refresh is reported, never propagated: nothing depends on
// ranking, so a database blip must not become anything a create sees.
func TestShadowReportsRefreshFailure(t *testing.T) {
	m := &rankerMock{failWith: fmt.Errorf("connection reset")}
	s, obs := newShadow(t, m)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	s.Offer(nil, 512, 1, "h1")
	if o := awaitObservation(t, obs); o.Result != "error" {
		t.Fatalf("result = %q, want error", o.Result)
	}
}

// The candidate set is cached: shadow evaluation must not put a query on
// the database per create, even though it runs off the request path.
func TestShadowCachesCandidates(t *testing.T) {
	m := &rankerMock{rows: []db.ListCapacityCandidatesRow{candidate("h1")}}
	s, obs := newShadow(t, m)
	s.Ranker.TTL = time.Minute
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	for i := 0; i < 20; i++ {
		s.Offer(nil, 512, 1, "h1")
		awaitObservation(t, obs)
	}
	if got := m.queryCount(); got != 1 {
		t.Fatalf("candidate queries = %d, want 1 for 20 samples", got)
	}
}

func awaitObservation(t *testing.T, obs chan ShadowObservation) ShadowObservation {
	t.Helper()
	select {
	case o := <-obs:
		return o
	case <-time.After(3 * time.Second):
		t.Fatal("no shadow observation emitted")
		return ShadowObservation{}
	}
}

func rank(t *testing.T, rows []db.ListCapacityCandidatesRow, req RankRequest) RankResult {
	t.Helper()
	r := &CapacityRanker{DB: db.New(&rankerMock{rows: rows})}
	res, err := r.Rank(context.Background(), req)
	if err != nil {
		t.Fatalf("rank: %v", err)
	}
	return res
}

// Ranking is by DOMINANT resource, so the host with fewest sandboxes is
// not automatically best — the whole reason to rank on pressure rather
// than a count.
func TestRankerOrdersByDominantResource(t *testing.T) {
	memHeavy := candidate("mem-heavy")
	memHeavy.RunningSandboxes = 1
	memHeavy.AllocatedMemoryMib = 62 * 1024 // of 64 GiB

	balanced := candidate("balanced")
	balanced.RunningSandboxes = 40
	balanced.AllocatedMemoryMib = 8 * 1024

	res := rank(t, []db.ListCapacityCandidatesRow{memHeavy, balanced}, RankRequest{MemoryMib: 512, Vcpus: 1})
	if len(res.Order) == 0 || res.Order[0] != "balanced" {
		t.Fatalf("order = %v, want balanced first: memory pressure must outrank sandbox count", res.Order)
	}
}

// A host that cannot size its own VMs reports an allocation undercount,
// so it must never outrank a host whose numbers are complete.
func TestRankerPrefersFullyDescribedHosts(t *testing.T) {
	unsized := candidate("under-described")
	unsized.AllocatedMemoryMib = 512 // looks nearly empty
	unsized.UnknownAllocationVms = 3

	described := candidate("described")
	described.AllocatedMemoryMib = 32 * 1024

	for i := 0; i < 20; i++ {
		res := rank(t, []db.ListCapacityCandidatesRow{unsized, described}, RankRequest{MemoryMib: 512, Vcpus: 1})
		if len(res.Order) == 0 || res.Order[0] != "described" {
			t.Fatalf("order = %v; an undercount is not free capacity", res.Order)
		}
	}
	res := rank(t, []db.ListCapacityCandidatesRow{unsized, described}, RankRequest{MemoryMib: 512, Vcpus: 1})
	if res.Described != 1 || res.UnderDescribed != 1 {
		t.Fatalf("composition = %+v, want one described and one under-described", res)
	}
}

// Stale and legacy hosts are excluded from the ranking but counted, so
// the shadow can report how much of the fleet is describable.
func TestRankerExcludesStaleAndLegacyButCountsThem(t *testing.T) {
	fresh := candidate("fresh")

	stale := candidate("stale")
	stale.ReportedAt = pgtype.Timestamptz{Time: time.Now().Add(-(PressureFreshnessSecs + 30) * time.Second), Valid: true}

	legacy := candidate("legacy")
	legacy.PressureCapable = false

	res := rank(t, []db.ListCapacityCandidatesRow{fresh, stale, legacy}, RankRequest{MemoryMib: 512, Vcpus: 1})
	if len(res.Order) != 1 || res.Order[0] != "fresh" {
		t.Fatalf("order = %v, want only the fresh host", res.Order)
	}
	if res.Stale != 1 || res.Legacy != 1 {
		t.Fatalf("counts = %+v, want one stale and one legacy", res)
	}
}

// Hosts already at their operator limit are dropped: ranking them would
// propose a host that cannot take the sandbox.
func TestRankerDropsHostsAtTheirLimit(t *testing.T) {
	full := candidate("full")
	full.MaxSandboxes = 10
	full.RunningSandboxes = 10
	room := candidate("room")

	res := rank(t, []db.ListCapacityCandidatesRow{full, room}, RankRequest{MemoryMib: 512, Vcpus: 1})
	if len(res.Order) != 1 || res.Order[0] != "room" {
		t.Fatalf("order = %v, want only the host with room", res.Order)
	}
}

// Comparable hosts are ordered randomly. That is load-bearing for the
// enforcing design this prepares: a deterministic best-first order would
// point every replica at the same host.
func TestRankerRandomizesAmongComparableHosts(t *testing.T) {
	rows := []db.ListCapacityCandidatesRow{candidate("a"), candidate("b"), candidate("c")}
	firsts := map[string]int{}
	for i := 0; i < 200; i++ {
		res := rank(t, rows, RankRequest{MemoryMib: 512, Vcpus: 1})
		if len(res.Order) == 0 {
			t.Fatal("nothing ranked")
		}
		firsts[res.Order[0]]++
	}
	if len(firsts) != 3 {
		t.Fatalf("only %v ever ranked first; comparable hosts must not have a fixed order", firsts)
	}
}

// The template-locality hook: ranking honors an explicit host set.
func TestRankerHonorsAllowedHosts(t *testing.T) {
	rows := []db.ListCapacityCandidatesRow{candidate("h1"), candidate("h2"), candidate("h3")}
	res := rank(t, rows, RankRequest{MemoryMib: 512, Vcpus: 1, AllowedHosts: []string{"h2"}})
	if len(res.Order) != 1 || res.Order[0] != "h2" {
		t.Fatalf("order = %v, want only h2", res.Order)
	}
}

// Agreement must be judged against the whole comparable band, not the
// ranking's first choice. With equally good hosts that first choice is a
// random draw, so comparing against it would report disagreement for
// (N-1)/N of perfectly good placements — measuring the shuffle instead
// of the placement.
func TestShadowAgreementIsBandMembershipNotTheShuffle(t *testing.T) {
	rows := []db.ListCapacityCandidatesRow{candidate("a"), candidate("b"), candidate("c")}
	m := &rankerMock{rows: rows}
	s, obs := newShadow(t, m)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	// Every host is equally good, so every live choice must read as
	// agreement — every time, not one third of the time.
	for i := 0; i < 30; i++ {
		for _, host := range []string{"a", "b", "c"} {
			s.Offer(nil, 512, 1, host)
			if o := awaitObservation(t, obs); o.Agreement != "in_band" {
				t.Fatalf("host %s reported %q; comparable hosts must all count as agreement", host, o.Agreement)
			}
		}
	}
}

// The queue alone is not a rate limiter: while the worker keeps up it
// accepts everything, and each sample costs a fleet-sized ranking pass.
func TestShadowRateLimitsSamples(t *testing.T) {
	m := &rankerMock{rows: []db.ListCapacityCandidatesRow{candidate("h1")}}
	s, obs := newShadow(t, m)
	shadowSampleInterval = 50 * time.Millisecond // restored by newShadow's cleanup

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	for i := 0; i < 500; i++ {
		s.Offer(nil, 512, 1, "h1")
	}
	// One sample admitted for the whole burst; the rest are refused
	// before anything is built.
	awaitObservation(t, obs)
	select {
	case o := <-obs:
		t.Fatalf("a second sample was admitted within one interval: %+v", o)
	case <-time.After(20 * time.Millisecond):
	}
}

// The refusal path is the common one, so it must not allocate: building
// a message only to drop it would cost every create a heap allocation.
func TestShadowOfferDoesNotAllocateWhenRefused(t *testing.T) {
	m := &rankerMock{rows: []db.ListCapacityCandidatesRow{candidate("h1")}}
	s, _ := newShadow(t, m)
	shadowSampleInterval = time.Hour // admit the first, refuse the rest

	caps := []string{"preview_ports_v1"}
	s.Offer(caps, 512, 1, "h1") // consumes the one allowed sample

	allocs := testing.AllocsPerRun(200, func() {
		s.Offer(caps, 512, 1, "h1")
	})
	if allocs > 0 {
		t.Fatalf("refused offer allocates %.1f times per call; it must decide before building the sample", allocs)
	}
}

// Region preference must not hide viable hosts: filtering by region
// before dropping full hosts lets one full local host mask every remote
// host with room, leaving nothing rankable.
func TestRankerFallsBackToRemoteWhenLocalIsFull(t *testing.T) {
	local := candidate("local-full")
	local.Region = "region-a"
	local.MaxSandboxes = 10
	local.RunningSandboxes = 10

	remote := candidate("remote-room")
	remote.Region = "region-b"

	r := &CapacityRanker{DB: db.New(&rankerMock{rows: []db.ListCapacityCandidatesRow{local, remote}}), Region: "region-a"}
	res, err := r.Rank(context.Background(), RankRequest{MemoryMib: 512, Vcpus: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Order) != 1 || res.Order[0] != "remote-room" {
		t.Fatalf("order = %v; a full local host must not hide a viable remote one", res.Order)
	}
}

// ...while a viable local host still wins over a remote one.
func TestRankerStillPrefersViableLocalHosts(t *testing.T) {
	local := candidate("local")
	local.Region = "region-a"
	local.RunningSandboxes = 50 // more loaded, still preferred

	remote := candidate("remote")
	remote.Region = "region-b"

	r := &CapacityRanker{DB: db.New(&rankerMock{rows: []db.ListCapacityCandidatesRow{local, remote}}), Region: "region-a"}
	res, err := r.Rank(context.Background(), RankRequest{MemoryMib: 512, Vcpus: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Order) != 1 || res.Order[0] != "local" {
		t.Fatalf("order = %v, want the local host", res.Order)
	}
}
