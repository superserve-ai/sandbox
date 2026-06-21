package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

// ms is a tiny helper to make duration literals readable in tests.
func ms(n int) time.Duration { return time.Duration(n) * time.Millisecond }

func durs(vals ...int) []time.Duration {
	out := make([]time.Duration, len(vals))
	for i, v := range vals {
		out[i] = ms(v)
	}
	return out
}

func TestSummarize_KnownInputs(t *testing.T) {
	// 1..10 ms. Nearest-rank on a 0-based sorted slice of n=10:
	//   p50: ceil(0.50*10)-1 = 5-1 = 4 -> sorted[4] = 5ms
	//   p90: ceil(0.90*10)-1 = 9-1 = 8 -> sorted[8] = 9ms
	//   p99: ceil(0.99*10)-1 = 10-1 = 9 -> sorted[9] = 10ms
	//   max: 10ms
	got := summarize(durs(1, 2, 3, 4, 5, 6, 7, 8, 9, 10))
	want := Percentiles{N: 10, P50: ms(5), P90: ms(9), P99: ms(10), Max: ms(10)}
	if got != want {
		t.Fatalf("summarize(1..10) = %+v, want %+v", got, want)
	}
}

func TestSummarize_OrderingNotAssumed(t *testing.T) {
	// Same multiset as above but shuffled — result must be identical, and the
	// input slice must not be mutated.
	in := durs(7, 2, 10, 4, 1, 9, 3, 8, 5, 6)
	inCopy := make([]time.Duration, len(in))
	copy(inCopy, in)

	got := summarize(in)
	want := Percentiles{N: 10, P50: ms(5), P90: ms(9), P99: ms(10), Max: ms(10)}
	if got != want {
		t.Fatalf("summarize(shuffled 1..10) = %+v, want %+v", got, want)
	}
	for i := range in {
		if in[i] != inCopy[i] {
			t.Fatalf("summarize mutated its input at index %d: got %v want %v", i, in[i], inCopy[i])
		}
	}
}

func TestSummarize_SingleSample(t *testing.T) {
	got := summarize(durs(42))
	want := Percentiles{N: 1, P50: ms(42), P90: ms(42), P99: ms(42), Max: ms(42)}
	if got != want {
		t.Fatalf("summarize(single) = %+v, want %+v", got, want)
	}
}

func TestSummarize_Empty(t *testing.T) {
	got := summarize(nil)
	if got != (Percentiles{}) {
		t.Fatalf("summarize(nil) = %+v, want zero value", got)
	}
	got = summarize([]time.Duration{})
	if got != (Percentiles{}) {
		t.Fatalf("summarize(empty) = %+v, want zero value", got)
	}
}

func TestNearestRank_HundredSamples(t *testing.T) {
	// 1..100 ms. With n=100, nearest-rank p-th = sorted[ceil(p/100*100)-1] = sorted[p-1].
	sorted := durs(rangeInts(1, 100)...)
	cases := []struct {
		p    float64
		want time.Duration
	}{
		{50, ms(50)}, // ceil(50)-1 = 49 -> 50ms
		{90, ms(90)},
		{99, ms(99)},
		{100, ms(100)},
		{0, ms(1)},   // clamps to first
		{1, ms(1)},   // ceil(1)-1 = 0 -> 1ms
		{49, ms(49)}, // ceil(49)-1 = 48 -> 49ms
	}
	for _, c := range cases {
		if got := nearestRank(sorted, c.p); got != c.want {
			t.Errorf("nearestRank(1..100, p=%g) = %v, want %v", c.p, got, c.want)
		}
	}
}

func TestNearestRank_EdgeBounds(t *testing.T) {
	sorted := durs(10, 20, 30)
	if got := nearestRank(sorted, -5); got != ms(10) {
		t.Errorf("p<0 should clamp to min: got %v", got)
	}
	if got := nearestRank(sorted, 150); got != ms(30) {
		t.Errorf("p>100 should clamp to max: got %v", got)
	}
	if got := nearestRank(nil, 50); got != 0 {
		t.Errorf("empty should be 0: got %v", got)
	}
}

func rangeInts(lo, hi int) []int {
	out := make([]int, 0, hi-lo+1)
	for i := lo; i <= hi; i++ {
		out = append(out, i)
	}
	return out
}

// -----------------------------------------------------------------------------
// Matrix expansion
// -----------------------------------------------------------------------------

func TestMatrixExpand_Count(t *testing.T) {
	m := Matrix{
		Tiers:       []Tier{Tier1, Tier2, Tier3},
		MemMiB:      []int{512, 2048, 8192},
		WorkingMiB:  []int{128, 512, 1024},
		Cache:       []CacheState{CacheWarm, CacheCold},
		Contentions: []int{1, 8, 32},
	}
	cells := m.Expand()
	want := 3 * 3 * 3 * 2 * 3 // 162
	if len(cells) != want {
		t.Fatalf("Expand() count = %d, want %d", len(cells), want)
	}
}

func TestMatrixExpand_OrderAndFirstLast(t *testing.T) {
	m := Matrix{
		Tiers:       []Tier{Tier1, Tier2},
		MemMiB:      []int{512, 2048},
		WorkingMiB:  []int{128},
		Cache:       []CacheState{CacheWarm, CacheCold},
		Contentions: []int{1, 8},
	}
	cells := m.Expand()
	if len(cells) != 2*2*1*2*2 {
		t.Fatalf("unexpected count %d", len(cells))
	}
	// Outermost axis is tier, innermost is contention.
	first := Cell{Tier: Tier1, MemMiB: 512, WorkingMiB: 128, Cache: CacheWarm, Contention: 1}
	if cells[0] != first {
		t.Errorf("first cell = %+v, want %+v", cells[0], first)
	}
	last := Cell{Tier: Tier2, MemMiB: 2048, WorkingMiB: 128, Cache: CacheCold, Contention: 8}
	if cells[len(cells)-1] != last {
		t.Errorf("last cell = %+v, want %+v", cells[len(cells)-1], last)
	}
	// Innermost axis (contention) changes fastest between cells[0] and cells[1].
	if cells[1].Contention != 8 || cells[1].Tier != Tier1 || cells[1].Cache != CacheWarm {
		t.Errorf("cells[1] should advance contention only: got %+v", cells[1])
	}
}

func TestParseMatrixFlags_OK(t *testing.T) {
	m, err := parseMatrixFlags("1,2,3", "512,2048", "128 , 512", "warm,cold", "1,32")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(m.Tiers) != 3 || m.Tiers[2] != Tier3 {
		t.Errorf("tiers parsed wrong: %+v", m.Tiers)
	}
	if len(m.MemMiB) != 2 || m.MemMiB[1] != 2048 {
		t.Errorf("mem parsed wrong: %+v", m.MemMiB)
	}
	if len(m.WorkingMiB) != 2 || m.WorkingMiB[0] != 128 || m.WorkingMiB[1] != 512 {
		t.Errorf("ws parsed wrong (whitespace?): %+v", m.WorkingMiB)
	}
	if len(m.Cache) != 2 || m.Cache[1] != CacheCold {
		t.Errorf("cache parsed wrong: %+v", m.Cache)
	}
	if len(m.Contentions) != 2 || m.Contentions[1] != 32 {
		t.Errorf("contention parsed wrong: %+v", m.Contentions)
	}
}

func TestParseMatrixFlags_Errors(t *testing.T) {
	cases := []struct {
		name                              string
		tiers, mem, ws, cache, contention string
	}{
		{"bad tier range", "0,4", "512", "128", "warm", "1"},
		{"non-int mem", "1", "lots", "128", "warm", "1"},
		{"bad cache", "1", "512", "128", "lukewarm", "1"},
		{"empty axis", "1", "512", "128", "warm", ""},
		{"non-int contention", "1", "512", "128", "warm", "many"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := parseMatrixFlags(c.tiers, c.mem, c.ws, c.cache, c.contention); err == nil {
				t.Fatalf("expected error for %s", c.name)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Gates
// -----------------------------------------------------------------------------

func TestEvaluateGate(t *testing.T) {
	pass := func(p99 time.Duration) Percentiles { return Percentiles{N: 1, P99: p99, P50: p99} }

	if g := evaluateGate(Tier1, pass(ms(9))); !g.Pass {
		t.Errorf("Tier1 p99=9ms should PASS (<10ms): %+v", g)
	}
	if g := evaluateGate(Tier1, pass(ms(11))); g.Pass {
		t.Errorf("Tier1 p99=11ms should FAIL (>=10ms): %+v", g)
	}
	if g := evaluateGate(Tier2, pass(ms(49))); !g.Pass {
		t.Errorf("Tier2 p99=49ms should PASS (<50ms): %+v", g)
	}
	if g := evaluateGate(Tier2, pass(ms(50))); g.Pass {
		t.Errorf("Tier2 p99=50ms should FAIL (>=50ms): %+v", g)
	}
	// Tier3: both p50<1s and p99<2s.
	if g := evaluateGate(Tier3, Percentiles{N: 1, P50: 900 * time.Millisecond, P99: 1900 * time.Millisecond}); !g.Pass {
		t.Errorf("Tier3 p50=900ms p99=1900ms should PASS: %+v", g)
	}
	if g := evaluateGate(Tier3, Percentiles{N: 1, P50: 1100 * time.Millisecond, P99: 1900 * time.Millisecond}); g.Pass {
		t.Errorf("Tier3 p50=1100ms should FAIL: %+v", g)
	}
	// No samples -> empty (no gate decision, no string).
	if g := evaluateGate(Tier1, Percentiles{}); g.String() != "" {
		t.Errorf("empty percentiles should yield no gate string: %q", g.String())
	}
}

// -----------------------------------------------------------------------------
// Providers
// -----------------------------------------------------------------------------

func TestVMDProvider_NotWired(t *testing.T) {
	p := newVMDProvider()
	_, err := p.Wake(context.Background(), WakeParams{Cell: Cell{Tier: Tier1}})
	if !errors.Is(err, ErrVMDNotWired) {
		t.Fatalf("vmdProvider.Wake should return ErrVMDNotWired, got %v", err)
	}
}

func TestStubProvider_Deterministic(t *testing.T) {
	cell := Cell{Tier: Tier1, MemMiB: 2048, WorkingMiB: 512, Cache: CacheWarm, Contention: 1}
	a := newStubProvider(7)
	b := newStubProvider(7)
	pa, err := a.Wake(context.Background(), WakeParams{Cell: cell})
	if err != nil {
		t.Fatal(err)
	}
	pb, err := b.Wake(context.Background(), WakeParams{Cell: cell})
	if err != nil {
		t.Fatal(err)
	}
	if pa != pb {
		t.Fatalf("same seed should be deterministic: %+v vs %+v", pa, pb)
	}
}

func TestStubProvider_TierPhaseShape(t *testing.T) {
	s := newStubProvider(1)
	// Tier 1: no fetch/attach/load phases; total is small.
	t1, _ := s.Wake(context.Background(), WakeParams{Cell: Cell{Tier: Tier1, MemMiB: 2048, WorkingMiB: 512, Cache: CacheWarm, Contention: 1}})
	if t1.Fetch != 0 || t1.Attach != 0 || t1.Load != 0 {
		t.Errorf("Tier1 should have no fetch/attach/load: %+v", t1)
	}
	if t1.Guest <= 0 || t1.Resume <= 0 {
		t.Errorf("Tier1 should have guest+resume phases: %+v", t1)
	}
	// Tier 3: fetch/attach present.
	t3, _ := s.Wake(context.Background(), WakeParams{Cell: Cell{Tier: Tier3, MemMiB: 2048, WorkingMiB: 512, Cache: CacheCold, Contention: 1}})
	if t3.Fetch <= 0 || t3.Attach <= 0 || t3.Load <= 0 {
		t.Errorf("Tier3 should have fetch/attach/load: %+v", t3)
	}
	if t3.Total() <= t1.Total() {
		t.Errorf("Tier3 total (%v) should exceed Tier1 total (%v)", t3.Total(), t1.Total())
	}
}

// -----------------------------------------------------------------------------
// run() integration over the stub provider
// -----------------------------------------------------------------------------

func TestRun_StubSmallMatrix(t *testing.T) {
	cfg := Config{
		Iterations: 200,
		Matrix: Matrix{
			Tiers:       []Tier{Tier1},
			MemMiB:      []int{2048},
			WorkingMiB:  []int{512},
			Cache:       []CacheState{CacheWarm},
			Contentions: []int{1},
		},
	}
	results, err := run(context.Background(), newStubProvider(3), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 cell result, got %d", len(results))
	}
	r := results[0]
	if r.Err != nil {
		t.Fatalf("unexpected cell error: %v", r.Err)
	}
	if r.Wake.N != 200 {
		t.Errorf("expected 200 samples, got %d", r.Wake.N)
	}
	// Percentiles must be monotonic.
	if !(r.Wake.P50 <= r.Wake.P90 && r.Wake.P90 <= r.Wake.P99 && r.Wake.P99 <= r.Wake.Max) {
		t.Errorf("percentiles not monotonic: %+v", r.Wake)
	}
	if r.Gate.String() == "" {
		t.Errorf("expected a gate decision for Tier1 with samples")
	}
}

func TestRun_VMDRecordsError(t *testing.T) {
	cfg := Config{
		Iterations: 10,
		Matrix: Matrix{
			Tiers:       []Tier{Tier1},
			MemMiB:      []int{2048},
			WorkingMiB:  []int{512},
			Cache:       []CacheState{CacheWarm},
			Contentions: []int{1},
		},
	}
	results, err := run(context.Background(), newVMDProvider(), cfg)
	if err != nil {
		t.Fatalf("run itself should not error (cell error is recorded): %v", err)
	}
	if len(results) != 1 || results[0].Err == nil {
		t.Fatalf("expected the vmd cell to record an error, got %+v", results)
	}
	if !errors.Is(results[0].Err, ErrVMDNotWired) {
		t.Errorf("expected ErrVMDNotWired, got %v", results[0].Err)
	}
}
