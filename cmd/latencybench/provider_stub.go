package main

import (
	"context"
	"math"
	"math/rand"
	"time"
)

// stubProvider returns SYNTHETIC, plausible-looking per-phase timings so the
// harness (matrix sweep, percentile math, table rendering, gate evaluation) can be
// exercised end-to-end without a VM or KVM. It is NOT a measurement of anything.
//
// The synthetic model is intentionally simple and clearly fake:
//   - Phase means are drawn from rough per-tier expectations in §3, scaled by the
//     working set for the guest-fault phase (Tier 2/3 fault-in cost grows with ws).
//   - A small lognormal jitter and a rare tail spike produce a distribution (not a
//     constant), so p50/p90/p99 differ — enough to demonstrate the gates.
//
// Determinism: seeded RNG, so a given -seed reproduces the same output. This makes
// the stub useful in tests and reviews, and keeps it obviously distinct from a real
// measurement.
type stubProvider struct {
	rng *rand.Rand
}

func newStubProvider(seed int64) *stubProvider {
	return &stubProvider{rng: rand.New(rand.NewSource(seed))}
}

func (s *stubProvider) Label() string { return "stub (SYNTHETIC — not measured)" }

func (s *stubProvider) Wake(_ context.Context, params WakeParams) (PhaseTimings, error) {
	c := params.Cell

	// Base per-phase means (microseconds) chosen to roughly match §3 expectations.
	// These are made up. Do not cite them.
	ctrlUs := 200.0 + 30.0*float64(c.Contention) // control plane grows under contention
	resumeUs := 1000.0                           // FC PATCH /vm Resumed ~1ms
	netUs := 100.0                               // netns kept attached on Tier 1 (cheap)

	var fetchUs, attachUs, loadUs float64
	// Guest fault-in: Tier 1 pages are resident (cheap); Tier 2/3 fault from the
	// mem file, so the guest phase scales with the working set.
	var guestUs float64

	switch c.Tier {
	case Tier1:
		// Resident memory: the first op just re-touches already-present pages.
		guestUs = 1500.0 + 0.5*float64(c.WorkingMiB)
	case Tier2:
		loadUs = 4000.0
		guestUs = 4000.0 + 25.0*float64(c.WorkingMiB) // UFFD fault-in dominates
	case Tier3:
		loadUs = 6000.0
		guestUs = 6000.0 + 25.0*float64(c.WorkingMiB)
		fetchUs = 200000.0 + 80.0*float64(c.MemMiB) // snapshot transport
		attachUs = 150000.0                         // cold /state mount
		netUs = 3000.0                              // full netns build on a cold host
	}

	// Cold page cache penalizes the loading/faulting phases.
	if c.Cache == CacheCold {
		loadUs *= 1.6
		guestUs *= 1.4
		fetchUs *= 1.3
	}

	pt := PhaseTimings{
		Control: s.sample(ctrlUs),
		Fetch:   s.sampleOptional(fetchUs),
		Attach:  s.sampleOptional(attachUs),
		Load:    s.sampleOptional(loadUs),
		Resume:  s.sample(resumeUs),
		Net:     s.sample(netUs),
		Guest:   s.sample(guestUs),
	}
	return pt, nil
}

// sample draws a positive duration around meanUs with lognormal jitter plus a rare
// heavy-tail spike, producing a realistic-looking spread (so p99 > p50).
func (s *stubProvider) sample(meanUs float64) time.Duration {
	if meanUs <= 0 {
		return 0
	}
	// Lognormal jitter: sigma 0.25 in log-space => ~±25% typical spread.
	jitter := math.Exp(s.rng.NormFloat64() * 0.25)
	v := meanUs * jitter
	// ~1% chance of a 3–8x tail spike (the outliers the gates care about).
	if s.rng.Float64() < 0.01 {
		v *= 3 + 5*s.rng.Float64()
	}
	return time.Duration(v * float64(time.Microsecond))
}

// sampleOptional returns 0 for phases that don't apply to a tier (meanUs == 0),
// otherwise behaves like sample.
func (s *stubProvider) sampleOptional(meanUs float64) time.Duration {
	if meanUs <= 0 {
		return 0
	}
	return s.sample(meanUs)
}
