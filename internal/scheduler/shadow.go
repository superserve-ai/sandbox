package scheduler

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/superserve-ai/sandbox/internal/sentrylog"
)

// shadowQueueDepth bounds the pending sample set. Small on purpose: the
// queue IS the sampler. Under a burst it fills, later offers are dropped,
// and what gets evaluated is a sample of traffic rather than all of it —
// which is the whole point. A deep queue would trade the thing being
// protected (latency, memory) for completeness nobody needs from a
// measurement that changes no behavior.
const shadowQueueDepth = 64

// shadowSampleInterval is the minimum gap between accepted samples: an
// explicit rate limit, because the queue alone is not one.
//
// A bounded queue only samples once the worker falls BEHIND. While it
// keeps up it accepts everything, and each accepted sample costs a
// fleet-sized ranking pass and a handful of metric writes — background
// work, but proportional to create rate, which is exactly what a
// high-churn host cannot afford. Ten samples a second is far more than
// enough to characterize placement behavior.
// A var, not a const, so tests can drive many samples through without
// sleeping; nothing in production reassigns it.
var shadowSampleInterval = 100 * time.Millisecond

// ShadowObservation is one evaluated sample, for metrics. Every field is
// a bounded enum or a small int; nothing here is per-sandbox or
// per-tenant.
type ShadowObservation struct {
	// Result: "ranked" (a host would have been chosen), "no_candidates"
	// (nothing rankable), or "error" (the refresh failed).
	Result string
	// Agreement says whether the host the live scheduler picked was among
	// the ones ranking considered equally good: "in_band",
	// "out_of_band", or "unknown" when there was nothing to compare.
	//
	// Judged against the BAND, never against the ranking's first choice.
	// That first choice is drawn at random from the comparable set, so
	// comparing against it would report disagreement (N-1)/N of the time
	// for N equally good hosts — measuring the shuffle rather than the
	// placement.
	Agreement string
	// Profile names the capability set this sample ranked against.
	//
	// Public and private creates rank DIFFERENT host populations, and
	// the composition counts are last-value gauges: without a label
	// separating them, whichever profile sampled last overwrites the
	// other and readiness reads as whatever the most recent create
	// happened to need.
	Profile string
	// Counts of what the ranker saw, so the fleet's readiness for
	// enforcement is visible before anything depends on it.
	Described      int
	UnderDescribed int
	Legacy         int
	Stale          int
	// Duration of the ranking pass itself, off the request path.
	Duration time.Duration
}

// capabilityProfile names a capability set with a short, bounded label.
// The sets are code-defined and few, so an unrecognized one is folded
// into "other" rather than becoming unbounded metric cardinality.
func capabilityProfile(caps []string) string {
	switch len(caps) {
	case 0:
		return "none"
	case 1:
		return "basic"
	default:
		return "extended"
	}
}

// shadowSample is one create's shape, captured on the request path. Kept
// tiny and value-only: it is copied into a channel by a request
// goroutine, so it must not carry anything whose lifetime or locking the
// request cares about.
type shadowSample struct {
	requiredCapabilities []string
	memoryMib            int32
	vcpus                int32
	chosenHost           string
}

// ShadowEvaluator runs capacity ranking alongside real placement without
// influencing it.
//
// The contract that matters is what Offer costs a create: a bounded,
// non-blocking channel send and nothing else. No database query, no
// lock a request could wait on, no ranking work, no metric emission —
// all of that happens on the worker. When the queue is full the sample
// is dropped rather than queued or awaited, so a slow or stuck evaluator
// can never appear in create latency.
//
// It exists to answer, from production traffic, whether the ranking
// would make sane choices before anything is allowed to depend on it:
// how often it would agree with today's scheduler, and how much of the
// fleet is even describable (publishing fresh, complete pressure).
type ShadowEvaluator struct {
	Ranker  *CapacityRanker
	Observe func(ShadowObservation)

	samples chan shadowSample
	// lastSampled is the wall clock of the last accepted sample, as
	// UnixNano. Atomic rather than a mutex so the reject path — the
	// common one — is a load and a compare, with nothing a request can
	// block on.
	lastSampled atomic.Int64
}

// NewShadowEvaluator builds an evaluator with its queue ready. Run must
// be called to drain it; until then Offer simply fills the queue and
// then drops, which is harmless.
func NewShadowEvaluator(ranker *CapacityRanker, observe func(ShadowObservation)) *ShadowEvaluator {
	return &ShadowEvaluator{
		Ranker:  ranker,
		Observe: observe,
		samples: make(chan shadowSample, shadowQueueDepth),
	}
}

// Offer records a create for later evaluation. Safe to call from a
// request goroutine: it never blocks and never returns an error, because
// there is no failure a create should care about.
func (s *ShadowEvaluator) Offer(requiredCapabilities []string, memoryMib, vcpus int32, chosenHost string) {
	if s == nil || s.samples == nil {
		return
	}
	// Decide BEFORE building anything. The rejected path is the common
	// one by design, and it must not allocate: copying the capability
	// slice first would cost every create a heap allocation to produce a
	// message that is immediately thrown away.
	if !s.admitSample() {
		return
	}
	// Copied only now: the caller's slice may be reused or mutated after
	// this returns, and from here the sample outlives the request.
	caps := append([]string(nil), requiredCapabilities...)
	select {
	case s.samples <- shadowSample{
		requiredCapabilities: caps,
		memoryMib:            memoryMib,
		vcpus:                vcpus,
		chosenHost:           chosenHost,
	}:
	default:
		// Worker still busy with the previous sample; drop rather than
		// wait. Nothing downstream needs completeness.
	}
}

// admitSample reports whether enough time has passed to take another
// sample, advancing the clock when it does. Compare-and-swap so that
// concurrent creates cannot both pass the same window.
func (s *ShadowEvaluator) admitSample() bool {
	now := time.Now().UnixNano()
	last := s.lastSampled.Load()
	if now-last < int64(shadowSampleInterval) {
		return false
	}
	return s.lastSampled.CompareAndSwap(last, now)
}

// Run drains and evaluates samples until ctx is cancelled. One worker:
// ranking is cheap, and a single consumer keeps the candidate cache
// refresh serialized without a lock a request could ever contend.
func (s *ShadowEvaluator) Run(ctx context.Context) {
	defer sentrylog.Recover("capacity-shadow-evaluator")
	for {
		select {
		case <-ctx.Done():
			return
		case sample := <-s.samples:
			s.evaluate(ctx, sample)
		}
	}
}

func (s *ShadowEvaluator) evaluate(ctx context.Context, sample shadowSample) {
	started := time.Now()
	result, err := s.Ranker.Rank(ctx, RankRequest{
		RequiredCapabilities: sample.requiredCapabilities,
		MemoryMib:            sample.memoryMib,
		Vcpus:                sample.vcpus,
	})
	obs := ShadowObservation{
		Profile:        capabilityProfile(sample.requiredCapabilities),
		Described:      result.Described,
		UnderDescribed: result.UnderDescribed,
		Legacy:         result.Legacy,
		Stale:          result.Stale,
		Duration:       time.Since(started),
		Agreement:      "unknown",
	}
	switch {
	case err != nil:
		warnRankFailure(err, sample.requiredCapabilities)
		obs.Result = "error"
	case len(result.Order) == 0:
		obs.Result = "no_candidates"
	default:
		obs.Result = "ranked"
		if sample.chosenHost != "" {
			obs.Agreement = "out_of_band"
			for _, id := range result.TopBand {
				if id == sample.chosenHost {
					obs.Agreement = "in_band"
					break
				}
			}
		}
	}
	if s.Observe != nil {
		s.Observe(obs)
	}
}
