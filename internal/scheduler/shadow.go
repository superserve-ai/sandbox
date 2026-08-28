package scheduler

import (
	"context"
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

// ShadowObservation is one evaluated sample, for metrics. Every field is
// a bounded enum or a small int; nothing here is per-sandbox or
// per-tenant.
type ShadowObservation struct {
	// Result: "ranked" (a host would have been chosen), "no_candidates"
	// (nothing rankable), or "error" (the refresh failed).
	Result string
	// Agreement compares the ranking's first choice against the host the
	// live scheduler actually picked: "same", "different", or "unknown"
	// when there was nothing to compare.
	Agreement string
	// Counts of what the ranker saw, so the fleet's readiness for
	// enforcement is visible before anything depends on it.
	Described      int
	UnderDescribed int
	Legacy         int
	Stale          int
	// Duration of the ranking pass itself, off the request path.
	Duration time.Duration
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
	// The slice is copied because the caller's may be reused or mutated
	// after this returns; everything else is a value.
	caps := append([]string(nil), requiredCapabilities...)
	select {
	case s.samples <- shadowSample{
		requiredCapabilities: caps,
		memoryMib:            memoryMib,
		vcpus:                vcpus,
		chosenHost:           chosenHost,
	}:
	default:
		// Queue full: drop. Sampling under load is the intent.
	}
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
			if result.Order[0] == sample.chosenHost {
				obs.Agreement = "same"
			} else {
				obs.Agreement = "different"
			}
		}
	}
	if s.Observe != nil {
		s.Observe(obs)
	}
}
