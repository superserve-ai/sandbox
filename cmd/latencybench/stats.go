package main

import (
	"math"
	"sort"
	"time"
)

// Percentiles holds the summary statistics the validation gates are decided on.
// All fields are durations.
type Percentiles struct {
	N   int
	P50 time.Duration
	P90 time.Duration
	P99 time.Duration
	Max time.Duration
}

// summarize computes p50/p90/p99/max over the given samples.
//
// Percentile definition: nearest-rank on a 0-based sorted slice. For a percentile
// p in [0,100] over n sorted samples, the chosen index is:
//
//	idx = ceil(p/100 * n) - 1, clamped to [0, n-1]
//
// This is the classic "nearest-rank" method (NIST / Hyndman-Fan type 1 family):
// the returned value is always an actual observed sample, never an interpolation.
// We deliberately avoid linear interpolation because (a) the gates compare against
// hard thresholds where reporting a real observed sample is more defensible, and
// (b) it makes the math trivially testable against hand-computed expectations.
//
// Samples are copied before sorting, so the caller's slice is left untouched and
// the input need not be pre-sorted. An empty input yields a zero-value
// Percentiles (N == 0).
func summarize(samples []time.Duration) Percentiles {
	if len(samples) == 0 {
		return Percentiles{}
	}
	sorted := make([]time.Duration, len(samples))
	copy(sorted, samples)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	return Percentiles{
		N:   len(sorted),
		P50: nearestRank(sorted, 50),
		P90: nearestRank(sorted, 90),
		P99: nearestRank(sorted, 99),
		Max: sorted[len(sorted)-1],
	}
}

// nearestRank returns the p-th percentile of an already-sorted, non-empty slice
// using the nearest-rank method. See summarize for the definition.
func nearestRank(sorted []time.Duration, p float64) time.Duration {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[n-1]
	}
	idx := int(math.Ceil(p/100*float64(n))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= n {
		idx = n - 1
	}
	return sorted[idx]
}
