package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Tier is a hibernation tier from VALIDATION-latency.md §0 / DIAGRAMS §2.
type Tier int

const (
	// Tier1 — paused-in-RAM. Firecracker PATCH /vm Paused -> Resumed. Memory
	// stays resident, /state mounted, network attached, lease held. This is the
	// gate that decides whether between-turns hibernation is viable at all.
	Tier1 Tier = 1
	// Tier2 — local snapshot on host NVMe + UFFD lazy page-in. RAM reclaimed,
	// host pinned. Page-in cost moves into the first turn (T_guest).
	Tier2 Tier = 2
	// Tier3 — cold / cross-host. Snapshot + state in object storage, restored on
	// a different host with the /state volume attached there. Adds T_fetch and
	// T_attach long poles.
	Tier3 Tier = 3
)

func (t Tier) String() string {
	switch t {
	case Tier1:
		return "1"
	case Tier2:
		return "2"
	case Tier3:
		return "3"
	default:
		return "?(" + strconv.Itoa(int(t)) + ")"
	}
}

// CacheState is the host page-cache arm of the sweep.
type CacheState string

const (
	CacheWarm CacheState = "warm"
	CacheCold CacheState = "cold"
)

// Cell is one point in the sweep matrix.
type Cell struct {
	Tier       Tier
	MemMiB     int
	WorkingMiB int
	Cache      CacheState
	// Contention is the number of paused VMs per core during the measurement
	// (K = 1, 8, 32 in §4). Tier-1 wake p99 under contention is the density test.
	Contention int
}

// PhaseTimings is the per-wake decomposition from §2.3. A provider fills in the
// phases relevant to the tier (Fetch/Attach are Tier-3 only; Load is Tier 2/3).
type PhaseTimings struct {
	Control time.Duration // lease acquire + schedule/route (control plane)
	Fetch   time.Duration // snapshot bytes -> local (Tier 3 only)
	Attach  time.Duration // /state volume mount (Tier 3 only)
	Load    time.Duration // Firecracker build VM + load snapshot + UFFD up (Tier 2/3)
	Resume  time.Duration // Firecracker PATCH /vm Resumed (all)
	Net     time.Duration // network reattach if on the wake path (all — see §4)
	Guest   time.Duration // guest faults in working set + does first meaningful op (all)
}

// Total is the end-to-end wake latency: trigger issued -> first meaningful op
// done. This is what the gates are decided on.
func (p PhaseTimings) Total() time.Duration {
	return p.Control + p.Fetch + p.Attach + p.Load + p.Resume + p.Net + p.Guest
}

// WakeParams carries the cell and iteration index into a wake.
type WakeParams struct {
	Cell      Cell
	Iteration int
}

// WakeProvider performs one wake of a VM in the given tier and returns the
// per-phase decomposition. Implementations:
//
//   - stubProvider: synthetic, no VM, for exercising the harness.
//   - vmdProvider:  real Firecracker/vmd — not wired yet (returns an error).
type WakeProvider interface {
	// Wake puts a VM into the cell's tier, triggers a wake, drives the guest probe
	// to first-meaningful-op, and returns the phase decomposition for that single
	// iteration.
	Wake(ctx context.Context, params WakeParams) (PhaseTimings, error)
	// Label identifies the provider in output (e.g. "stub (SYNTHETIC)").
	Label() string
}

// -----------------------------------------------------------------------------
// Matrix expansion
// -----------------------------------------------------------------------------

// Matrix is the cross-product sweep config (§2.2).
type Matrix struct {
	Tiers       []Tier
	MemMiB      []int
	WorkingMiB  []int
	Cache       []CacheState
	Contentions []int
}

// Expand returns every cell of the cross product in a deterministic order
// (tier, mem, ws, cache, contention — outermost first).
func (m Matrix) Expand() []Cell {
	cells := make([]Cell, 0,
		len(m.Tiers)*len(m.MemMiB)*len(m.WorkingMiB)*len(m.Cache)*len(m.Contentions))
	for _, t := range m.Tiers {
		for _, mem := range m.MemMiB {
			for _, ws := range m.WorkingMiB {
				for _, cache := range m.Cache {
					for _, c := range m.Contentions {
						cells = append(cells, Cell{
							Tier:       t,
							MemMiB:     mem,
							WorkingMiB: ws,
							Cache:      cache,
							Contention: c,
						})
					}
				}
			}
		}
	}
	return cells
}

// parseMatrixFlags builds a Matrix from comma-separated flag strings.
func parseMatrixFlags(tiers, mem, ws, cache, contention string) (Matrix, error) {
	tierVals, err := parseInts(tiers)
	if err != nil {
		return Matrix{}, fmt.Errorf("tiers: %w", err)
	}
	var ts []Tier
	for _, v := range tierVals {
		if v < 1 || v > 3 {
			return Matrix{}, fmt.Errorf("tiers: %d out of range [1,3]", v)
		}
		ts = append(ts, Tier(v))
	}

	memVals, err := parseInts(mem)
	if err != nil {
		return Matrix{}, fmt.Errorf("mem: %w", err)
	}
	wsVals, err := parseInts(ws)
	if err != nil {
		return Matrix{}, fmt.Errorf("ws: %w", err)
	}
	contVals, err := parseInts(contention)
	if err != nil {
		return Matrix{}, fmt.Errorf("contention: %w", err)
	}

	var cacheVals []CacheState
	for _, raw := range splitNonEmpty(cache) {
		switch CacheState(raw) {
		case CacheWarm:
			cacheVals = append(cacheVals, CacheWarm)
		case CacheCold:
			cacheVals = append(cacheVals, CacheCold)
		default:
			return Matrix{}, fmt.Errorf("cache: unknown state %q (want warm|cold)", raw)
		}
	}

	m := Matrix{Tiers: ts, MemMiB: memVals, WorkingMiB: wsVals, Cache: cacheVals, Contentions: contVals}
	if len(m.Tiers) == 0 || len(m.MemMiB) == 0 || len(m.WorkingMiB) == 0 || len(m.Cache) == 0 || len(m.Contentions) == 0 {
		return Matrix{}, fmt.Errorf("every matrix axis must have at least one value")
	}
	return m, nil
}

func parseInts(s string) ([]int, error) {
	var out []int
	for _, raw := range splitNonEmpty(s) {
		v, err := strconv.Atoi(raw)
		if err != nil {
			return nil, fmt.Errorf("%q is not an int", raw)
		}
		out = append(out, v)
	}
	return out, nil
}

func splitNonEmpty(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// -----------------------------------------------------------------------------
// Gates (§0)
// -----------------------------------------------------------------------------

// GateResult is the pass/fail decision for a cell against its tier's gate.
type GateResult struct {
	Pass   bool
	Detail string
}

func (g GateResult) String() string {
	if g.Detail == "" {
		return ""
	}
	if g.Pass {
		return "PASS"
	}
	return "FAIL"
}

// evaluateGate applies the §0 thresholds. The gate is decided on the end-to-end
// wake (first meaningful op), using p99 for Tiers 1/2 and both p50 and p99 for
// Tier 3.
func evaluateGate(t Tier, w Percentiles) GateResult {
	if w.N == 0 {
		return GateResult{}
	}
	switch t {
	case Tier1:
		return gateP99(w, 10*time.Millisecond)
	case Tier2:
		return gateP99(w, 50*time.Millisecond)
	case Tier3:
		p50ok := w.P50 < 1*time.Second
		p99ok := w.P99 < 2*time.Second
		return GateResult{
			Pass:   p50ok && p99ok,
			Detail: fmt.Sprintf("p50<1s=%v p99<2s=%v", p50ok, p99ok),
		}
	default:
		return GateResult{}
	}
}

func gateP99(w Percentiles, threshold time.Duration) GateResult {
	return GateResult{
		Pass:   w.P99 < threshold,
		Detail: fmt.Sprintf("p99<%s", threshold),
	}
}
