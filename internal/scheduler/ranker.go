package scheduler

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
)

// HostCapabilityCapacityPressure is advertised on a host's heartbeat by a
// vmd build that publishes capacity pressure. It is the wire contract
// that lets ranking distinguish "this host never publishes pressure"
// (nothing to rank on) from "this host should be publishing but its
// report is stale or missing" (its numbers cannot be trusted).
const HostCapabilityCapacityPressure = "capacity_pressure_v1"

// PressureFreshnessSecs is how old a pressure report may be before a
// pressure-capable host is treated as undescribed. Three heartbeat
// intervals: one report in flight, one missed, and margin — a publisher
// that broke while its heartbeat stays healthy must stop vouching for
// its own numbers, but a single lost report must not blip a healthy host
// out of consideration.
const PressureFreshnessSecs = 90

const (
	// pressureScoreTolerance defines "comparable" dominant pressure:
	// every host within this band of the best score is an equally good
	// target, and the choice within the band is uniformly random.
	//
	// The randomness is load-bearing for the eventual enforcing design,
	// not decoration here: a globally-best-first order would point every
	// control-plane replica at the same host, recreating the thundering
	// herd the legacy power-of-two choice exists to avoid.
	pressureScoreTolerance = 0.15
)

// RankRequest describes one sandbox to rank hosts for.
type RankRequest struct {
	RequiredCapabilities []string
	MemoryMib            int32
	Vcpus                int32
	// AllowedHosts restricts candidates to this set when non-empty. The
	// hook for template locality — a create from a template only certain
	// hosts hold. Its producer is separate work; ranking just honors it.
	AllowedHosts []string
}

// RankResult is the ordered outcome of one ranking pass.
type RankResult struct {
	// Order is the hosts worth trying, best first. Empty when nothing is
	// rankable.
	Order []string
	// TopBand is every host within the tolerance of the best score —
	// the set that is equally good on pressure grounds, from which
	// Order[0] was drawn at random.
	//
	// Judging a placement against Order[0] alone would be judging it
	// against a coin toss: with N comparable hosts it disagrees (N-1)/N
	// of the time even when the choice was perfect. Band membership is
	// the meaningful question.
	TopBand []string
	// Described counts candidates whose pressure is fresh and complete;
	// UnderDescribed counts those reporting VMs they could not size.
	Described      int
	UnderDescribed int
	// Legacy counts hosts that do not publish pressure at all. They are
	// rankable only by sandbox count, so they are reported separately
	// rather than mixed into a pressure comparison.
	Legacy int
	// Stale counts pressure-capable hosts whose report aged out.
	Stale int
}

// CapacityRanker orders hosts by published capacity pressure.
//
// It RANKS ONLY — it reserves nothing, writes nothing, and makes no
// placement decision. Enforcing admission belongs on the host that owns
// the capacity, inside its create RPC, where the check is a local mutex
// rather than a database round trip on the request path.
//
// Its candidate set is loaded in the background by whoever owns it (see
// ShadowEvaluator), never inside a caller's request.
type CapacityRanker struct {
	DB     *db.Queries
	Region string        // prefer same-region hosts when set
	TTL    time.Duration // 0 = defaultRankerCacheTTL

	mu    sync.RWMutex
	cache map[string]rankerCacheEntry
	// gen advances whenever the candidate set is refreshed, and keys the
	// memo below so a stale ranking can never outlive the rows it was
	// computed from.
	gen  uint64
	memo map[rankMemoKey]rankMemoEntry
}

// rankMemoKey identifies a ranking that would produce the same answer:
// the same candidate set, the same capability filter, the same shape.
type rankMemoKey struct {
	capabilities string
	memoryMib    int32
	vcpus        int32
	allowedHosts string
}

type rankMemoEntry struct {
	gen    uint64
	result RankResult
}

const defaultRankerCacheTTL = 30 * time.Second

type rankerCacheEntry struct {
	rows     []db.ListCapacityCandidatesRow
	cachedAt time.Time
}

func (r *CapacityRanker) ttl() time.Duration {
	if r.TTL > 0 {
		return r.TTL
	}
	return defaultRankerCacheTTL
}

// Invalidate drops cached candidate sets so the next refresh reflects
// host status or capability changes immediately.
func (r *CapacityRanker) Invalidate() {
	r.mu.Lock()
	r.cache = nil
	r.gen++
	r.memo = nil
	r.mu.Unlock()
}

// Rank orders hosts for a request. The candidate set comes from cache;
// when it is missing or expired this refreshes it, which means Rank
// performs I/O and must only be called from a background worker.
func (r *CapacityRanker) Rank(ctx context.Context, req RankRequest) (RankResult, error) {
	rows, err := r.candidates(ctx, req.RequiredCapabilities)
	if err != nil {
		return RankResult{}, err
	}

	// Ranking is O(fleet) in both time and allocation, and creates
	// repeat a handful of shapes — the default size, one per template —
	// against a candidate set that only changes when it is refreshed. So
	// memoize per (candidate generation, shape): a fleet-sized pass runs
	// once per refresh per distinct shape, not once per sample. Without
	// this a large fleet turns a steady sample rate into steady GC
	// pressure for a measurement nothing depends on.
	capKey, _ := capabilityCacheKey(req.RequiredCapabilities)
	memoKey := rankMemoKey{
		capabilities: capKey,
		memoryMib:    req.MemoryMib,
		vcpus:        req.Vcpus,
		allowedHosts: strings.Join(req.AllowedHosts, "\x00"),
	}
	r.mu.RLock()
	entry, hit := r.memo[memoKey]
	gen := r.gen
	r.mu.RUnlock()
	if hit && entry.gen == gen {
		return entry.result, nil
	}
	if len(req.AllowedHosts) > 0 {
		allowed := make(map[string]bool, len(req.AllowedHosts))
		for _, id := range req.AllowedHosts {
			allowed[id] = true
		}
		filtered := rows[:0:0]
		for _, row := range rows {
			if allowed[row.ID] {
				filtered = append(filtered, row)
			}
		}
		rows = filtered
	}

	// Composition describes the FLEET, so all four counts are taken over
	// the same population: every capability-matching host, before any
	// viability or region filtering. Counting described hosts after those
	// filters while counting legacy and stale before them would make the
	// gauges incomparable — a low described count would mean "wrong
	// region" as readily as "not publishing", which is the opposite of
	// what a readiness signal is for.
	var result RankResult
	var eligible []db.ListCapacityCandidatesRow
	for _, row := range rows {
		switch {
		case !row.PressureCapable:
			result.Legacy++
		case !row.ReportedAt.Valid || time.Since(row.ReportedAt.Time) >= PressureFreshnessSecs*time.Second:
			result.Stale++
		case row.UnknownAllocationVms > 0:
			result.UnderDescribed++
			eligible = append(eligible, row)
		default:
			result.Described++
			eligible = append(eligible, row)
		}
	}
	// Viability BEFORE region. Filtering by region first lets a single
	// full local host hide every remote host with room: the local set is
	// non-empty, so remote candidates are discarded, and then the local
	// one is dropped for being full — leaving nothing.
	viable := eligible[:0:0]
	for _, row := range eligible {
		if fits(row, req) {
			viable = append(viable, row)
		}
	}
	eligible = preferRegion(viable, r.Region)

	// Fully-described hosts first. An unsized VM contributes zero memory
	// and zero vCPUs to its host's report, which is indistinguishable
	// from no VM at all — so an under-described host's ratios are an
	// UNDERCOUNT and it looks emptier than it is. Ordering, not
	// exclusion: the shortfall is confined to memory and vCPUs (sandbox
	// and slot counts stay exact whatever a VM's size), and every host
	// carries unsized VMs until its pre-declaration sandboxes cycle out,
	// so excluding them would empty the set on day one.
	described, underDescribed := splitByDescription(eligible)

	order, band := rankCandidates(described, req)
	underOrder, underBand := rankCandidates(underDescribed, req)
	order = append(order, underOrder...)
	if len(band) == 0 {
		// Nothing fully described: the acceptable set is the
		// under-described band, since that is all there is to choose
		// from.
		band = underBand
	}

	result.Order = make([]string, 0, len(order))
	for _, row := range order {
		result.Order = append(result.Order, row.ID)
	}
	result.TopBand = make([]string, 0, len(band))
	for _, row := range band {
		result.TopBand = append(result.TopBand, row.ID)
	}

	r.mu.Lock()
	if r.gen == gen { // a refresh mid-rank invalidates this answer
		if r.memo == nil {
			r.memo = make(map[rankMemoKey]rankMemoEntry)
		}
		r.memo[memoKey] = rankMemoEntry{gen: gen, result: result}
	}
	r.mu.Unlock()
	return result, nil
}

func (r *CapacityRanker) candidates(ctx context.Context, required []string) ([]db.ListCapacityCandidatesRow, error) {
	key, normalized := capabilityCacheKey(required)
	r.mu.RLock()
	entry, ok := r.cache[key]
	r.mu.RUnlock()
	if ok && time.Since(entry.cachedAt) < r.ttl() {
		return entry.rows, nil
	}

	rows, err := r.DB.ListCapacityCandidates(ctx, db.ListCapacityCandidatesParams{
		PressureCapability:   HostCapabilityCapacityPressure,
		RequiredCapabilities: normalized,
	})
	if err != nil {
		return nil, fmt.Errorf("list capacity candidates: %w", err)
	}
	r.mu.Lock()
	if r.cache == nil {
		r.cache = make(map[string]rankerCacheEntry)
	}
	r.cache[key] = rankerCacheEntry{rows: rows, cachedAt: time.Now()}
	// New rows, so every memoized ranking is now answering from stale
	// data; bump the generation rather than walk the memo.
	r.gen++
	r.memo = nil
	r.mu.Unlock()
	return rows, nil
}

// splitByDescription separates hosts that fully know their own
// allocation from those reporting unsized VMs.
func splitByDescription(rows []db.ListCapacityCandidatesRow) (described, underDescribed []db.ListCapacityCandidatesRow) {
	for _, row := range rows {
		if row.UnknownAllocationVms > 0 {
			underDescribed = append(underDescribed, row)
		} else {
			described = append(described, row)
		}
	}
	return described, underDescribed
}

// preferRegion keeps only same-region rows when any exist; otherwise the
// full set stands (a remote host beats nowhere to put the sandbox).
func preferRegion(rows []db.ListCapacityCandidatesRow, region string) []db.ListCapacityCandidatesRow {
	if region == "" || len(rows) == 0 {
		return rows
	}
	var local []db.ListCapacityCandidatesRow
	for _, row := range rows {
		if row.Region == region {
			local = append(local, row)
		}
	}
	if len(local) > 0 {
		return local
	}
	return rows
}

// rankCandidates orders hosts best-first: obviously-full hosts are
// dropped, survivors are scored by dominant pressure, the tolerance band
// around the best score is shuffled (with warm-slot hosts ahead within
// it), and out-of-band hosts follow in score order.
func rankCandidates(eligible []db.ListCapacityCandidatesRow, req RankRequest) (order, band []db.ListCapacityCandidatesRow) {
	type scored struct {
		row   db.ListCapacityCandidatesRow
		score float64
	}
	candidates := make([]scored, 0, len(eligible))
	for _, row := range eligible {
		candidates = append(candidates, scored{row: row, score: dominantScore(row, req)})
	}
	if len(candidates) == 0 {
		return nil, nil
	}
	best := candidates[0].score
	for _, c := range candidates[1:] {
		if c.score < best {
			best = c.score
		}
	}

	// Inside the band every host is an equally good target on pressure
	// grounds, so warm-slot availability decides — but only as a
	// partition, and each partition is shuffled: preferring warmth must
	// not reintroduce a deterministic first choice.
	var warmBand, coldBand, rest []scored
	for _, c := range candidates {
		switch {
		case c.score > best+pressureScoreTolerance:
			rest = append(rest, c)
		case hasWarmSlot(c.row):
			warmBand = append(warmBand, c)
		default:
			coldBand = append(coldBand, c)
		}
	}
	rand.Shuffle(len(warmBand), func(i, j int) { warmBand[i], warmBand[j] = warmBand[j], warmBand[i] })
	rand.Shuffle(len(coldBand), func(i, j int) { coldBand[i], coldBand[j] = coldBand[j], coldBand[i] })
	sort.SliceStable(rest, func(i, j int) bool { return rest[i].score < rest[j].score })

	out := make([]db.ListCapacityCandidatesRow, 0, len(candidates))
	for _, group := range [][]scored{warmBand, coldBand, rest} {
		for _, c := range group {
			out = append(out, c.row)
		}
	}
	// The band is the set the ranker would actually draw from, which is
	// NOT every host within the score tolerance: warm hosts are ordered
	// ahead of cold ones, so while any warm host is available a cold one
	// is never chosen. Including cold hosts here would report agreement
	// for a placement the ranker would never have made.
	drawn := warmBand
	if len(drawn) == 0 {
		drawn = coldBand
	}
	band = make([]db.ListCapacityCandidatesRow, 0, len(drawn))
	for _, c := range drawn {
		band = append(band, c.row)
	}
	return out, band
}

// fits reports whether a host is under its OPERATOR limits with room for
// one more sandbox. Memory and vCPUs are deliberately not hard limits:
// firecracker hosts overcommit both by design (lazy faulting), so
// capping at physical capacity would rule out hosts that run fine today.
// They are ranking signals instead.
func fits(row db.ListCapacityCandidatesRow, req RankRequest) bool {
	if row.MaxSandboxes > 0 &&
		row.RunningSandboxes+row.ProvisioningSandboxes+row.PausedSandboxes+1 > row.MaxSandboxes {
		return false
	}
	if lim := effectiveSlotLimit(row.MaxNetworkSlots, row.NetSlotCeiling); lim > 0 {
		netNew := 1 - row.WarmNetSlots
		if netNew < 0 {
			netNew = 0
		}
		if row.UsedNetSlots+row.ProvisioningNetSlots+row.WarmNetSlots+netNew > lim {
			return false
		}
	}
	return true
}

// dominantScore is a host's worst pressure ratio across the four
// resource axes with this request's shape charged in. Memory and vcpu
// ratios may legitimately exceed 1.0 on overcommitted hosts — they order
// hosts, they do not gate them.
func dominantScore(row db.ListCapacityCandidatesRow, req RankRequest) float64 {
	var score float64
	if row.MaxSandboxes > 0 {
		s := float64(row.RunningSandboxes+row.ProvisioningSandboxes+row.PausedSandboxes+1) /
			float64(row.MaxSandboxes)
		score = max(score, s)
	}
	if lim := effectiveSlotLimit(row.MaxNetworkSlots, row.NetSlotCeiling); lim > 0 {
		netNew := 1 - row.WarmNetSlots
		if netNew < 0 {
			netNew = 0
		}
		s := float64(row.UsedNetSlots+row.ProvisioningNetSlots+row.WarmNetSlots+netNew) / float64(lim)
		score = max(score, s)
	}
	if row.CapacityMemoryMib > 0 {
		s := float64(row.AllocatedMemoryMib+int64(req.MemoryMib)) / float64(row.CapacityMemoryMib)
		score = max(score, s)
	}
	if row.CapacityVcpus > 0 {
		s := float64(row.AllocatedVcpus+int64(req.Vcpus)) / float64(row.CapacityVcpus)
		score = max(score, s)
	}
	return score
}

// hasWarmSlot reports whether a prepared network slot is available, so a
// create landing here would skip slot provisioning.
func hasWarmSlot(row db.ListCapacityCandidatesRow) bool { return row.WarmNetSlots > 0 }

func effectiveSlotLimit(maxSlots, ceiling int32) int32 {
	switch {
	case maxSlots > 0 && ceiling > 0:
		return min(maxSlots, ceiling)
	case maxSlots > 0:
		return maxSlots
	default:
		return ceiling
	}
}

// warnRankFailure keeps refresh failures visible without letting them
// reach a caller: nothing depends on ranking yet.
func warnRankFailure(err error, required []string) {
	log.Warn().Err(err).Strs("required_capabilities", required).
		Msg("capacity ranking refresh failed; shadow evaluation skipped for this sample")
}
