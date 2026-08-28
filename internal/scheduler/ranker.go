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
	gen  uint64
	plan *rankPlan
}

const defaultRankerCacheTTL = 30 * time.Second

// rankerFillTimeout bounds one candidate refresh, matching the live
// scheduler's cache-fill bound.
const rankerFillTimeout = 5 * time.Second

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

// rankedHost is one candidate with everything that does NOT depend on
// the clock or on chance precomputed: its score for a given request
// shape, whether it fits, whether it has warm inventory, and the instant
// its pressure report goes stale.
type rankedHost struct {
	id        string
	region    string
	capable   bool
	described bool
	viable    bool
	warm      bool
	score     float64
	staleAt   time.Time // zero when the host has never reported
}

// rankPlan is the memoized, deterministic half of a ranking: valid for
// one candidate generation and one request shape.
//
// Freshness and randomness are deliberately NOT in here. Caching a
// freshness verdict would keep calling a host described for up to a full
// refresh interval after its report aged out, and caching the shuffled
// order would hand every decision in that interval the same host —
// defeating the load spreading the shuffle exists to provide.
type rankPlan struct {
	hosts []rankedHost
}

// Rank orders hosts for a request. The candidate set comes from cache;
// when it is missing or expired this refreshes it, which means Rank
// performs I/O and must only be called from a background worker.
func (r *CapacityRanker) Rank(ctx context.Context, req RankRequest) (RankResult, error) {
	plan, err := r.plan(ctx, req)
	if err != nil {
		return RankResult{}, err
	}
	return rankFromPlan(plan, r.Region), nil
}

// plan returns the deterministic ranking data for this generation and
// shape, computing it once and reusing it: scoring and fitting are
// O(fleet) with real allocation, and creates repeat a handful of shapes.
func (r *CapacityRanker) plan(ctx context.Context, req RankRequest) (*rankPlan, error) {
	rows, err := r.candidates(ctx, req.RequiredCapabilities)
	if err != nil {
		return nil, err
	}

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
		return entry.plan, nil
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

	plan := &rankPlan{hosts: make([]rankedHost, 0, len(rows))}
	for _, row := range rows {
		h := rankedHost{
			id:        row.ID,
			region:    row.Region,
			capable:   row.PressureCapable,
			described: row.UnknownAllocationVms == 0,
			viable:    fits(row, req),
			warm:      hasWarmSlot(row),
			score:     dominantScore(row, req),
		}
		if row.ReportedAt.Valid {
			h.staleAt = row.ReportedAt.Time.Add(PressureFreshnessSecs * time.Second)
		}
		plan.hosts = append(plan.hosts, h)
	}

	r.mu.Lock()
	if r.gen == gen { // a refresh mid-plan invalidates this one
		if r.memo == nil {
			r.memo = make(map[rankMemoKey]rankMemoEntry)
		}
		r.memo[memoKey] = rankMemoEntry{gen: gen, plan: plan}
	}
	r.mu.Unlock()
	return plan, nil
}

// rankFromPlan applies everything that must be decided fresh: whether
// each report is still within its freshness window, and which of the
// comparable hosts to put first.
func rankFromPlan(plan *rankPlan, region string) RankResult {
	now := time.Now()
	var result RankResult

	// Composition describes the FLEET, so all four counts are taken over
	// the same population: every capability-matching host, before any
	// viability or region filtering. Counting described hosts after those
	// filters while counting legacy and stale before them would make the
	// gauges incomparable — a low described count would mean "wrong
	// region" as readily as "not publishing", which is the opposite of
	// what a readiness signal is for.
	eligible := make([]rankedHost, 0, len(plan.hosts))
	for _, h := range plan.hosts {
		switch {
		case !h.capable:
			result.Legacy++
		case h.staleAt.IsZero() || !now.Before(h.staleAt):
			result.Stale++
		case h.described:
			result.Described++
			eligible = append(eligible, h)
		default:
			result.UnderDescribed++
			eligible = append(eligible, h)
		}
	}

	// Viability BEFORE region. Filtering by region first lets a single
	// full local host hide every remote host with room: the local set is
	// non-empty, so remote candidates are discarded, and then the local
	// one is dropped for being full — leaving nothing.
	viable := eligible[:0:0]
	for _, h := range eligible {
		if h.viable {
			viable = append(viable, h)
		}
	}
	eligible = preferRegionHosts(viable, region)

	// Fully-described hosts first. An unsized VM contributes zero memory
	// and zero vCPUs to its host's report, which is indistinguishable
	// from no VM at all — so an under-described host looks emptier than
	// it is. Ordering, not exclusion: the shortfall is confined to memory
	// and vCPUs, and every host carries unsized VMs until its
	// pre-declaration sandboxes cycle out.
	var described, underDescribed []rankedHost
	for _, h := range eligible {
		if h.described {
			described = append(described, h)
		} else {
			underDescribed = append(underDescribed, h)
		}
	}

	order, band := orderHosts(described)
	underOrder, underBand := orderHosts(underDescribed)
	order = append(order, underOrder...)
	if len(band) == 0 {
		band = underBand
	}
	result.Order, result.TopBand = order, band
	return result
}

// orderHosts sorts one tier best-first and reports the band it drew
// from. The shuffle happens here, per call: a frozen order would send
// every decision in a generation to the same host.
func orderHosts(hosts []rankedHost) (order, band []string) {
	if len(hosts) == 0 {
		return nil, nil
	}
	best := hosts[0].score
	for _, h := range hosts[1:] {
		if h.score < best {
			best = h.score
		}
	}

	var warmBand, coldBand, rest []rankedHost
	for _, h := range hosts {
		switch {
		case h.score > best+pressureScoreTolerance:
			rest = append(rest, h)
		case h.warm:
			warmBand = append(warmBand, h)
		default:
			coldBand = append(coldBand, h)
		}
	}
	rand.Shuffle(len(warmBand), func(i, j int) { warmBand[i], warmBand[j] = warmBand[j], warmBand[i] })
	rand.Shuffle(len(coldBand), func(i, j int) { coldBand[i], coldBand[j] = coldBand[j], coldBand[i] })
	sort.SliceStable(rest, func(i, j int) bool { return rest[i].score < rest[j].score })

	order = make([]string, 0, len(hosts))
	for _, group := range [][]rankedHost{warmBand, coldBand, rest} {
		for _, h := range group {
			order = append(order, h.id)
		}
	}

	// The band is the set the ranker would actually draw from, which is
	// NOT every host within the score tolerance: warm hosts are ordered
	// ahead of cold ones, so while any warm host is available a cold one
	// is never chosen.
	drawn := warmBand
	if len(drawn) == 0 {
		drawn = coldBand
	}
	band = make([]string, 0, len(drawn))
	for _, h := range drawn {
		band = append(band, h.id)
	}
	return order, band
}

// preferRegionHosts keeps only same-region hosts when any exist;
// otherwise the full set stands (a remote host beats nowhere to put the
// sandbox).
func preferRegionHosts(hosts []rankedHost, region string) []rankedHost {
	if region == "" || len(hosts) == 0 {
		return hosts
	}
	local := hosts[:0:0]
	for _, h := range hosts {
		if h.region == region {
			local = append(local, h)
		}
	}
	if len(local) > 0 {
		return local
	}
	return hosts
}

func (r *CapacityRanker) candidates(ctx context.Context, required []string) ([]db.ListCapacityCandidatesRow, error) {
	key, normalized := capabilityCacheKey(required)
	r.mu.RLock()
	entry, ok := r.cache[key]
	r.mu.RUnlock()
	if ok && time.Since(entry.cachedAt) < r.ttl() {
		return entry.rows, nil
	}

	// Bounded like the live scheduler's cache fill: a background worker
	// with no deadline would sit on a wedged database indefinitely,
	// holding the sample it was evaluating and stalling every later one.
	ctx, cancel := context.WithTimeout(ctx, rankerFillTimeout)
	defer cancel()
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
