package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/superserve-ai/sandbox/internal/preview"
)

// ErrInstanceNotFound is returned when the resolver has no record of the instance.
var ErrInstanceNotFound = errors.New("proxy: instance not found")

// ErrVMDPreviewProtocolUnsupported is returned when a successful lookup lacks
// proof that VMD understands preview publication. Treating that response as a
// legacy sandbox would expose strict sandboxes during a VMD rollback.
var ErrVMDPreviewProtocolUnsupported = errors.New("proxy: vmd does not attest preview publication protocol")

// InstanceInfo holds the routing information for a sandbox instance.
type InstanceInfo struct {
	VMIP                     string
	Status                   string
	StartedAt                int64  // Unix nanoseconds; changes on restart — used as transport lifecycle key
	TeamID                   string // owning team, for usage attribution
	OwnerID                  string // creating user, for usage attribution; empty when unknown
	PreviewAccess            string
	PreviewPorts             map[int]struct{}
	PreviewPortAccess        map[int]string
	PreviewPortTokenVersions map[int]int64
}

// lifecycleKey returns a string stable for the lifetime of one VM boot.
func (i InstanceInfo) lifecycleKey() string {
	return strconv.FormatInt(i.StartedAt, 10)
}

// Resolver is the interface the proxy uses to look up sandbox instances.
// The current implementation queries VMD's local HTTP server.
// When Redis is added, swap in a RedisResolver without touching the proxy.
type Resolver interface {
	Lookup(ctx context.Context, instanceID string) (InstanceInfo, error)
	Invalidate(instanceID string)
}

// ---------------------------------------------------------------------------
// VMDResolver — queries VMD's local HTTP server (current implementation)
// ---------------------------------------------------------------------------

const (
	defaultVMDAddr   = "http://127.0.0.1:9090"
	negativeCacheTTL = 1 * time.Second // cache "not found" slightly longer to absorb spam
	maxCacheSize     = 10_000          // cap against random instance ID amplification

	// vmdRequestTimeout bounds a single resolve call. A steady-state lookup is a
	// localhost map read (sub-ms), but a miss right after a VMD restart triggers
	// an on-demand reattach (netlink/nftables setup that takes no client ctx and
	// can run into the low seconds under host load). Keep this above VMD's own
	// 5s per-VM reattach bound so a would-succeed reattach isn't cut short into a
	// data-plane timeout; singleflight + the negative cache bound amplification.
	vmdRequestTimeout = 6 * time.Second
)

type cacheEntry struct {
	expiresAt time.Time
}

// VMDResolver looks up instanceID → vmIP by querying VMD's local HTTP server.
// Successful results are never cached: the response contains the live preview
// policy, so retaining it after the lookup would extend the lifetime of an
// unpublished port or a revoked credential. Concurrent overlapping lookups are
// still collapsed by singleflight. Only negative results are cached, to prevent
// VMD amplification from random unknown IDs.
type VMDResolver struct {
	vmdAddr string
	client  *http.Client
	// previewTokens is enabled only after cmd/proxy installs a valid seed.
	// It keeps the local protocol attestation honest when token auth is not
	// configured, causing VMD to withhold tokenized instances instead.
	previewTokens bool

	mu sync.Mutex
	// epoch advances on any explicit invalidation. It is part of the
	// singleflight key and guards negative-cache writes, so a request that was
	// already in flight cannot capture a later caller or reinsert a stale miss
	// after invalidation. A global epoch avoids an unbounded per-instance
	// generation map; an invalidation may cause an unrelated overlapping lookup
	// to use a new flight, but does not discard its negative cache entry.
	epoch uint64
	cache map[string]cacheEntry
	group singleflight.Group
}

// WithPreviewTokens declares that the owning proxy handler has a valid seed
// and can enforce HostCapabilityPortTokens. Configure it once at startup.
func (r *VMDResolver) WithPreviewTokens() *VMDResolver {
	r.previewTokens = true
	return r
}

// NewVMDResolver creates a Resolver that queries VMD at vmdAddr.
// Pass "" to use the default (127.0.0.1:9090).
func NewVMDResolver(vmdAddr string) *VMDResolver {
	if vmdAddr == "" {
		vmdAddr = defaultVMDAddr
	}
	return &VMDResolver{
		vmdAddr: vmdAddr,
		client:  &http.Client{Timeout: vmdRequestTimeout},
		cache:   make(map[string]cacheEntry),
	}
}

// Lookup returns current InstanceInfo for the given instanceID. Every
// non-overlapping successful lookup re-reads local VMD; only calls overlapping
// the same in-flight read share its result. Unknown IDs retain a short negative
// cache to absorb repeated probes.
func (r *VMDResolver) Lookup(ctx context.Context, instanceID string) (InstanceInfo, error) {
	epoch, negative := r.lookupEpoch(instanceID)
	if negative {
		return InstanceInfo{}, ErrInstanceNotFound
	}

	flightKey := instanceID + "\x00" + strconv.FormatUint(epoch, 10)
	v, err, _ := r.group.Do(flightKey, func() (any, error) {
		// A caller can miss the cache immediately before another in-flight fetch
		// records a 404. Re-check inside the singleflight call so that race does
		// not trigger a redundant VMD request.
		if r.negativeCached(instanceID) {
			return nil, ErrInstanceNotFound
		}
		return r.fetch(ctx, instanceID, epoch)
	})
	if err != nil {
		return InstanceInfo{}, err
	}
	return v.(InstanceInfo), nil
}

// Invalidate removes a cached miss and advances the lookup epoch. Future
// callers therefore cannot join an older in-flight request, and that older
// request cannot reinsert a stale negative result when it completes.
func (r *VMDResolver) Invalidate(instanceID string) {
	r.mu.Lock()
	delete(r.cache, instanceID)
	r.epoch++
	r.mu.Unlock()
}

// vmdResponse matches the JSON returned by VMD's local HTTP server.
type vmdResponse struct {
	VMIP                     string            `json:"vm_ip"`
	Status                   string            `json:"status"`
	StartedAt                int64             `json:"started_at"`
	TeamID                   string            `json:"team_id"`
	OwnerID                  string            `json:"owner_id"`
	PreviewAccess            string            `json:"preview_access"`
	PreviewPorts             map[string]bool   `json:"preview_ports"`
	PreviewPortAccess        map[string]string `json:"preview_port_access"`
	PreviewPortTokenVersions map[string]int64  `json:"preview_port_token_versions"`
}

func (r *VMDResolver) fetch(ctx context.Context, instanceID string, epoch uint64) (InstanceInfo, error) {
	u := fmt.Sprintf("%s/instances/%s", r.vmdAddr, url.PathEscape(instanceID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return InstanceInfo{}, fmt.Errorf("resolver: build request: %w", err)
	}
	req.Header.Set(preview.ProxyProtocolHeader, preview.HostCapabilityPorts)
	capabilities := preview.HostCapabilityPortAccess
	if r.previewTokens {
		capabilities += ", " + preview.HostCapabilityPortTokens
	}
	req.Header.Set(preview.ProxyCapabilitiesHeader, capabilities)

	resp, err := r.client.Do(req)
	if err != nil {
		return InstanceInfo{}, fmt.Errorf("resolver: vmd unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		r.storeNegative(instanceID, epoch)
		return InstanceInfo{}, ErrInstanceNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return InstanceInfo{}, fmt.Errorf("resolver: vmd returned %d for instance %s", resp.StatusCode, instanceID)
	}
	if got := resp.Header.Get(preview.VMDProtocolHeader); got != preview.HostCapabilityPorts {
		return InstanceInfo{}, fmt.Errorf("%w: %s=%q", ErrVMDPreviewProtocolUnsupported, preview.VMDProtocolHeader, got)
	}

	var raw vmdResponse
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return InstanceInfo{}, fmt.Errorf("resolver: decode response: %w", err)
	}

	info := InstanceInfo{
		VMIP: raw.VMIP, Status: raw.Status, StartedAt: raw.StartedAt,
		TeamID: raw.TeamID, OwnerID: raw.OwnerID,
		PreviewAccess:            raw.PreviewAccess,
		PreviewPorts:             decodePreviewPorts(raw.PreviewPorts),
		PreviewPortAccess:        decodePreviewPortAccess(raw.PreviewPorts, raw.PreviewPortAccess),
		PreviewPortTokenVersions: decodePreviewPortTokenVersions(raw.PreviewPorts, raw.PreviewPortTokenVersions),
	}
	return info, nil
}

func decodePreviewPortTokenVersions(published map[string]bool, raw map[string]int64) map[int]int64 {
	if len(published) == 0 || len(raw) == 0 {
		return nil
	}
	out := make(map[int]int64, len(raw))
	for key, version := range raw {
		port, err := strconv.Atoi(key)
		if err != nil || !published[key] || port < minProxiedPort || port > 65535 || version <= 0 {
			continue
		}
		out[port] = version
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func decodePreviewPortAccess(published map[string]bool, raw map[string]string) map[int]string {
	if len(published) == 0 || len(raw) == 0 {
		return nil
	}
	out := make(map[int]string, len(raw))
	for key, access := range raw {
		port, err := strconv.Atoi(key)
		if err != nil || !published[key] || port < minProxiedPort || port > 65535 {
			continue
		}
		out[port] = access
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func decodePreviewPorts(raw map[string]bool) map[int]struct{} {
	if len(raw) == 0 {
		return nil
	}
	out := make(map[int]struct{}, len(raw))
	for key, published := range raw {
		port, err := strconv.Atoi(key)
		if err != nil || !published || port < minProxiedPort || port > 65535 {
			continue
		}
		out[port] = struct{}{}
	}
	return out
}

func (r *VMDResolver) lookupEpoch(instanceID string) (uint64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.cache[instanceID]
	if !ok {
		return r.epoch, false
	}
	if time.Now().Before(entry.expiresAt) {
		return r.epoch, true
	}
	delete(r.cache, instanceID)
	return r.epoch, false
}

func (r *VMDResolver) negativeCached(instanceID string) bool {
	_, cached := r.lookupEpoch(instanceID)
	return cached
}

func (r *VMDResolver) storeNegative(instanceID string, epoch uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.epoch != epoch {
		return
	}
	if _, exists := r.cache[instanceID]; !exists && len(r.cache) >= maxCacheSize {
		r.evictRandom()
	}
	r.cache[instanceID] = cacheEntry{expiresAt: time.Now().Add(negativeCacheTTL)}
}

// evictRandom removes a random cache entry. O(1) under lock — Go's map
// iteration starts at a random bucket, so the first key is effectively random.
// Must be called with r.mu held.
func (r *VMDResolver) evictRandom() {
	for k := range r.cache {
		delete(r.cache, k)
		return
	}
}
