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
)

// ErrInstanceNotFound is returned when the resolver has no record of the instance.
var ErrInstanceNotFound = errors.New("proxy: instance not found")

// InstanceInfo holds the routing information for a sandbox instance.
type InstanceInfo struct {
	VMIP      string
	Status    string
	StartedAt int64 // Unix nanoseconds; changes on restart — used as transport lifecycle key
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
	defaultCacheTTL  = 500 * time.Millisecond // VMD is on localhost, latency is negligible
	negativeCacheTTL = 1 * time.Second        // cache "not found" slightly longer to absorb spam
	maxCacheSize     = 10_000                  // cap against random instance ID amplification
)

type cacheEntry struct {
	info      InstanceInfo
	err       error // non-nil for negative cache entries
	expiresAt time.Time
}

// VMDResolver looks up instanceID → vmIP by querying VMD's local HTTP server.
// Results are cached briefly to absorb request bursts to the same sandbox.
// Negative results are also cached to prevent VMD amplification from unknown IDs.
type VMDResolver struct {
	vmdAddr string
	ttl     time.Duration
	client  *http.Client

	mu    sync.Mutex
	cache map[string]cacheEntry
}

// NewVMDResolver creates a Resolver that queries VMD at vmdAddr.
// Pass "" to use the default (127.0.0.1:9090).
func NewVMDResolver(vmdAddr string) *VMDResolver {
	if vmdAddr == "" {
		vmdAddr = defaultVMDAddr
	}
	return &VMDResolver{
		vmdAddr: vmdAddr,
		ttl:     defaultCacheTTL,
		client:  &http.Client{Timeout: 2 * time.Second},
		cache:   make(map[string]cacheEntry),
	}
}

// Lookup returns InstanceInfo for the given instanceID.
func (r *VMDResolver) Lookup(ctx context.Context, instanceID string) (InstanceInfo, error) {
	r.mu.Lock()
	if e, ok := r.cache[instanceID]; ok && time.Now().Before(e.expiresAt) {
		r.mu.Unlock()
		return e.info, e.err
	}
	r.mu.Unlock()

	return r.fetch(ctx, instanceID)
}

// Invalidate removes an instance from the cache so the next Lookup goes to VMD.
func (r *VMDResolver) Invalidate(instanceID string) {
	r.mu.Lock()
	delete(r.cache, instanceID)
	r.mu.Unlock()
}

// vmdResponse matches the JSON returned by VMD's local HTTP server.
type vmdResponse struct {
	VMIP      string `json:"vm_ip"`
	Status    string `json:"status"`
	StartedAt int64  `json:"started_at"`
}

func (r *VMDResolver) fetch(ctx context.Context, instanceID string) (InstanceInfo, error) {
	u := fmt.Sprintf("%s/instances/%s", r.vmdAddr, url.PathEscape(instanceID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return InstanceInfo{}, fmt.Errorf("resolver: build request: %w", err)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return InstanceInfo{}, fmt.Errorf("resolver: vmd unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		r.store(instanceID, InstanceInfo{}, ErrInstanceNotFound, negativeCacheTTL)
		return InstanceInfo{}, ErrInstanceNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return InstanceInfo{}, fmt.Errorf("resolver: vmd returned %d for instance %s", resp.StatusCode, instanceID)
	}

	var raw vmdResponse
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return InstanceInfo{}, fmt.Errorf("resolver: decode response: %w", err)
	}

	info := InstanceInfo{VMIP: raw.VMIP, Status: raw.Status, StartedAt: raw.StartedAt}
	r.store(instanceID, info, nil, r.ttl)
	return info, nil
}

func (r *VMDResolver) store(instanceID string, info InstanceInfo, err error, ttl time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.cache) >= maxCacheSize {
		r.cache = make(map[string]cacheEntry)
	}
	r.cache[instanceID] = cacheEntry{info: info, err: err, expiresAt: time.Now().Add(ttl)}
}
