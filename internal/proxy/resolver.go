package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

const (
	defaultVMDAddr  = "http://localhost:9090"
	defaultCacheTTL = 5 * time.Second
)

// ErrInstanceNotFound is returned when VMD has no record of the instance.
var ErrInstanceNotFound = errors.New("proxy: instance not found")

// InstanceInfo is what the resolver returns for a given instance.
type InstanceInfo struct {
	VMIP      string
	Status    string
	StartedAt int64 // Unix nanoseconds; changes when the sandbox restarts — used as a lifecycle key
}

// lifecycleKey returns a string that is stable for the lifetime of one VM boot.
// The proxy uses it to detect when a sandbox was replaced and old transports must be closed.
func (i InstanceInfo) lifecycleKey() string {
	return fmt.Sprintf("%d", i.StartedAt)
}

type cacheEntry struct {
	info      InstanceInfo
	expiresAt time.Time
}

// Resolver looks up instanceID → vmIP by querying VMD's local HTTP server.
// Results are cached with a short TTL to avoid a VMD call on every request.
type Resolver struct {
	vmdAddr string
	ttl     time.Duration
	client  *http.Client

	mu    sync.Mutex
	cache map[string]cacheEntry
}

// NewResolver creates a Resolver that queries VMD at vmdAddr.
// Pass "" to use the default (localhost:9090).
func NewResolver(vmdAddr string) *Resolver {
	if vmdAddr == "" {
		vmdAddr = defaultVMDAddr
	}
	return &Resolver{
		vmdAddr: vmdAddr,
		ttl:     defaultCacheTTL,
		client:  &http.Client{Timeout: 2 * time.Second},
		cache:   make(map[string]cacheEntry),
	}
}

// Lookup returns InstanceInfo for the given instanceID.
// Hits cache first; falls through to VMD if stale or missing.
func (r *Resolver) Lookup(ctx context.Context, instanceID string) (InstanceInfo, error) {
	r.mu.Lock()
	if e, ok := r.cache[instanceID]; ok && time.Now().Before(e.expiresAt) {
		r.mu.Unlock()
		return e.info, nil
	}
	r.mu.Unlock()

	return r.fetch(ctx, instanceID)
}

// Invalidate removes an instance from the cache so the next Lookup goes to VMD.
// Called when an upstream request fails, in case the sandbox has moved.
func (r *Resolver) Invalidate(instanceID string) {
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

func (r *Resolver) fetch(ctx context.Context, instanceID string) (InstanceInfo, error) {
	url := fmt.Sprintf("%s/instances/%s", r.vmdAddr, instanceID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return InstanceInfo{}, fmt.Errorf("resolver: build request: %w", err)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return InstanceInfo{}, fmt.Errorf("resolver: vmd unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return InstanceInfo{}, ErrInstanceNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return InstanceInfo{}, fmt.Errorf("resolver: vmd returned %d for instance %s", resp.StatusCode, instanceID)
	}

	var raw vmdResponse
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return InstanceInfo{}, fmt.Errorf("resolver: decode response: %w", err)
	}

	info := InstanceInfo{
		VMIP:      raw.VMIP,
		Status:    raw.Status,
		StartedAt: raw.StartedAt,
	}

	r.mu.Lock()
	r.cache[instanceID] = cacheEntry{info: info, expiresAt: time.Now().Add(r.ttl)}
	r.mu.Unlock()

	return info, nil
}
