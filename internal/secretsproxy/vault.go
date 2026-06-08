package secretsproxy

import (
	"context"
	"errors"
	"sync"
	"time"
)

// VaultClient fetches credential values for the daemon.
type VaultClient interface {
	FetchCredential(ctx context.Context, teamID, secretID string) (string, error)
}

// ErrCredentialRevoked indicates the secret has been soft-deleted or is no longer valid.
var ErrCredentialRevoked = errors.New("secretsproxy: credential revoked or not found")

// cachedVault wraps a VaultClient with a per-(team, secret) TTL cache.
type cachedVault struct {
	upstream VaultClient
	ttl      time.Duration
	now      func() time.Time

	mu      sync.Mutex
	entries map[cacheKey]cachedEntry
}

type cacheKey struct {
	teamID   string
	secretID string
}

type cachedEntry struct {
	value   string
	expires time.Time
}

// NewCachedVault wraps client with a TTL cache; ttl<=0 falls back to 60s.
func NewCachedVault(client VaultClient, ttl time.Duration) *cachedVault {
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	return &cachedVault{
		upstream: client,
		ttl:      ttl,
		now:      time.Now,
		entries:  make(map[cacheKey]cachedEntry),
	}
}

// FetchCredential returns the cached value when fresh, otherwise hits the upstream.
func (c *cachedVault) FetchCredential(ctx context.Context, teamID, secretID string) (string, error) {
	key := cacheKey{teamID: teamID, secretID: secretID}
	c.mu.Lock()
	if e, ok := c.entries[key]; ok && c.now().Before(e.expires) {
		c.mu.Unlock()
		return e.value, nil
	}
	c.mu.Unlock()

	v, err := c.upstream.FetchCredential(ctx, teamID, secretID)
	if err != nil {
		return "", err
	}

	c.mu.Lock()
	c.entries[key] = cachedEntry{value: v, expires: c.now().Add(c.ttl)}
	c.mu.Unlock()
	return v, nil
}

// Invalidate drops every cached entry for secretID across all teams.
func (c *cachedVault) Invalidate(secretID string) {
	c.mu.Lock()
	for k := range c.entries {
		if k.secretID == secretID {
			delete(c.entries, k)
		}
	}
	c.mu.Unlock()
}
