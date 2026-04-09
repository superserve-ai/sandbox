package api

import (
	"context"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// RateLimitConfig defines rate limiting parameters for a token-bucket limiter.
type RateLimitConfig struct {
	// Rate is the number of requests per second allowed per key.
	Rate float64
	// Burst is the maximum number of requests allowed in a burst.
	Burst int
	// CleanupInterval is how often stale entries are removed.
	CleanupInterval time.Duration
	// MaxAge is how long an idle entry is kept before cleanup.
	MaxAge time.Duration
}

// DefaultIPRateLimitConfig is the global per-IP limit applied before auth.
// It exists mainly to blunt unauthenticated floods; legitimate customers hit
// the per-team limit long before this.
func DefaultIPRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		Rate:            50,
		Burst:           100,
		CleanupInterval: 5 * time.Minute,
		MaxAge:          10 * time.Minute,
	}
}

// DefaultTeamRateLimitConfig is the per-team limit applied after auth.
// This is the real fairness mechanism — each authenticated team gets its
// own bucket regardless of how many requests share an IP.
func DefaultTeamRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		Rate:            20,
		Burst:           40,
		CleanupInterval: 5 * time.Minute,
		MaxAge:          10 * time.Minute,
	}
}

type limiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// keyedRateLimiter is a map of token-bucket limiters keyed by an arbitrary
// string (IP address, team ID, API key ID, etc.). It is safe for concurrent
// use. Stale entries are removed by a background cleanup goroutine started
// by RateLimit / TeamRateLimit.
type keyedRateLimiter struct {
	mu      sync.Mutex
	entries map[string]*limiterEntry
	rate    rate.Limit
	burst   int
}

func newKeyedRateLimiter(r float64, burst int) *keyedRateLimiter {
	return &keyedRateLimiter{
		entries: make(map[string]*limiterEntry),
		rate:    rate.Limit(r),
		burst:   burst,
	}
}

func (l *keyedRateLimiter) get(key string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry, ok := l.entries[key]
	if !ok {
		entry = &limiterEntry{
			limiter: rate.NewLimiter(l.rate, l.burst),
		}
		l.entries[key] = entry
	}
	entry.lastSeen = time.Now()
	return entry.limiter
}

func (l *keyedRateLimiter) cleanup(maxAge time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for key, entry := range l.entries {
		if entry.lastSeen.Before(cutoff) {
			delete(l.entries, key)
		}
	}
}

// startCleanup runs a ticker-driven cleanup loop that exits when ctx is done.
func (l *keyedRateLimiter) startCleanup(ctx context.Context, cfg RateLimitConfig) {
	go func() {
		ticker := time.NewTicker(cfg.CleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				l.cleanup(cfg.MaxAge)
			}
		}
	}()
}

// enforce applies the limiter to the current request and writes RateLimit-*
// headers. Returns true if the request should proceed, false if it was
// aborted with a 429.
func enforceLimit(c *gin.Context, l *rate.Limiter, cfg RateLimitConfig) bool {
	r := l.Reserve()
	if !r.OK() {
		c.Header("Retry-After", "1")
		c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
			"error": gin.H{
				"code":    "rate_limited",
				"message": "Rate limit exceeded. Please retry later.",
			},
		})
		return false
	}

	delay := r.Delay()
	if delay > 0 {
		// Bucket is empty — cancel the reservation and reject.
		r.Cancel()
		retryAfter := int(math.Ceil(delay.Seconds()))
		if retryAfter < 1 {
			retryAfter = 1
		}
		c.Header("RateLimit-Limit", strconv.Itoa(cfg.Burst))
		c.Header("RateLimit-Remaining", "0")
		c.Header("RateLimit-Reset", strconv.Itoa(retryAfter))
		c.Header("Retry-After", strconv.Itoa(retryAfter))
		c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
			"error": gin.H{
				"code":    "rate_limited",
				"message": "Rate limit exceeded. Please retry later.",
			},
		})
		return false
	}

	// Token acquired — emit informational headers.
	c.Header("RateLimit-Limit", strconv.Itoa(cfg.Burst))
	remaining := int(l.Tokens())
	if remaining < 0 {
		remaining = 0
	}
	c.Header("RateLimit-Remaining", strconv.Itoa(remaining))
	// Reset = seconds until the bucket is fully replenished from empty.
	resetSeconds := int(math.Ceil(float64(cfg.Burst-remaining) / cfg.Rate))
	if resetSeconds < 1 {
		resetSeconds = 1
	}
	c.Header("RateLimit-Reset", strconv.Itoa(resetSeconds))
	return true
}

// RateLimit returns a Gin middleware that enforces per-IP rate limiting
// globally (including unauthenticated requests). It's a coarse first line of
// defense against flood attacks — the real per-customer fairness comes from
// TeamRateLimit applied after authentication.
//
// The supplied context controls the background cleanup goroutine: when ctx
// is cancelled, the cleanup loop exits so the limiter does not leak. Tests
// that build many routers should pass a per-test context so goroutines
// don't accumulate across runs.
func RateLimit(ctx context.Context, cfg RateLimitConfig) gin.HandlerFunc {
	limiter := newKeyedRateLimiter(cfg.Rate, cfg.Burst)
	limiter.startCleanup(ctx, cfg)

	return func(c *gin.Context) {
		key := c.ClientIP()
		if enforceLimit(c, limiter.get(key), cfg) {
			c.Next()
		}
	}
}

// TeamRateLimit returns a Gin middleware that enforces per-team rate limiting.
// Must be registered AFTER APIKeyAuth so the team_id context value is set.
//
// Behind a load balancer, per-IP rate limiting collapses many tenants onto a
// single bucket (since X-Forwarded-For can resolve to the same edge IP). This
// middleware keyes on team_id so each authenticated customer gets a dedicated
// bucket regardless of source IP.
//
// If team_id is not set on the context (should not happen post-auth) the
// request falls back to per-IP to avoid silently disabling rate limiting.
func TeamRateLimit(ctx context.Context, cfg RateLimitConfig) gin.HandlerFunc {
	limiter := newKeyedRateLimiter(cfg.Rate, cfg.Burst)
	limiter.startCleanup(ctx, cfg)

	return func(c *gin.Context) {
		var key string
		if v, ok := c.Get("team_id"); ok {
			if s, ok := v.(string); ok && s != "" {
				key = "team:" + s
			}
		}
		if key == "" {
			key = "ip:" + c.ClientIP()
		}
		if enforceLimit(c, limiter.get(key), cfg) {
			c.Next()
		}
	}
}
