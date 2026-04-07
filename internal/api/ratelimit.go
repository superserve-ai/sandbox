package api

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// RateLimitConfig defines rate limiting parameters.
type RateLimitConfig struct {
	// Rate is the number of requests per second allowed per IP.
	Rate float64
	// Burst is the maximum number of requests allowed in a burst.
	Burst int
	// CleanupInterval is how often stale entries are removed.
	CleanupInterval time.Duration
	// MaxAge is how long an idle entry is kept before cleanup.
	MaxAge time.Duration
}

// DefaultRateLimitConfig returns sensible defaults for API rate limiting.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		Rate:            20,
		Burst:           40,
		CleanupInterval: 5 * time.Minute,
		MaxAge:          10 * time.Minute,
	}
}

type ipEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type ipRateLimiter struct {
	mu      sync.Mutex
	entries map[string]*ipEntry
	rate    rate.Limit
	burst   int
}

func newIPRateLimiter(r float64, burst int) *ipRateLimiter {
	return &ipRateLimiter{
		entries: make(map[string]*ipEntry),
		rate:    rate.Limit(r),
		burst:   burst,
	}
}

func (l *ipRateLimiter) get(ip string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry, ok := l.entries[ip]
	if !ok {
		entry = &ipEntry{
			limiter: rate.NewLimiter(l.rate, l.burst),
		}
		l.entries[ip] = entry
	}
	entry.lastSeen = time.Now()
	return entry.limiter
}

func (l *ipRateLimiter) cleanup(maxAge time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for ip, entry := range l.entries {
		if entry.lastSeen.Before(cutoff) {
			delete(l.entries, ip)
		}
	}
}

// RateLimit returns a Gin middleware that enforces per-IP rate limiting
// using a token bucket algorithm. Returns standard rate limit headers
// and 429 Too Many Requests when the limit is exceeded.
//
// The supplied context controls the background cleanup goroutine: when ctx
// is cancelled, the cleanup loop exits so the limiter does not leak. Tests
// that build many routers should pass a per-test context so goroutines
// don't accumulate across runs.
func RateLimit(ctx context.Context, cfg RateLimitConfig) gin.HandlerFunc {
	limiter := newIPRateLimiter(cfg.Rate, cfg.Burst)

	// Background cleanup of stale entries — exits cleanly on ctx.Done.
	go func() {
		ticker := time.NewTicker(cfg.CleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				limiter.cleanup(cfg.MaxAge)
			}
		}
	}()

	return func(c *gin.Context) {
		ip := c.ClientIP()
		l := limiter.get(ip)

		// Reserve a token to get timing info for headers.
		r := l.Reserve()
		if !r.OK() {
			c.Header("Retry-After", "1")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": gin.H{
					"code":    "rate_limited",
					"message": "Rate limit exceeded. Please retry later.",
				},
			})
			return
		}

		delay := r.Delay()
		if delay > 0 {
			// Token not immediately available — rate exceeded.
			r.Cancel()
			retryAfter := int(delay.Seconds()) + 1
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
			return
		}

		// Token acquired — set informational headers.
		c.Header("RateLimit-Limit", strconv.Itoa(cfg.Burst))
		remaining := int(l.Tokens())
		if remaining < 0 {
			remaining = 0
		}
		c.Header("RateLimit-Remaining", strconv.Itoa(remaining))
		c.Header("RateLimit-Reset", "1")

		c.Next()
	}
}
