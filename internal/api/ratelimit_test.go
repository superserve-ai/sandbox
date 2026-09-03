package api

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestPreAuthLimiterUsesBoundedDegradedBucket(t *testing.T) {
	gin.SetMode(gin.TestMode)
	limiter := newKeyedRateLimiter(100, 2)
	for i := 0; i < 5000; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-API-Key", "invalid-key-"+string(rune(i)))
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = req
		if got := preAuthLimiterKey(c); got != "ip:unverified" {
			t.Fatalf("unverified key = %q, want degraded bucket", got)
		}
	}
	if got := len(limiter.entries); got != 0 {
		t.Fatalf("key derivation should not create entries directly: got %d", got)
	}

	// All invalid keys consume the same bucket and are eventually rejected.
	for i := 0; i < 10; i++ {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest("GET", "/", nil)
		c.Request.Header.Set("X-API-Key", "invalid-"+string(rune(i)))
		if enforceLimit(c, limiter.get(preAuthLimiterKey(c)), RateLimitConfig{Rate: 100, Burst: 2}) {
			if i >= 2 {
				t.Fatalf("request %d unexpectedly passed shared degraded bucket", i)
			}
		}
	}
	if got := len(limiter.entries); got != 1 {
		t.Fatalf("degraded limiter keys = %d, want 1", got)
	}
}

func TestTeamRateLimiterKeysRemainIndependent(t *testing.T) {
	limiter := newKeyedRateLimiter(100, 2)
	for _, team := range []string{"team-a", "team-b"} {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest("GET", "/", nil)
		c.Set("team_id", team)
		key := "team:" + team
		limiter.get(key)
	}
	if got := len(limiter.entries); got != 2 {
		t.Fatalf("team limiter keys = %d, want 2", got)
	}
}
