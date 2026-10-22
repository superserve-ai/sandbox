package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// With trusted proxies configured, a caller-prepended X-Forwarded-For entry
// must not change the address the rate limiter keys on.
func TestApplyTrustedProxiesIgnoresSpoofedForwardedFor(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	if err := ApplyTrustedProxies(r, "10.0.0.0/8, 192.0.2.10/32"); err != nil {
		t.Fatal(err)
	}
	r.GET("/", func(c *gin.Context) { c.String(http.StatusOK, c.ClientIP()) })

	for _, spoofed := range []string{"203.0.113.1", "203.0.113.2"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.1.2.3:4567"
		req.Header.Set("X-Forwarded-For", spoofed+", 198.51.100.7, 192.0.2.10")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if got := w.Body.String(); got != "198.51.100.7" {
			t.Errorf("spoofed %s: ClientIP = %q, want 198.51.100.7", spoofed, got)
		}
	}
}
