package api

import (
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const clientIPContextKey = "verified_client_ip"

func resolveClientIP(r *http.Request, forwardingRuleIP string) (string, bool) {
	remote := r.RemoteAddr
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}
	remoteIP := net.ParseIP(strings.TrimSpace(remote))
	if remoteIP == nil || forwardingRuleIP == "" {
		return remote, false
	}
	// Cloud Run's direct service hostname is not an LB ingress path and must
	// never be allowed to self-assert the forwarding-rule suffix. For
	// internal-and-cloud-load-balancing ingress, the documented marker that
	// the request was proxied by Google's Application Load Balancer is Via:
	// 1.1 google; the backend hop's RemoteAddr is not documented as private
	// for serverless NEGs.
	if strings.HasSuffix(strings.ToLower(r.Host), ".run.app") {
		return remote, false
	}
	if !strings.EqualFold(strings.TrimSpace(r.Header.Get("Via")), "1.1 google") {
		return remote, false
	}
	lb := net.ParseIP(strings.TrimSpace(forwardingRuleIP))
	if lb == nil {
		return remote, false
	}
	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	if len(parts) < 2 {
		return remote, false
	}
	client, terminal := net.ParseIP(strings.TrimSpace(parts[len(parts)-2])), net.ParseIP(strings.TrimSpace(parts[len(parts)-1]))
	if client == nil || terminal == nil || !terminal.Equal(lb) {
		return remote, false
	}
	return client.String(), true
}

func clientIP(c *gin.Context) string {
	if value, ok := c.Get(clientIPContextKey); ok {
		if ip, ok := value.(string); ok && ip != "" {
			return ip
		}
	}
	return ""
}

func verifiedClientIPMiddleware(forwardingRuleIP string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if ip, verified := resolveClientIP(c.Request, forwardingRuleIP); verified {
			c.Set(clientIPContextKey, ip)
		}
		c.Next()
	}
}
