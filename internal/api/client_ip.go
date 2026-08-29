package api

import (
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const clientIPContextKey = "verified_client_ip"

func resolveClientIP(r *http.Request, forwardingRuleIP string) string {
	remote := r.RemoteAddr
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}
	remoteIP := net.ParseIP(strings.TrimSpace(remote))
	if remoteIP == nil || forwardingRuleIP == "" {
		return remote
	}
	// Only an internal transport peer may assert the load-balancer XFF
	// contract. A public peer can reach the service directly and forge a
	// syntactically valid forwarding-rule suffix.
	if !remoteIP.IsPrivate() {
		return remote
	}
	// Cloud Run's direct service hostname is not an LB ingress path and must
	// never be allowed to self-assert the forwarding-rule suffix.
	if strings.HasSuffix(strings.ToLower(r.Host), ".run.app") {
		return remote
	}
	lb := net.ParseIP(strings.TrimSpace(forwardingRuleIP))
	if lb == nil {
		return remote
	}
	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	if len(parts) < 2 {
		return remote
	}
	client, terminal := net.ParseIP(strings.TrimSpace(parts[len(parts)-2])), net.ParseIP(strings.TrimSpace(parts[len(parts)-1]))
	if client == nil || terminal == nil || !terminal.Equal(lb) {
		return remote
	}
	return client.String()
}

func clientIP(c *gin.Context) string {
	if value, ok := c.Get(clientIPContextKey); ok {
		if ip, ok := value.(string); ok && ip != "" {
			return ip
		}
	}
	return resolveClientIP(c.Request, "")
}

func verifiedClientIPMiddleware(forwardingRuleIP string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(clientIPContextKey, resolveClientIP(c.Request, forwardingRuleIP))
		c.Next()
	}
}
