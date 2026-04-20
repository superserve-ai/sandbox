package api

import (
	"crypto/subtle"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

// InternalAuth returns middleware that authenticates internal API requests
// via a shared token in the Authorization header. The expected token is
// read from the INTERNAL_API_TOKEN env var. If the env var is unset, all
// requests are rejected (fail-closed).
func InternalAuth() gin.HandlerFunc {
	token := os.Getenv("INTERNAL_API_TOKEN")

	return func(c *gin.Context) {
		if token == "" {
			respondErrorMsg(c, "unauthorized", "internal API not configured", http.StatusUnauthorized)
			c.Abort()
			return
		}

		auth := c.GetHeader("Authorization")
		provided := strings.TrimPrefix(auth, "Bearer ")
		if provided == auth || provided == "" {
			respondErrorMsg(c, "unauthorized", "missing or invalid Authorization header", http.StatusUnauthorized)
			c.Abort()
			return
		}

		if subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			respondErrorMsg(c, "unauthorized", "invalid token", http.StatusUnauthorized)
			c.Abort()
			return
		}

		c.Next()
	}
}
