package api

import (
	"crypto/subtle"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

// OperatorAuth returns middleware that authenticates operator actions via a
// shared token in the Authorization header, read from OPERATOR_API_TOKEN.
// Unset rejects everything (fail-closed).
//
// This is deliberately a DIFFERENT credential from INTERNAL_API_TOKEN: the
// infra-internal token is provisioned onto every vmd host for heartbeats,
// so a host holding it could otherwise approve itself — POSTing its own
// activation the moment it self-registers, bypassing the provisioning
// review. The machines being operated must never hold the key that
// operates them.
func OperatorAuth() gin.HandlerFunc {
	token := os.Getenv("OPERATOR_API_TOKEN")

	return func(c *gin.Context) {
		if token == "" {
			respondErrorMsg(c, "unauthorized", "operator API not configured", http.StatusUnauthorized)
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
