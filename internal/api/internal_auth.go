package api

import (
	"crypto/subtle"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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

// PromotionProducerAuth uses credentials dedicated to the signup evidence producer.
func PromotionProducerAuth(envName string) gin.HandlerFunc {
	token := os.Getenv(envName)
	other := "PROMOTION_ACCOUNT_TOKEN"
	if envName == other {
		other = "PROMOTION_CAPTURE_TOKEN"
	}
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		provided := strings.TrimPrefix(auth, "Bearer ")
		otherToken := os.Getenv(other)
		internalToken := os.Getenv("INTERNAL_API_TOKEN")
		if token == "" || otherToken == "" || token == otherToken ||
			(token == internalToken && internalToken != "") ||
			provided == auth || provided == "" ||
			subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			respondErrorMsg(c, "unauthorized", "invalid promotion producer credential", http.StatusUnauthorized)
			c.Abort()
			return
		}
		c.Next()
	}
}

// InternalActorFromHeader records an actor UUID from the X-Actor-User-Id
// header when internal handlers need to attribute an action. The header is
// optional so read-only internal endpoints can continue to work without it.
func InternalActorFromHeader() gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := strings.TrimSpace(c.GetHeader("X-Actor-User-Id"))
		if raw != "" {
			if id, err := uuid.Parse(raw); err == nil {
				c.Set("actor_id", id)
			}
		}
		c.Next()
	}
}
