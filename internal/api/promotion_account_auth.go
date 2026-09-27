package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type promotionAccountClaims struct {
	jwt.RegisteredClaims
	Operation            string `json:"operation"`
	AttemptID            string `json:"attempt_id,omitempty"`
	TeamID               string `json:"team_id,omitempty"`
	HomeRegion           string `json:"home_region,omitempty"`
	AuthorityUnavailable *bool  `json:"authority_unavailable,omitempty"`
}

// PromotionAccountAuth verifies Console's server-derived assertions. Console
// verifies the existing Auth login for evidence/register; bind instead uses
// trusted signup provenance, which is available before email confirmation.
func PromotionAccountAuth() gin.HandlerFunc {
	key, err := base64.StdEncoding.DecodeString(os.Getenv("PROMOTION_ACCOUNT_PUBLIC_KEY"))
	configured := err == nil && len(key) == ed25519.PublicKeySize
	return func(c *gin.Context) {
		raw := c.GetHeader("X-Promotion-Account-Assertion")
		c.Request.Header.Del("X-Promotion-Account-Assertion")
		deny := func() {
			respondErrorMsg(c, "forbidden", "account provenance mismatch", http.StatusForbidden)
			c.Abort()
		}
		if !configured || raw == "" || len(raw) > promotionRequestLimit {
			deny()
			return
		}
		claims := new(promotionAccountClaims)
		_, err := jwt.ParseWithClaims(raw, claims, func(*jwt.Token) (any, error) {
			return ed25519.PublicKey(key), nil
		}, jwt.WithValidMethods([]string{"EdDSA"}),
			jwt.WithIssuer("promotion-auth-adapter"), jwt.WithAudience("promotion-account"),
			jwt.WithExpirationRequired(), jwt.WithIssuedAt())
		actor, actorErr := uuid.Parse(claims.Subject)
		operation := strings.TrimPrefix(c.FullPath(), "/internal/promotion/account/")
		if err != nil || actorErr != nil || actor == uuid.Nil ||
			claims.IssuedAt == nil || claims.ExpiresAt == nil ||
			!claims.ExpiresAt.After(claims.IssuedAt.Time) ||
			claims.ExpiresAt.Sub(claims.IssuedAt.Time) > 5*time.Minute ||
			claims.Operation != operation {
			deny()
			return
		}
		switch operation {
		case "bind":
			attempt, err := uuid.Parse(claims.AttemptID)
			if err != nil || attempt == uuid.Nil {
				deny()
				return
			}
		case "create-team":
			region := sandboxIDRegionFromEnv()
			if region == "" {
				// East predates tagged sandbox IDs and remains the team default.
				region = "use"
			}
			attempt, attemptErr := uuid.Parse(claims.AttemptID)
			team, teamErr := uuid.Parse(claims.TeamID)
			if attemptErr != nil || attempt == uuid.Nil || teamErr != nil || team == uuid.Nil ||
				claims.AuthorityUnavailable == nil || claims.HomeRegion == "" ||
				claims.HomeRegion != region {
				deny()
				return
			}
		case "evidence", "register", "signup-eligibility":
			if claims.AttemptID != "" {
				deny()
				return
			}
		default:
			deny()
			return
		}
		c.Set("promotion_account", claims)
		c.Next()
	}
}
