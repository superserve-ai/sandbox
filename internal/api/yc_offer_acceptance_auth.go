package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type ycAcceptanceClaims struct {
	jwt.RegisteredClaims
	Operation  string `json:"operation"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	BodySHA256 string `json:"body_sha256"`
}

func YCOfferAcceptanceAuth(operation string) gin.HandlerFunc {
	key, err := base64.StdEncoding.DecodeString(os.Getenv("PROMOTION_ACCOUNT_PUBLIC_KEY"))
	configured := err == nil && len(key) == ed25519.PublicKeySize
	return func(c *gin.Context) {
		c.Header("Cache-Control", "private, no-store")
		assertion := c.GetHeader("X-YC-Acceptance-Assertion")
		c.Request.Header.Del("X-YC-Acceptance-Assertion")
		c.Request.Header.Del("X-Actor-User-Id")
		deny := func() {
			respondErrorMsg(c, "forbidden", "Verified account session required.", http.StatusForbidden)
			c.Abort()
		}
		if !configured || len(assertion) == 0 || len(assertion) > promotionRequestLimit {
			deny()
			return
		}
		claims := new(ycAcceptanceClaims)
		_, err := jwt.ParseWithClaims(assertion, claims, func(*jwt.Token) (any, error) { return ed25519.PublicKey(key), nil }, jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithIssuer("promotion-auth-adapter"), jwt.WithAudience("yc-acceptance"), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
		actor, actorErr := uuid.Parse(claims.Subject)
		if err != nil || actorErr != nil || actor == uuid.Nil || claims.IssuedAt == nil || claims.ExpiresAt == nil || !claims.ExpiresAt.After(claims.IssuedAt.Time) || claims.ExpiresAt.Sub(claims.IssuedAt.Time) > time.Minute || len(claims.Audience) != 1 || claims.Audience[0] != "yc-acceptance" || claims.Operation != operation || claims.Method != c.Request.Method || claims.Path != c.Request.URL.RequestURI() {
			deny()
			return
		}
		body, err := io.ReadAll(io.LimitReader(c.Request.Body, promotionRequestLimit+1))
		if err != nil || len(body) > promotionRequestLimit {
			deny()
			return
		}
		hash := sha256.Sum256(body)
		if claims.BodySHA256 != hex.EncodeToString(hash[:]) {
			deny()
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(body))
		c.Set("actor_id", actor)
		c.Set("yc_acceptance_verified", true)
		c.Next()
	}
}
