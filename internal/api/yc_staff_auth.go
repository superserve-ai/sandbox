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

type ycStaffClaims struct {
	jwt.RegisteredClaims
	Operation     string `json:"operation"`
	Method        string `json:"method"`
	Path          string `json:"path"`
	BodySHA256    string `json:"body_sha256"`
	Provider      string `json:"provider"`
	EmailVerified bool   `json:"email_verified"`
}

// Console signs only after verifying the current Google login. This audience
// cannot be substituted with a promotion-account assertion or an actor header.
func YCStaffAuth() gin.HandlerFunc {
	key, err := base64.StdEncoding.DecodeString(os.Getenv("PROMOTION_ACCOUNT_PUBLIC_KEY"))
	configured := err == nil && len(key) == ed25519.PublicKeySize
	return func(c *gin.Context) {
		raw := c.GetHeader("X-YC-Staff-Assertion")
		c.Request.Header.Del("X-YC-Staff-Assertion")
		c.Request.Header.Del("X-Actor-User-Id")
		deny := func() {
			respondErrorMsg(c, "forbidden", "Verified staff session required.", http.StatusForbidden)
			c.Abort()
		}
		if !configured || raw == "" || len(raw) > promotionRequestLimit {
			deny()
			return
		}
		claims := new(ycStaffClaims)
		_, err := jwt.ParseWithClaims(raw, claims, func(*jwt.Token) (any, error) { return ed25519.PublicKey(key), nil },
			jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithIssuer("promotion-auth-adapter"), jwt.WithAudience("yc-staff"), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
		actor, actorErr := uuid.Parse(claims.Subject)
		op := "read"
		if c.Request.Method == http.MethodPost {
			op = "decision"
		}
		if err != nil || actorErr != nil || actor == uuid.Nil || claims.IssuedAt == nil || claims.ExpiresAt == nil ||
			!claims.ExpiresAt.After(claims.IssuedAt.Time) || claims.ExpiresAt.Sub(claims.IssuedAt.Time) > time.Minute ||
			len(claims.Audience) != 1 || claims.Audience[0] != "yc-staff" || claims.Provider != "google" || !claims.EmailVerified || claims.Operation != op ||
			claims.Method != c.Request.Method || claims.Path != c.Request.URL.RequestURI() {
			deny()
			return
		}
		body, err := io.ReadAll(io.LimitReader(c.Request.Body, promotionRequestLimit+1))
		if err != nil || len(body) > promotionRequestLimit {
			deny()
			return
		}
		digest := sha256.Sum256(body)
		if claims.BodySHA256 != hex.EncodeToString(digest[:]) {
			deny()
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(body))
		c.Set("actor_id", actor)
		c.Set("yc_staff_verified", true)
		c.Next()
	}
}

func (h *Handlers) requireYCStaff(c *gin.Context, permission string) (uuid.UUID, bool) {
	if !c.GetBool("yc_staff_verified") || actorIDFromContext(c) == nil {
		respondError(c, ErrForbidden)
		return uuid.Nil, false
	}
	return h.requirePlatformBilling(c, permission)
}
