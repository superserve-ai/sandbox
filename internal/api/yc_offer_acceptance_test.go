package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestYCAcceptanceAssertionIsBoundToActorAndRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	t.Setenv("PROMOTION_ACCOUNT_PUBLIC_KEY", base64.StdEncoding.EncodeToString(pub))
	actor := uuid.New()
	path := "/internal/yc/account/offers/accept"
	body := `{"claim_id":"` + uuid.NewString() + `"}`
	hash := sha256.Sum256([]byte(body))
	route := gin.New()
	route.POST(path, YCOfferAcceptanceAuth("accept"), func(c *gin.Context) {
		if id := actorIDFromContext(c); id == nil || *id != actor || c.GetHeader("X-Actor-User-Id") != "" {
			t.Error("actor was not exclusively signature-derived")
		}
		c.Status(204)
	})
	for _, tc := range []struct {
		name     string
		change   func(*ycAcceptanceClaims)
		body     string
		unsigned bool
		want     int
	}{
		{name: "ordinary verified account", want: 204},
		{name: "header spoof", unsigned: true, want: 403},
		{name: "staff assertion", change: func(c *ycAcceptanceClaims) { c.Audience = jwt.ClaimStrings{"yc-staff"} }, want: 403},
		{name: "mixed audience", change: func(c *ycAcceptanceClaims) { c.Audience = jwt.ClaimStrings{"yc-acceptance", "promotion-account"} }, want: 403},
		{name: "read used for accept", change: func(c *ycAcceptanceClaims) { c.Operation = "offer" }, want: 403},
		{name: "different endpoint", change: func(c *ycAcceptanceClaims) { c.Path = path + "?team=other" }, want: 403},
		{name: "changed request", body: `{"claim_id":"` + uuid.NewString() + `"}`, want: 403},
		{name: "long lived", change: func(c *ycAcceptanceClaims) { c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(2 * time.Minute)) }, want: 403},
		{name: "expired", change: func(c *ycAcceptanceClaims) {
			c.IssuedAt = jwt.NewNumericDate(time.Now().Add(-2 * time.Minute))
			c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Minute))
		}, want: 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := ycAcceptanceClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: "promotion-auth-adapter", Subject: actor.String(), Audience: jwt.ClaimStrings{"yc-acceptance"}, IssuedAt: jwt.NewNumericDate(time.Now()), ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute))}, Operation: "accept", Method: "POST", Path: path, BodySHA256: hex.EncodeToString(hash[:])}
			if tc.change != nil {
				tc.change(&claims)
			}
			payload := body
			if tc.body != "" {
				payload = tc.body
			}
			req := httptest.NewRequest("POST", path, strings.NewReader(payload))
			req.Header.Set("X-Actor-User-Id", uuid.NewString())
			if !tc.unsigned {
				signed, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(key)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("X-YC-Acceptance-Assertion", signed)
			}
			response := httptest.NewRecorder()
			route.ServeHTTP(response, req)
			if response.Code != tc.want {
				t.Fatalf("got %d want %d: %s", response.Code, tc.want, response.Body.String())
			}
		})
	}
}
