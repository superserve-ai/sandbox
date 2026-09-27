package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestPromotionAccountAssertions(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PROMOTION_ACCOUNT_PUBLIC_KEY", base64.StdEncoding.EncodeToString(public))
	t.Setenv("PROMOTION_CAPTURE_TOKEN", "capture-example-token")
	t.Setenv("PROMOTION_ACCOUNT_TOKEN", "account-example-token")
	t.Setenv("INTERNAL_API_TOKEN", "internal-example-token")
	user, otherUser, attempt := uuid.New(), uuid.New(), uuid.New()
	now := time.Now()
	for _, operation := range []string{"bind", "evidence", "register", "signup-eligibility"} {
		t.Run(operation, func(t *testing.T) {
			for _, tc := range []struct {
				name   string
				mutate func(*promotionAccountClaims, *promotionAccountRequest)
				status int
			}{
				{"valid", nil, http.StatusServiceUnavailable},
				{"missing assertion", func(_ *promotionAccountClaims, body *promotionAccountRequest) { body.UserID = otherUser }, http.StatusForbidden},
				{"unsigned assertion", func(c *promotionAccountClaims, body *promotionAccountRequest) {
					c.Subject = otherUser.String()
					body.UserID = otherUser
				}, http.StatusForbidden},
				{"wrong signing key", nil, http.StatusForbidden},
				{"wrong algorithm", nil, http.StatusForbidden},
				{"missing producer token", nil, http.StatusUnauthorized},
				{"capture token", nil, http.StatusUnauthorized},
				{"missing actor", nil, http.StatusForbidden},
				{"invalid actor", nil, http.StatusForbidden},
				{"wrong actor", nil, http.StatusForbidden},
				{"wrong account", func(_ *promotionAccountClaims, body *promotionAccountRequest) { body.UserID = otherUser }, http.StatusForbidden},
				{"expired", func(c *promotionAccountClaims, _ *promotionAccountRequest) {
					c.IssuedAt = jwt.NewNumericDate(now.Add(-2 * time.Minute))
					c.ExpiresAt = jwt.NewNumericDate(now.Add(-time.Minute))
				}, http.StatusForbidden},
				{"missing expiry", func(c *promotionAccountClaims, _ *promotionAccountRequest) { c.ExpiresAt = nil }, http.StatusForbidden},
				{"missing issued time", func(c *promotionAccountClaims, _ *promotionAccountRequest) { c.IssuedAt = nil }, http.StatusForbidden},
				{"future issued time", func(c *promotionAccountClaims, _ *promotionAccountRequest) {
					c.IssuedAt = jwt.NewNumericDate(now.Add(time.Minute))
				}, http.StatusForbidden},
				{"long lifetime", func(c *promotionAccountClaims, _ *promotionAccountRequest) {
					c.ExpiresAt = jwt.NewNumericDate(now.Add(time.Hour))
				}, http.StatusForbidden},
				{"wrong issuer", func(c *promotionAccountClaims, _ *promotionAccountRequest) { c.Issuer = "tenant" }, http.StatusForbidden},
				{"wrong audience", func(c *promotionAccountClaims, _ *promotionAccountRequest) { c.Audience = jwt.ClaimStrings{"tenant"} }, http.StatusForbidden},
				{"wrong operation", func(c *promotionAccountClaims, _ *promotionAccountRequest) {
					if operation == "bind" {
						c.Operation = "evidence"
						c.AttemptID = ""
					} else {
						c.Operation = "bind"
						c.AttemptID = attempt.String()
					}
				}, http.StatusForbidden},
				{"missing subject", func(c *promotionAccountClaims, _ *promotionAccountRequest) { c.Subject = "" }, http.StatusForbidden},
				{"nil subject", func(c *promotionAccountClaims, _ *promotionAccountRequest) { c.Subject = uuid.Nil.String() }, http.StatusForbidden},
				{"wrong attempt", func(c *promotionAccountClaims, _ *promotionAccountRequest) { c.AttemptID = uuid.NewString() }, http.StatusForbidden},
			} {
				t.Run(tc.name, func(t *testing.T) {
					claims := promotionAccountClaims{
						RegisteredClaims: jwt.RegisteredClaims{
							Issuer: "promotion-auth-adapter", Audience: jwt.ClaimStrings{"promotion-account"},
							Subject: user.String(), IssuedAt: jwt.NewNumericDate(now.Add(-time.Second)),
							ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
						},
						Operation: operation,
					}
					body := promotionAccountRequest{UserID: user}
					if operation == "bind" {
						claims.AttemptID = attempt.String()
						body.AttemptID = attempt
					}
					if tc.mutate != nil {
						tc.mutate(&claims, &body)
					}
					var key any = private
					var method jwt.SigningMethod = jwt.SigningMethodEdDSA
					if tc.name == "wrong signing key" {
						key = otherPrivate
					}
					if tc.name == "wrong algorithm" {
						method, key = jwt.SigningMethodHS256, []byte("account-example-token")
					}
					if tc.name == "unsigned assertion" {
						method, key = jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType
					}
					assertion, err := jwt.NewWithClaims(method, claims).SignedString(key)
					if err != nil {
						t.Fatal(err)
					}
					payload, err := json.Marshal(body)
					if err != nil {
						t.Fatal(err)
					}
					h := new(Handlers)
					r := gin.New()
					account := r.Group("/internal/promotion/account", PromotionProducerAuth("PROMOTION_ACCOUNT_TOKEN"), PromotionAccountAuth())
					account.POST("/bind", h.BindPromotionSignupAccount)
					account.POST("/evidence", h.GetPromotionSignupAccountEvidence)
					account.POST("/register", h.RegisterPromotionSignupDevice)
					account.POST("/signup-eligibility", h.EvaluateSignupPromotion)
					req := httptest.NewRequest(http.MethodPost, "/internal/promotion/account/"+operation, strings.NewReader(string(payload)))
					// Matching caller-controlled fields must not override signed identity.
					req.Header.Set("X-Actor-User-Id", body.UserID.String())
					switch tc.name {
					case "missing actor":
						req.Header.Del("X-Actor-User-Id")
					case "invalid actor":
						req.Header.Set("X-Actor-User-Id", "invalid")
					case "wrong actor":
						req.Header.Set("X-Actor-User-Id", otherUser.String())
					}
					if tc.name != "missing producer token" {
						req.Header.Set("Authorization", "Bearer account-example-token")
					}
					if tc.name == "capture token" {
						req.Header.Set("Authorization", "Bearer capture-example-token")
					}
					if tc.name != "missing assertion" {
						req.Header.Set("X-Promotion-Account-Assertion", assertion)
					}
					w := httptest.NewRecorder()
					r.ServeHTTP(w, req)
					// Only valid provenance may reach the unavailable database.
					if w.Code != tc.status {
						t.Fatalf("got %d, want %d: %s", w.Code, tc.status, w.Body.String())
					}
				})
			}
		})
	}
}

func TestPromotionAccountAssertionKeyRequired(t *testing.T) {
	for _, key := range []string{"", "invalid", base64.StdEncoding.EncodeToString(make([]byte, 31))} {
		t.Run(key, func(t *testing.T) {
			t.Setenv("PROMOTION_ACCOUNT_PUBLIC_KEY", key)
			r := gin.New()
			r.POST("/internal/promotion/account/evidence", PromotionAccountAuth(), func(c *gin.Context) { c.Status(http.StatusNoContent) })
			req := httptest.NewRequest(http.MethodPost, "/internal/promotion/account/evidence", nil)
			req.Header.Set("X-Promotion-Account-Assertion", "invalid")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != http.StatusForbidden {
				t.Fatalf("got %d, want %d", w.Code, http.StatusForbidden)
			}
		})
	}
}
