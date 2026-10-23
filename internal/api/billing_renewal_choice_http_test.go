package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func renewalHTTPAssertion(t *testing.T, key ed25519.PrivateKey, actor uuid.UUID, path, body string, change func(*renewalChoiceClaims)) string {
	t.Helper()
	now := time.Now()
	hash := sha256.Sum256([]byte(body))
	c := renewalChoiceClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: "promotion-auth-adapter", Subject: actor.String(), Audience: jwt.ClaimStrings{"yc-renewal"}, IssuedAt: jwt.NewNumericDate(now.Add(-time.Second)), ExpiresAt: jwt.NewNumericDate(now.Add(30 * time.Second))}, Operation: "status", Method: http.MethodPost, Path: path, BodySHA256: hex.EncodeToString(hash[:])}
	if change != nil {
		change(&c)
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, c).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestRenewalChoiceHTTPAssertionScope(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PROMOTION_ACCOUNT_PUBLIC_KEY", base64.StdEncoding.EncodeToString(pub))
	actor := uuid.New()
	path := "/internal/yc/account/renewals/status"
	body := `{}`
	tests := []struct {
		name               string
		change             func(*renewalChoiceClaims)
		wireBody, wirePath string
		status             int
	}{
		{name: "customer", status: 204},
		{name: "wrong audience", change: func(c *renewalChoiceClaims) { c.Audience = jwt.ClaimStrings{"yc-staff"} }, status: 403},
		{name: "extra audience", change: func(c *renewalChoiceClaims) { c.Audience = append(c.Audience, "yc-staff") }, status: 403},
		{name: "wrong operation", change: func(c *renewalChoiceClaims) { c.Operation = "submit" }, status: 403},
		{name: "changed body", wireBody: `{"team_id":"changed"}`, status: 403},
		{name: "changed query", wirePath: path + "?other=1", status: 403},
		{name: "future issued", change: func(c *renewalChoiceClaims) { c.IssuedAt = jwt.NewNumericDate(time.Now().Add(time.Hour)) }, status: 403},
		{name: "expired", change: func(c *renewalChoiceClaims) { c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour)) }, status: 403},
		{name: "long lifetime", change: func(c *renewalChoiceClaims) { c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Hour)) }, status: 403},
		{name: "no issued time", change: func(c *renewalChoiceClaims) { c.IssuedAt = nil }, status: 403},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := gin.New()
			r.POST(path, YCRenewalAuth("status"), func(c *gin.Context) {
				if got := actorIDFromContext(c); got == nil || *got != actor {
					t.Fatal("actor mismatch")
				}
				if c.GetHeader("X-YC-Renewal-Assertion") != "" || c.GetHeader("X-Actor-User-Id") != "" {
					t.Fatal("identity header retained")
				}
				c.Status(204)
			})
			wireBody, wirePath := tc.wireBody, tc.wirePath
			if wireBody == "" {
				wireBody = body
			}
			if wirePath == "" {
				wirePath = path
			}
			req := httptest.NewRequest(http.MethodPost, wirePath, strings.NewReader(wireBody))
			req.Header.Set("X-YC-Renewal-Assertion", renewalHTTPAssertion(t, key, actor, path, body, tc.change))
			req.Header.Set("X-Actor-User-Id", uuid.NewString())
			out := httptest.NewRecorder()
			r.ServeHTTP(out, req)
			if out.Code != tc.status {
				t.Fatalf("%d: %s", out.Code, out.Body.String())
			}
		})
	}
}

func TestRenewalChoiceHTTPUnconfiguredAndSpoofedActor(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	t.Setenv("PROMOTION_ACCOUNT_PUBLIC_KEY", base64.StdEncoding.EncodeToString(pub))
	actor := uuid.New()
	path := "/internal/yc/account/renewals/status"
	body := `{"team_id":"` + uuid.NewString() + `","assignment_id":"` + uuid.NewString() + `"}`
	h := &Handlers{Pool: new(pgxpool.Pool)}
	r := gin.New()
	r.POST(path, YCRenewalAuth("status"), h.RenewalChoiceStatus)
	for _, signed := range []bool{false, true} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("X-Actor-User-Id", actor.String())
		if signed {
			req.Header.Set("X-YC-Renewal-Assertion", renewalHTTPAssertion(t, key, actor, path, body, nil))
		}
		out := httptest.NewRecorder()
		r.ServeHTTP(out, req)
		want := 403
		if signed {
			want = 503
		}
		if out.Code != want {
			t.Fatalf("signed=%t: %d %s", signed, out.Code, out.Body.String())
		}
	}
}
