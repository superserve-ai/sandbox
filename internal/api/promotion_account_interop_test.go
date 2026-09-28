package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// The Console producer suite emits fresh assertions using its actual signer.
// Run this test within their five-minute lifetime; no private key is shared.
func TestPromotionAccountConsoleInterop(t *testing.T) {
	path := os.Getenv("PROMOTION_ASSERTION_FIXTURE_IN")
	if path == "" {
		t.Skip("requires fresh Console producer output via PROMOTION_ASSERTION_FIXTURE_IN")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		PublicKey string `json:"public_key"`
		Requests  []struct {
			Operation string                  `json:"operation"`
			Assertion string                  `json:"assertion"`
			Body      promotionAccountRequest `json:"body"`
			Actor     string                  `json:"actor"`
		} `json:"requests"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Requests) != 3 {
		t.Fatal("Console fixture must cover bind, evidence and register")
	}
	t.Setenv("PROMOTION_ACCOUNT_PUBLIC_KEY", fixture.PublicKey)
	t.Setenv("PROMOTION_CAPTURE_TOKEN", "capture-test-token")
	t.Setenv("INTERNAL_API_TOKEN", "internal-test-token")
	seen := make(map[string]bool)
	for _, request := range fixture.Requests {
		if seen[request.Operation] || (request.Operation != "bind" && request.Operation != "evidence" && request.Operation != "register") {
			t.Fatal("duplicate or unknown Console operation")
		}
		seen[request.Operation] = true
		t.Run(request.Operation, func(t *testing.T) {
			token := "account-test-token"
			if request.Operation == "register" {
				token = "west-account-test-token"
			}
			t.Setenv("PROMOTION_ACCOUNT_TOKEN", token)
			h := new(Handlers)
			r := gin.New()
			account := r.Group("/internal/promotion/account", PromotionProducerAuth("PROMOTION_ACCOUNT_TOKEN"), PromotionAccountAuth())
			account.POST("/bind", h.BindPromotionSignupAccount)
			account.POST("/evidence", h.GetPromotionSignupAccountEvidence)
			account.POST("/register", h.RegisterPromotionSignupDevice)
			for _, spoof := range []bool{false, true} {
				body, actor := request.Body, request.Actor
				want := http.StatusServiceUnavailable
				if spoof {
					body.UserID = uuid.New()
					actor = body.UserID.String()
					want = http.StatusForbidden
				}
				payload, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				req := httptest.NewRequest(http.MethodPost, "/internal/promotion/account/"+request.Operation, strings.NewReader(string(payload)))
				req.Header.Set("Authorization", "Bearer "+token)
				req.Header.Set("X-Actor-User-Id", actor)
				req.Header.Set("X-Promotion-Account-Assertion", request.Assertion)
				w := httptest.NewRecorder()
				r.ServeHTTP(w, req)
				// Only the unmodified producer request may reach the unavailable DB.
				if w.Code != want {
					t.Fatalf("spoof=%v: got %d, want %d: %s", spoof, w.Code, want, w.Body.String())
				}
			}
		})
	}
}
