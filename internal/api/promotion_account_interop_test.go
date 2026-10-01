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
			Operation string          `json:"operation"`
			Assertion string          `json:"assertion"`
			Body      json.RawMessage `json:"body"`
			Actor     string          `json:"actor"`
		} `json:"requests"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Requests) != 4 {
		t.Fatal("Console fixture must cover bind, evidence, register and create-team")
	}
	t.Setenv("PROMOTION_ACCOUNT_PUBLIC_KEY", fixture.PublicKey)
	t.Setenv("PROMOTION_CAPTURE_TOKEN", "capture-test-token")
	t.Setenv("INTERNAL_API_TOKEN", "internal-test-token")
	seen := make(map[string]bool)
	for _, request := range fixture.Requests {
		if seen[request.Operation] || (request.Operation != "bind" && request.Operation != "evidence" && request.Operation != "register" && request.Operation != "create-team") {
			t.Fatal("duplicate or unknown Console operation")
		}
		seen[request.Operation] = true
		t.Run(request.Operation, func(t *testing.T) {
			region := "use"
			if request.Operation == "create-team" {
				var creation struct {
					HomeRegion string `json:"home_region"`
				}
				if err := json.Unmarshal(request.Body, &creation); err != nil {
					t.Fatal(err)
				}
				if creation.HomeRegion != "use" && creation.HomeRegion != "usw" {
					t.Fatal("creation fixture requires home_region use or usw")
				}
				region = creation.HomeRegion
			}
			t.Setenv("SANDBOX_ID_REGION", region)
			token := "account-test-token"
			if request.Operation == "register" || region == "usw" {
				token = "west-account-test-token"
			}
			t.Setenv("PROMOTION_ACCOUNT_TOKEN", token)
			h := new(Handlers)
			r := gin.New()
			account := r.Group("/internal/promotion/account", PromotionProducerAuth("PROMOTION_ACCOUNT_TOKEN"), PromotionAccountAuth())
			account.POST("/bind", h.BindPromotionSignupAccount)
			account.POST("/evidence", h.GetPromotionSignupAccountEvidence)
			account.POST("/register", h.RegisterPromotionSignupDevice)
			account.POST("/create-team", h.CreateTeamWithPromotionAttempt)
			mutations := []string{"original", "actor", "actor-and-body"}
			if request.Operation == "create-team" {
				mutations = append(mutations, "attempt_id", "team_id", "home_region", "authority_unavailable", "missing-decision")
			}
			for _, mutation := range mutations {
				var body map[string]any
				if err := json.Unmarshal(request.Body, &body); err != nil {
					t.Fatal(err)
				}
				actor := request.Actor
				want := http.StatusServiceUnavailable
				if mutation != "original" {
					want = http.StatusForbidden
				}
				switch mutation {
				case "actor":
					actor = uuid.NewString()
				case "actor-and-body":
					actor = uuid.NewString()
					body["user_id"] = actor
				case "attempt_id", "team_id":
					body[mutation] = uuid.NewString()
				case "home_region":
					body[mutation] = "usw"
					if region == "usw" {
						body[mutation] = "use"
					}
				case "authority_unavailable":
					decision, ok := body[mutation].(bool)
					if !ok {
						t.Fatal("creation fixture requires boolean authority_unavailable")
					}
					body[mutation] = !decision
				case "missing-decision":
					delete(body, "authority_unavailable")
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
					t.Fatalf("mutation=%s: got %d, want %d: %s", mutation, w.Code, want, w.Body.String())
				}
			}
		})
	}
}
