//go:build integration

package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func TestOfferCompositionInitialOnlyRenewalRoutes(t *testing.T) {
	a, _, r, o := offerCompositionFixture(t)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PROMOTION_ACCOUNT_PUBLIC_KEY", base64.StdEncoding.EncodeToString(pub))
	if a.h.RenewalChoices != nil {
		t.Fatal("initial fixture registered renewal service")
	}
	providerCalls := 0
	a.h.Stripe = &stripeHTTPClient{httpClient: &http.Client{Transport: stripeCheckoutRecoveryRoundTripper(func(*http.Request) (*http.Response, error) {
		providerCalls++
		return nil, errRenewalDisabled
	})}}
	router := gin.New()
	for _, operation := range []string{"status", "submit"} {
		path := "/internal/yc/account/renewals/" + operation
		handler := a.h.RenewalChoiceStatus
		if operation == "submit" {
			handler = a.h.SubmitRenewalChoice
		}
		router.POST(path, YCRenewalAuth(operation), handler)
		payload := map[string]any{"team_id": o.TeamID, "assignment_id": o.AssignmentID}
		if operation == "submit" {
			payload["intended_boundary"], payload["request_id"], payload["acceptance_id"] = time.Now().UTC().Truncate(time.Second), uuid.New(), r.ID
			payload["choice"], payload["expected_approval_revision"], payload["expected_choice_revision"] = "annual", r.ApprovalRevision, 0
		}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		req.Header.Set("X-YC-Renewal-Assertion", renewalHTTPAssertion(t, key, r.UserID, path, string(body), func(c *renewalChoiceClaims) { c.Operation = operation }))
		out := httptest.NewRecorder()
		router.ServeHTTP(out, req)
		if out.Code != http.StatusServiceUnavailable {
			t.Fatal("disabled renewal route did not fail closed", operation, out.Code, out.Body.String())
		}
	}
	var rows int
	if err = a.h.Pool.QueryRow(t.Context(), `SELECT count(*) FROM billing_renewal_choice WHERE team_id=$1`, o.TeamID).Scan(&rows); err != nil || rows != 0 || providerCalls != 0 {
		t.Fatal("disabled routes created renewal state or provider effects", rows, providerCalls, err)
	}
}
