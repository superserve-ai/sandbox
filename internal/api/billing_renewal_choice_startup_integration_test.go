//go:build integration

package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRenewalChoiceStartupRoutesUseConfiguredAuthority(t *testing.T) {
	a, h, r, f, client, actor := newRenewalAcceptedPairFixture(t, time.Now().UTC().Add(-time.Hour).Truncate(time.Second))
	cfg := renewalRuntimeFixtureConfig(t, h, a.Admission, f, client)
	h.ProviderPairEntitlementAuthority = nil
	if err := h.ConfigureRenewalChoices(t.Context(), cfg); err == nil || h.RenewalChoices != nil {
		t.Fatal("registration succeeded before financial authority initialization")
	}
	// Exercise the actual startup initializer while preventing background work
	// from consuming other synthetic fixtures in this shared test database.
	stopped, cancel := context.WithCancel(t.Context())
	cancel()
	h.StartUsageEntitlementService(stopped)
	if err := h.ConfigureRenewalChoices(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	h.StartRenewalChoiceService(stopped)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PROMOTION_ACCOUNT_PUBLIC_KEY", base64.StdEncoding.EncodeToString(pub))
	router := SetupRouter(t.Context(), h, nil)
	statusBody, _ := json.Marshal(map[string]any{"team_id": r.TeamID, "assignment_id": r.AssignmentID})
	request := func(operation, body string, requester uuid.UUID) *httptest.ResponseRecorder {
		path := "/internal/yc/account/renewals/" + operation
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-YC-Renewal-Assertion", renewalHTTPAssertion(t, key, requester, path, body, func(c *renewalChoiceClaims) { c.Operation = operation }))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	w := request("status", string(statusBody), actor)
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d %s", w.Code, w.Body.String())
	}
	var view renewalChoiceView
	if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil || view.Confirmed == nil || view.Confirmed.Choice != "annual" {
		t.Fatal("configured route did not read accepted pair", err)
	}
	submitBody, _ := json.Marshal(struct {
		renewalChoiceKey
		renewalChoiceRequest
	}{renewalChoiceKey{Team: r.TeamID, Assignment: *r.AssignmentID, Boundary: view.Boundary}, renewalChoiceRequest{Acceptance: view.Acceptance, ID: uuid.New(), Choice: "free", ApprovalRevision: view.ApprovalRevision, ChoiceRevision: view.Revision}})
	w = request("submit", string(submitBody), actor)
	if w.Code != http.StatusOK {
		t.Fatalf("submit: %d %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil || view.Requested == nil || view.Requested.Choice != "free" {
		t.Fatal("configured submit did not persist choice", err)
	}
	for _, operation := range []string{"status", "submit"} {
		body := string(statusBody)
		if operation == "submit" {
			body = string(submitBody)
		}
		w = request(operation, body, uuid.New())
		if w.Code != http.StatusForbidden {
			t.Fatalf("unauthorized %s: %d", operation, w.Code)
		}
	}
}
