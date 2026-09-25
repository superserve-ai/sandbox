package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestIsActivating(t *testing.T) {
	for _, status := range []string{"active", "trialing", "past_due", "ACTIVE", "PAST_DUE"} {
		if !isActivating(status) {
			t.Errorf("isActivating(%q) = false, want true", status)
		}
	}
	for _, status := range []string{"canceled", "paused", "incomplete"} {
		if isActivating(status) {
			t.Errorf("isActivating(%q) = true, want false", status)
		}
	}
}

func TestIsTerminalSubscriptionStatus(t *testing.T) {
	for _, status := range []string{"canceled", "UNPAID", "paused", "incomplete_expired"} {
		if !isTerminalSubscriptionStatus(status) {
			t.Errorf("isTerminalSubscriptionStatus(%q) = false, want true", status)
		}
	}
	for _, status := range []string{"active", "trialing", "past_due", "incomplete", ""} {
		if isTerminalSubscriptionStatus(status) {
			t.Errorf("isTerminalSubscriptionStatus(%q) = true, want false", status)
		}
	}
}

func TestStripeRecoveryWatermarkMatchesStripePrecision(t *testing.T) {
	now := time.Date(2026, time.September, 22, 19, 22, 15, 987654321, time.FixedZone("example", -5*60*60))
	got := stripeRecoveryWatermark(now)
	want := time.Date(2026, time.September, 23, 0, 22, 15, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("stripeRecoveryWatermark(%v) = %v, want %v", now, got, want)
	}
	if got.Nanosecond() != 0 {
		t.Fatalf("stripe recovery watermark retains subsecond precision: %v", got)
	}
}

func TestStripeSubscriptionPeriodBoundsUsesItemPeriodsBeforeTopLevelFallback(t *testing.T) {
	itemStart, itemEnd := int64(1_700_000_000), int64(1_700_086_400)
	gotStart, gotEnd, ok := (stripeSubscription{
		CurrentPeriodStart: 0,
		CurrentPeriodEnd:   0,
		Items: stripeSubscriptionItems{Data: []stripeSubscriptionItem{{
			CurrentPeriodStart: itemStart,
			CurrentPeriodEnd:   itemEnd,
		}}},
	}).periodBounds()
	if !ok || gotStart != itemStart || gotEnd != itemEnd {
		t.Fatalf("item period bounds = (%d, %d, %t), want (%d, %d, true)", gotStart, gotEnd, ok, itemStart, itemEnd)
	}

	fallbackStart, fallbackEnd := int64(1_800_000_000), int64(1_800_086_400)
	gotStart, gotEnd, ok = (stripeSubscription{
		CurrentPeriodStart: fallbackStart,
		CurrentPeriodEnd:   fallbackEnd,
	}).periodBounds()
	if !ok || gotStart != fallbackStart || gotEnd != fallbackEnd {
		t.Fatalf("top-level period bounds = (%d, %d, %t), want (%d, %d, true)", gotStart, gotEnd, ok, fallbackStart, fallbackEnd)
	}
}

func TestParseOptionalUUID(t *testing.T) {
	if got, err := parseOptionalUUID(""); err != nil || got != nil {
		t.Fatalf("empty UUID = (%v, %v), want (nil, nil)", got, err)
	}
	if _, err := parseOptionalUUID("not-a-uuid"); err == nil {
		t.Fatal("invalid UUID unexpectedly accepted")
	}
}

func TestStripeClientGrantsPaginates(t *testing.T) {
	var paths []string
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		paths = append(paths, r.URL.String())
		page := stripeGrantList{Data: []stripeGrant{{ID: "grant_1"}}, HasMore: len(paths) == 1}
		if len(paths) == 2 {
			page.Data[0].ID = "grant_2"
		}
		body, _ := json.Marshal(page)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body))), Header: make(http.Header), Request: r}, nil
	})}

	grants, err := (stripeClient{baseURL: "https://stripe.example", httpClient: client}).grants(t.Context(), "cus_example")
	if err != nil {
		t.Fatalf("grants: %v", err)
	}
	if len(grants) != 2 || grants[0].ID != "grant_1" || grants[1].ID != "grant_2" {
		t.Fatalf("grants = %#v, want two pages", grants)
	}
	if len(paths) != 2 || !strings.Contains(paths[1], "starting_after=grant_1") {
		t.Fatalf("request paths = %v, want cursor on second page", paths)
	}
}

func TestVerifiedActivationGrantRequiresApplicabilityAndIdentity(t *testing.T) {
	identity := "stripe-activation-credit-00000000-0000-0000-0000-000000000001"
	grant := stripeGrant{
		ID:       "grant_activation",
		Category: "promotional",
		Metadata: map[string]string{activationGrantIdentityMetadataKey: identity},
	}
	grant.Amount.Monetary.Value = 9500
	grant.Amount.Monetary.Currency = "usd"
	grant.ApplicabilityConfig.Scope.PriceType = "metered"
	if !(stripeClient{}).isVerifiedActivationGrant(grant, "", identity) {
		t.Fatal("matching activation identity and applicability should verify the grant")
	}

	grant.Metadata[activationGrantIdentityMetadataKey] = "stripe-activation-credit-other-team"
	if (stripeClient{}).isVerifiedActivationGrant(grant, "", identity) {
		t.Fatal("a grant for another activation identity must remain unverified")
	}
	grant.Metadata[activationGrantIdentityMetadataKey] = identity
	grant.ApplicabilityConfig.Scope.PriceType = "licensed"
	if (stripeClient{}).isVerifiedActivationGrant(grant, "", identity) {
		t.Fatal("a grant with non-metered applicability must remain unverified")
	}
	grant.ApplicabilityConfig.Scope.PriceType = "metered"
	if !(stripeClient{}).isVerifiedActivationGrant(grant, grant.ID, "") {
		t.Fatal("a persisted local grant ID may establish identity, but applicability is still required")
	}
	grant.ExpiresAt = int64PtrForTest(time.Now().UTC().Add(-time.Minute).Unix())
	if (stripeClient{}).isVerifiedActivationGrant(grant, grant.ID, "") {
		t.Fatal("an expired grant must not establish activation")
	}
	grant.ExpiresAt = nil
	grant.VoidedAt = int64PtrForTest(time.Now().UTC().Unix())
	if (stripeClient{}).isVerifiedActivationGrant(grant, grant.ID, "") {
		t.Fatal("a voided grant must not establish activation")
	}
}

func TestAuditAccountDryRunSkipsUnsafeTargetsAndDoesNotMutate(t *testing.T) {
	teamID := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	activeSubscription := stripeSubscription{
		ID:       "sub_active",
		Customer: "cus_active",
		Status:   "active",
		Items: stripeSubscriptionItems{Data: []stripeSubscriptionItem{{
			CurrentPeriodStart: 1_700_000_000,
			CurrentPeriodEnd:   1_700_086_400,
		}}},
	}
	identity := activationGrantIdentity(teamID)
	existingGrant := stripeGrant{
		ID:       "grant_existing",
		Category: "promotional",
		Metadata: map[string]string{activationGrantIdentityMetadataKey: identity},
	}
	existingGrant.Amount.Monetary.Value = 9500
	existingGrant.Amount.Monetary.Currency = "usd"
	existingGrant.ApplicabilityConfig.Scope.PriceType = "metered"

	cases := []struct {
		name       string
		account    billingAccount
		sub        stripeSubscription
		grants     []stripeGrant
		excluded   *uuid.UUID
		wantResult string
		wantReason string
		wantGrant  string
	}{
		{
			name:       "excluded target",
			account:    billingAccount{TeamID: teamID, CustomerID: stringPtrForTest("cus_active"), SubscriptionID: stringPtrForTest("sub_active")},
			sub:        activeSubscription,
			excluded:   uuidPtrForTest(teamID),
			wantResult: "skipped",
			wantReason: "operationally_excluded",
		},
		{
			name:       "uncertain local ownership",
			account:    billingAccount{TeamID: teamID, SubscriptionID: stringPtrForTest("sub_active")},
			wantResult: "skipped",
			wantReason: "uncertain_local_ownership",
		},
		{
			name:       "subscription ownership mismatch",
			account:    billingAccount{TeamID: teamID, CustomerID: stringPtrForTest("cus_local"), SubscriptionID: stringPtrForTest("sub_active")},
			sub:        activeSubscription,
			wantResult: "skipped",
			wantReason: "subscription_ownership_mismatch",
		},
		{
			name:    "canceled subscription",
			account: billingAccount{TeamID: teamID, CustomerID: stringPtrForTest("cus_active"), SubscriptionID: stringPtrForTest("sub_active")},
			sub: stripeSubscription{
				ID: "sub_active", Customer: "cus_active", Status: "canceled",
				CurrentPeriodStart: 1_700_000_000, CurrentPeriodEnd: 1_700_086_400,
			},
			wantResult: "skipped",
			wantReason: "subscription_not_active",
		},
		{
			name:       "active subscription without grant",
			account:    billingAccount{TeamID: teamID, CustomerID: stringPtrForTest("cus_active"), SubscriptionID: stringPtrForTest("sub_active")},
			sub:        activeSubscription,
			wantResult: "candidate",
			wantReason: "active_subscription_without_activation_grant",
		},
		{
			name:    "past_due subscription without grant",
			account: billingAccount{TeamID: teamID, CustomerID: stringPtrForTest("cus_active"), SubscriptionID: stringPtrForTest("sub_active")},
			sub: stripeSubscription{
				ID: "sub_active", Customer: "cus_active", Status: "past_due",
				CurrentPeriodStart: 1_700_000_000, CurrentPeriodEnd: 1_700_086_400,
			},
			wantResult: "candidate",
			wantReason: "active_subscription_without_activation_grant",
		},
		{
			name:       "existing verified grant",
			account:    billingAccount{TeamID: teamID, CustomerID: stringPtrForTest("cus_active"), SubscriptionID: stringPtrForTest("sub_active")},
			sub:        activeSubscription,
			grants:     []stripeGrant{existingGrant},
			wantResult: "candidate",
			wantReason: "existing_stripe_grant_reconcile",
			wantGrant:  existingGrant.ID,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stripe := newRecoveryTestStripeClient(t, tc.sub, tc.grants)
			result := auditAccount(context.Background(), nil, *stripe.client, tc.account, tc.excluded, false)
			if result["mode"] != "dry-run" {
				t.Fatalf("mode = %#v, want dry-run", result["mode"])
			}
			if result["outcome"] != tc.wantResult || result["reason"] != tc.wantReason {
				t.Fatalf("result = %#v, want outcome=%q reason=%q", result, tc.wantResult, tc.wantReason)
			}
			if tc.wantGrant != "" && result["grant_id"] != tc.wantGrant {
				t.Fatalf("grant_id = %#v, want %q", result["grant_id"], tc.wantGrant)
			}
			if stripe.postCalls != 0 {
				t.Fatalf("dry-run made %d grant creation calls", stripe.postCalls)
			}
		})
	}
}

type recoveryTestStripeClient struct {
	client    *stripeClient
	server    *httptest.Server
	postCalls int
}

func newRecoveryTestStripeClient(t *testing.T, sub stripeSubscription, grants []stripeGrant) *recoveryTestStripeClient {
	t.Helper()
	fixture := &recoveryTestStripeClient{}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/subscriptions/"):
			_ = json.NewEncoder(w).Encode(sub)
		case r.URL.Path == "/v1/billing/credit_grants" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(stripeGrantList{Data: grants})
		case r.URL.Path == "/v1/billing/credit_grants" && r.Method == http.MethodPost:
			fixture.postCalls++
			_ = json.NewEncoder(w).Encode(stripeGrant{ID: "grant_created"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(fixture.server.Close)
	client := stripeClient{baseURL: fixture.server.URL, httpClient: fixture.server.Client()}
	fixture.client = &client
	return fixture
}

func stringPtrForTest(value string) *string { return &value }

func int64PtrForTest(value int64) *int64 { return &value }

func uuidPtrForTest(value uuid.UUID) *uuid.UUID { return &value }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRecoverySnapshotIncludesCheckoutIdentity(t *testing.T) {
	at := time.Now()
	session := "cs_original"
	a := billingAccount{CheckoutAt: &at, CheckoutSessionID: &session}
	b := a
	replacement := "cs_replacement"
	b.CheckoutSessionID = &replacement
	if sameRecoveryBillingSnapshot(a, b) {
		t.Fatal("replacement checkout was not detected")
	}
	b = a
	later := at.Add(time.Second)
	b.CheckoutAt = &later
	if sameRecoveryBillingSnapshot(a, b) {
		t.Fatal("new checkout reservation was not detected")
	}
}

func TestAuditCheckoutSeparatesUnverifiedStateFromLookupFailures(t *testing.T) {
	for _, tc := range []struct {
		name            string
		code            int
		body            string
		outcome, reason string
	}{
		{"server failure", 500, `{}`, "unresolved", "stripe_checkout_lookup_failed"},
		{"invalid response", 200, `not json`, "unresolved", "stripe_checkout_lookup_failed"},
		{"open session", 200, `{"id":"cs_pending","status":"open"}`, "skipped", "checkout_not_verified_complete"},
		{"expired session", 200, `{"id":"cs_pending","status":"expired"}`, "skipped", "checkout_not_verified_complete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != http.MethodGet || r.URL.Path != "/v1/checkout/sessions/cs_pending" {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
				w.WriteHeader(tc.code)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			at := time.Now()
			account := billingAccount{TeamID: uuid.New(), CustomerID: stringPtrForTest("cus_current"), SubscriptionID: stringPtrForTest("sub_current"), CheckoutSessionID: stringPtrForTest("cs_pending"), CheckoutAt: &at}
			result := auditAccount(context.Background(), nil, stripeClient{baseURL: server.URL}, account, nil, false)
			if result["outcome"] != tc.outcome || result["reason"] != tc.reason {
				t.Fatalf("result=%v, want %s/%s", result, tc.outcome, tc.reason)
			}
			if calls != 1 {
				t.Fatalf("requests=%d, want exactly one read", calls)
			}
		})
	}
}
