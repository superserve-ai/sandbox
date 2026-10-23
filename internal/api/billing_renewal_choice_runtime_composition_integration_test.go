//go:build integration

package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func renewalRuntimeFixtureConfig(t *testing.T, h *Handlers, admission *YCAcceptedProvisioningAdmission, f *pairFixture, client *stripeHTTPClient) RenewalChoiceConfig {
	t.Helper()
	client.secretKey = "sk_test_example"
	h.YCOfferAcceptance, h.PromotionAuthPool, h.Stripe = admission.Service, admission.Service.Shared, client
	if h.ProviderPairEntitlementAuthority == nil {
		h.ProviderPairEntitlementAuthority = &offerProvisioningAuthority{h: h, admission: admission, client: client, successorRequester: RenewalSuccessorRequester, dispatchesResolved: CheckProviderPairDispatchesResolved}
	}
	monthly := f.p.Terms
	monthly.FeePriceID, monthly.FeeAmount, monthly.FeeMonths = "price_monthly", 120000, 1
	price := f.fee.Items.Data[0].Price
	price.ID, price.UnitAmountDecimal, price.Recurring.Interval, price.Recurring.IntervalCount = monthly.FeePriceID, "120000", "month", 1
	serve := f.serve
	f.serve = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/prices/price_monthly" {
			json.NewEncoder(w).Encode(price)
			return true
		}
		return serve != nil && serve(w, r)
	}
	return RenewalChoiceConfig{Enabled: true, Merchant: f.p.Identity.Merchant, Live: f.p.Identity.Live, APIVersion: renewalStripeVersion,
		Monthly: monthly, MonthlyVersion: 1,
		Boundary: RenewalBoundaryEvidence{Accepted: true, Contract: RenewalBoundaryContractVersion, ReviewedSource: renewalBoundaryReviewedSource, ReceiptDigest: strings.Repeat("a", 64), Merchant: f.p.Identity.Merchant, Live: f.p.Identity.Live, APIVersion: renewalStripeVersion}}
}

func configureRenewalRuntimeFixture(t *testing.T, h *Handlers, admission *YCAcceptedProvisioningAdmission, f *pairFixture, client *stripeHTTPClient) *renewalChoiceService {
	t.Helper()
	if err := h.ConfigureRenewalChoices(t.Context(), renewalRuntimeFixtureConfig(t, h, admission, f, client)); err != nil {
		t.Fatal(err)
	}
	return h.RenewalChoices
}

func TestRenewalChoiceRuntimeRegistrationAtomic(t *testing.T) {
	a, h, r, f, client, actor := newRenewalAcceptedPairFixture(t, time.Now().UTC().Add(-time.Hour).Truncate(time.Second))
	cfg := renewalRuntimeFixtureConfig(t, h, a.Admission, f, client)
	f.requests = nil
	for name, change := range map[string]func(*RenewalChoiceConfig){
		"wrong contract":    func(c *RenewalChoiceConfig) { c.Boundary.Contract = "unreviewed" },
		"wrong source":      func(c *RenewalChoiceConfig) { c.Boundary.ReviewedSource = "unreviewed" },
		"missing evidence":  func(c *RenewalChoiceConfig) { c.Boundary.Accepted = false },
		"evidence merchant": func(c *RenewalChoiceConfig) { c.Boundary.Merchant = "acct_other" },
		"evidence mode":     func(c *RenewalChoiceConfig) { c.Boundary.Live = !c.Live },
		"evidence version":  func(c *RenewalChoiceConfig) { c.Boundary.APIVersion = "unsupported" },
		"client version":    func(c *RenewalChoiceConfig) { c.APIVersion = "unsupported" },
		"catalog version":   func(c *RenewalChoiceConfig) { c.MonthlyVersion = 999999 },
		"catalog amount":    func(c *RenewalChoiceConfig) { c.Monthly.FeeAmount++ },
		"provider merchant": func(c *RenewalChoiceConfig) { c.Merchant, c.Boundary.Merchant = "acct_other", "acct_other" },
		"provider mode":     func(c *RenewalChoiceConfig) { c.Live, c.Boundary.Live = true, true },
	} {
		t.Run(name, func(t *testing.T) {
			bad := cfg
			change(&bad)
			if err := h.ConfigureRenewalChoices(t.Context(), bad); err == nil || h.RenewalChoices != nil {
				t.Fatal("invalid registration became visible", err)
			}
		})
	}
	var rows int
	if err := h.Pool.QueryRow(t.Context(), `SELECT count(*) FROM billing_renewal_choice WHERE assignment_id=$1`, *r.AssignmentID).Scan(&rows); err != nil || rows != 0 {
		t.Fatal("configuration created journal state", rows, err)
	}
	results := make(chan error, 2)
	for range 2 {
		go func() { results <- h.ConfigureRenewalChoices(t.Context(), cfg) }()
	}
	first, second := <-results, <-results
	if (first == nil) == (second == nil) {
		t.Fatal("concurrent configuration must publish exactly once", first, second)
	}
	for _, request := range f.requests {
		if !strings.HasPrefix(request, "GET ") {
			t.Fatal("configuration wrote to provider", request)
		}
	}
	// Mutation of the caller's mapping after registration must not change terms.
	cfg.Monthly.Resources[0].PriceID = "price_replaced"
	view, err := h.RenewalChoices.currentView(t.Context(), r.TeamID, *r.AssignmentID, actor)
	if err != nil || view.Confirmed == nil || view.Confirmed.Choice != "annual" {
		t.Fatal("registered service cannot initialize the real accepted pair", err)
	}
	authority := h.RenewalChoices.Authority.(*acceptedRenewalAuthority)
	if authority.Monthly.Resources[0].PriceID == "price_replaced" {
		t.Fatal("caller mutated registered mapping")
	}
}
