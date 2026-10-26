//go:build integration

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/billing"
)

func TestProFirstCycleQuoteIgnoresFreeUsageCalendar(t *testing.T) {
	for _, now := range []time.Time{
		time.Date(2026, 10, 26, 19, 0, 0, 0, time.UTC),
		time.Date(2027, 1, 31, 23, 59, 59, 0, time.UTC),
		time.Date(2028, 1, 31, 12, 0, 0, 0, time.UTC),
		time.Date(2028, 2, 29, 12, 0, 0, 0, time.UTC),
	} {
		t.Run(now.Format(time.RFC3339), func(t *testing.T) {
			h, team, offer, params := newProFirstCycleQuoteFixture(t, now)
			preview, err := customerProCheckoutTerms(t.Context(), h.Pool, team, true, false)
			if err != nil || !preview.FirstPaidProCycle || preview.Accepted || preview.PeriodEnd != nil || preview.FirstPaymentCents != nil {
				t.Fatalf("unaccepted first cycle preview: %+v %v", preview, err)
			}
			quote := func() { requestProFirstCycleQuote(t, h, team, offer, params, http.StatusAccepted) }
			quote()
			accepted, err := h.proUpgrade(t.Context(), team)
			if err != nil {
				t.Fatal(err)
			}
			_, wantEnd, _ := billing.AnniversaryPeriod(now, now)
			var frozen StripeCreateCheckoutSessionParams
			if err = json.Unmarshal(accepted.Payload, &frozen); err != nil {
				t.Fatal(err)
			}
			if !accepted.Anchor.Equal(now) || !accepted.Start.Equal(now) || !accepted.End.Equal(wantEnd) || accepted.Amount != offer.Amount || accepted.bridgeCreditAmount() != offer.Credit || !frozen.FirstPaidProCycle || strings.Contains(frozen.OneOffName, "Prorated") || !strings.Contains(frozen.OneOffName, "expires at the end of this billing month") {
				t.Fatalf("first paid month: %+v payload=%s", accepted, accepted.Payload)
			}
			status, err := customerProCheckoutTerms(t.Context(), h.Pool, team, true, false)
			wire, _ := json.Marshal(status)
			if err != nil || !status.Accepted || !status.FirstPaidProCycle || status.CreditExpiresAt == nil || !status.CreditExpiresAt.Equal(wantEnd) || status.FirstCreditCents == nil || *status.FirstCreditCents != offer.Credit || status.FirstPaymentCents == nil || *status.FirstPaymentCents != offer.Amount || !strings.Contains(string(wire), `"first_paid_pro_cycle":true`) {
				t.Fatalf("accepted quote contract: %s %v", wire, err)
			}
			// Even across a calendar boundary, an accepted checkout keeps its exact quote.
			h.Now = func() time.Time { return now.Add(48 * time.Hour) }
			quote()
			replay, err := h.proUpgrade(t.Context(), team)
			if err != nil || string(replay.Payload) != string(accepted.Payload) || !replay.End.Equal(accepted.End) || replay.ID != accepted.ID {
				t.Fatalf("accepted operation repriced: %+v %v", replay, err)
			}
		})
	}
}

func newProFirstCycleQuoteFixture(t *testing.T, now time.Time) (*Handlers, uuid.UUID, proOffer, StripeCreateCheckoutSessionParams) {
	t.Helper()
	h, team := newPlanAssignmentFixture(t)
	h.Now = func() time.Time { return now }
	if _, err := assignInTx(t, h, planAssignment{Team: team, Terms: testPlanTerms("free", "free", 2, nil), Source: "signup", Reason: "new Free account"}); err != nil {
		t.Fatal(err)
	}
	customer := "cus_" + uuid.NewString()
	if _, err := h.Pool.Exec(t.Context(), `INSERT INTO team_billing_account(team_id,stripe_customer_id) VALUES($1,$2)`, team, customer); err != nil {
		t.Fatal(err)
	}
	// A Free usage period is an accounting bucket, never a paid anniversary.
	start, end := billing.CurrentBillingPeriod(now)
	if _, err := h.Pool.Exec(t.Context(), `INSERT INTO team_billing_period(team_id,period_start,period_end) VALUES($1,$2,$3)`, team, start, end); err != nil {
		t.Fatal(err)
	}
	terms, err := h.planTermsForPricingVersion(t.Context(), "pro_monthly", "v2")
	if err != nil {
		t.Fatal(err)
	}
	offer := proOffer{Key: terms.OfferKey, Name: terms.DisplayName, Price: "price_pro", Amount: terms.FeeCents, Months: 1, Credit: terms.MonthlyCreditCents, VersionID: terms.VersionID, Version: terms.Version, Family: terms.Family, Pricing: "v2", PricingV2: true, Limits: &terms.Limits, Grants: terms.Grants, Allowance: terms.Allowance}
	params := StripeCreateCheckoutSessionParams{CustomerID: customer, OperationID: uuid.New(), ClientReferenceID: team.String(), BasePriceID: offer.Price, OneOffProduct: "prod_pro", AllowPromotionCodes: true, PlanTerms: &StripeCheckoutPlanTerms{Amount: offer.Amount, Months: 1, Credit: offer.Credit, VersionID: offer.VersionID, Version: offer.Version, Family: offer.Family, PricingV2: true, Limits: offer.Limits, Grants: offer.Grants}}
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "unavailable", 503) }))
	t.Cleanup(provider.Close)
	h.Stripe = &stripeHTTPClient{baseURL: provider.URL, httpClient: provider.Client(), apiVersion: "2026-05-27.dahlia"}
	return h, team, offer, params
}

func requestProFirstCycleQuote(t *testing.T, h *Handlers, team uuid.UUID, offer proOffer, params StripeCreateCheckoutSessionParams, status int) {
	t.Helper()
	response := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(response)
	c.Request = httptest.NewRequest(http.MethodPost, "/stripe/pro-checkout", nil)
	h.createProUpgrade(c, team, uuid.MustParse("00000000-0000-0000-0000-000000000111"), offer, params, pricingPublicState{LegacyOpen: true})
	if response.Code != status {
		t.Fatalf("quote: %d %s; want %d", response.Code, response.Body.String(), status)
	}
}

func TestProFirstCyclePreservesCommercialAnchorsAndRejectsUnpaidLeftovers(t *testing.T) {
	now := time.Date(2026, 10, 26, 19, 0, 0, 0, time.UTC)
	for _, kind := range []string{"commercial_anchor", "provider_without_anchor", "expired_first_cycle", "expired_untouched_quote", "prepaid_history"} {
		t.Run(kind, func(t *testing.T) {
			h, team, offer, params := newProFirstCycleQuoteFixture(t, now)
			want := http.StatusAccepted
			switch kind {
			case "commercial_anchor":
				if _, err := h.Pool.Exec(t.Context(), `UPDATE team_billing_account SET commercial_billing_anchor=$2 WHERE team_id=$1`, team, now.AddDate(0, -1, 0).Add(-24*time.Hour)); err != nil {
					t.Fatal(err)
				}
			case "provider_without_anchor":
				want = http.StatusConflict
				if _, err := h.Pool.Exec(t.Context(), `UPDATE team_billing_account SET stripe_subscription_id=$2 WHERE team_id=$1`, team, "sub_"+uuid.NewString()); err != nil {
					t.Fatal(err)
				}
			case "expired_first_cycle", "expired_untouched_quote":
				var subscription *string
				if kind == "expired_first_cycle" {
					want = http.StatusConflict
					subscription = stringPtr("sub_" + uuid.NewString())
				}
				if _, err := h.Pool.Exec(t.Context(), `INSERT INTO billing_pro_upgrade(id,team_id,actor_id,customer_id,offer_key,request_payload,anchor,period_start,period_end,quoted_at,amount_cents,state,subscription_id) VALUES($1,$2,$3,$4,'pro_monthly','{"FirstPaidProCycle":true}',$5,$5,$6,$5,25000,'expired',$7)`, uuid.New(), team, uuid.New(), params.CustomerID, now, now.AddDate(0, 1, 0), subscription); err != nil {
					t.Fatal(err)
				}
			case "prepaid_history":
				if _, err := assignInTx(t, h, planAssignment{Team: team, Terms: testPlanTerms("starter", "prepaid", 2, nil), Source: "staff", Reason: "prior paid terms"}); err != nil {
					t.Fatal(err)
				}
				if _, err := assignInTx(t, h, planAssignment{Team: team, Terms: testPlanTerms("free", "free", 2, nil), Source: "staff", Reason: "returned to Free"}); err != nil {
					t.Fatal(err)
				}
			}
			requestProFirstCycleQuote(t, h, team, offer, params, want)
			if want == http.StatusConflict {
				var count int
				if err := h.Pool.QueryRow(t.Context(), `SELECT count(*) FROM billing_pro_upgrade WHERE team_id=$1 AND state<>'expired'`, team).Scan(&count); err != nil || count != 0 {
					t.Fatalf("unsafe new operation: %d %v", count, err)
				}
				return
			}
			u, err := h.proUpgrade(t.Context(), team)
			if err != nil {
				t.Fatal(err)
			}
			var p StripeCreateCheckoutSessionParams
			if err = json.Unmarshal(u.Payload, &p); err != nil {
				t.Fatal(err)
			}
			if kind == "expired_untouched_quote" {
				if !p.FirstPaidProCycle || !u.Anchor.Equal(now) || u.Amount != offer.Amount {
					t.Fatalf("untouched expired quote cannot retry: %+v", u)
				}
				return
			}
			status, err := customerProCheckoutTerms(t.Context(), h.Pool, team, true, kind == "commercial_anchor")
			if err != nil || status.FirstPaidProCycle || !status.Accepted || status.CreditExpiresAt != nil || status.FirstPaymentCents == nil || *status.FirstPaymentCents != u.Amount {
				t.Fatalf("legacy accepted response changed: %+v %v", status, err)
			}
			if p.FirstPaidProCycle || u.Anchor.Equal(now) || u.Amount >= offer.Amount {
				t.Fatalf("reset existing customer calendar: %+v", u)
			}
		})
	}
}
