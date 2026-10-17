//go:build integration

package integration

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/db"
)

func commercialIssue(t *testing.T, c db.BillingCommercialContract) {
	t.Helper()
	e := commercialBegin(t, c, commercialClaim(t, c))
	var evidence map[string]any
	if err := json.Unmarshal(e.RequestPayload, &evidence); err != nil {
		t.Fatal(err)
	}
	grant := "credgr_" + uuid.NewString()
	evidence["id"], evidence["customer"] = grant, c.CustomerID
	body, _ := json.Marshal(evidence)
	if _, err := testQueries.ConfirmUsageEntitlementIssued(t.Context(), db.ConfirmUsageEntitlementIssuedParams{
		TeamID: c.TeamID, EntitlementID: e.ID, GrantID: &grant, Evidence: body,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestIntegration_GetBillingSummaryCommercialPlan(t *testing.T) {
	available := &fakeStripeClient{creditBalance: api.StripeCreditBalance{AvailableUSD: 1000, ObservedAt: time.Now().UTC()}}
	for _, tc := range []struct {
		name     string
		team     func(t *testing.T) uuid.UUID
		stripe   *fakeStripeClient
		key      string
		status   string
		price    any
		interval any
		included any // included_usage.status, or nil when absent
	}{
		{
			name: "free",
			team: func(t *testing.T) uuid.UUID {
				teamID, _, _, _ := seedBillingPeriodForStripe(t, true, true)
				return teamID
			},
			key: "free", status: "active",
		},
		{
			name: "lapsed fixed term reports free",
			team: func(t *testing.T) uuid.UUID {
				team, err := testQueries.CreateTeam(t.Context(), "commercial-"+uuid.NewString())
				if err != nil {
					t.Fatal(err)
				}
				customer, subscription := "cus_"+uuid.NewString(), "sub_"+uuid.NewString()
				start := time.Date(commercialNow(t).Year(), commercialNow(t).Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, -2, 0)
				end := start.AddDate(0, 1, 0)
				correctionExec(t, `INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,commercial_billing_anchor) VALUES($1,$2,$3,$4)`, team.ID, customer, subscription, start)
				if _, err := testQueries.CreateCommercialContract(t.Context(), db.CreateCommercialContractParams{
					TeamID: team.ID, OfferKey: "pro_monthly", StartsAt: start, EndsAt: commercialTime(end), CustomerID: customer, SubscriptionID: subscription,
					BasePriceID: "price_base", ChargeAmountCents: 120000, ChargeIntervalMonths: 1,
					EntitlementKind: "metered_usage", EntitlementAmountCents: 100000, EntitlementCadence: "monthly", EntitlementAnchor: start,
				}); err != nil {
					t.Fatal(err)
				}
				return team.ID
			},
			key: "free", status: "active",
		},
		{
			name: "pro monthly awaiting payment",
			team: func(t *testing.T) uuid.UUID { return commercialFixture(t, false).TeamID },
			key:  "pro_monthly", status: "pending", price: float64(1200), interval: float64(1), included: "not_issued",
		},
		{
			name: "pro annual allowance pending",
			team: func(t *testing.T) uuid.UUID {
				c := commercialObserve(t, commercialActivate(t, commercialFixture(t, true)), false)
				commercialClaim(t, c)
				return c.TeamID
			},
			key: "pro_annual", status: "active", price: float64(12000), interval: float64(12), included: "pending",
		},
		{
			name: "pro annual allowance issued",
			team: func(t *testing.T) uuid.UUID {
				c := commercialObserve(t, commercialActivate(t, commercialFixture(t, true)), false)
				commercialIssue(t, c)
				return c.TeamID
			},
			key: "pro_annual", status: "active", price: float64(12000), interval: float64(12), included: "issued",
		},
		{
			name: "pro monthly with stripe unavailable",
			team: func(t *testing.T) uuid.UUID {
				c := commercialObserve(t, commercialActivate(t, commercialFixture(t, false)), false)
				commercialIssue(t, c)
				return c.TeamID
			},
			stripe: &fakeStripeClient{creditBalanceErr: errors.New("credit balance unavailable")},
			key:    "pro_monthly", status: "active", price: float64(1200), interval: float64(1), included: "issued",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			teamID := tc.team(t)
			stripe := tc.stripe
			if stripe == nil {
				stripe = available
			}
			w := do(newBillingRouter(t, stripe), "GET", "/billing/summary", seedKeyForExistingTeamWithRole(t, teamID, "viewer"), "")
			if w.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
			}
			plan := mustJSON(t, w)["plan"].(map[string]any)
			if plan["key"] != tc.key || plan["status"] != tc.status || plan["price_usd"] != tc.price || plan["billing_interval_months"] != tc.interval {
				t.Fatalf("plan = %v", plan)
			}
			included, _ := plan["included_usage"].(map[string]any)
			if tc.included == nil {
				if plan["included_usage"] != nil {
					t.Fatalf("included_usage = %v, want null", plan["included_usage"])
				}
				return
			}
			if included["status"] != tc.included || included["amount_usd"] != float64(1000) {
				t.Fatalf("included_usage = %v", included)
			}
			start, _ := time.Parse(time.RFC3339, included["period_start"].(string))
			end, _ := time.Parse(time.RFC3339, included["period_end"].(string))
			if now := time.Now(); start.After(now) || !end.After(now) {
				t.Fatalf("period [%s,%s) does not contain now", start, end)
			}
		})
	}
}

// Plan credit grants are price-scoped, so the metered-scope balance alone
// reports them as zero.
func TestIntegration_GetBillingSummaryCountsIssuedPlanCredit(t *testing.T) {
	for _, tc := range []struct {
		name      string
		grantErr  error
		status    string
		remaining any
	}{
		{name: "grant balance counted", status: "available", remaining: float64(1000)},
		{name: "grant balance unreadable", grantErr: errors.New("grant unavailable"), status: "unavailable", remaining: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := commercialObserve(t, commercialActivate(t, commercialFixture(t, true)), false)
			commercialIssue(t, c)
			correctionExec(t, `UPDATE team_billing_account SET stripe_subscription_status='active' WHERE team_id=$1`, c.TeamID)
			stripe := &fakeStripeClient{
				creditBalance:   api.StripeCreditBalance{AvailableUSD: 0, ObservedAt: time.Now().UTC()},
				grantBalanceUSD: 1000,
				grantBalanceErr: tc.grantErr,
			}
			w := do(newBillingRouter(t, stripe), "GET", "/billing/summary", seedKeyForExistingTeamWithRole(t, c.TeamID, "viewer"), "")
			if w.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
			}
			body := mustJSON(t, w)
			if body["credit_status"] != tc.status || body["stripe_remaining_credit_usd"] != tc.remaining {
				t.Fatalf("credit_status=%v stripe_remaining_credit_usd=%v", body["credit_status"], body["stripe_remaining_credit_usd"])
			}
		})
	}
}
