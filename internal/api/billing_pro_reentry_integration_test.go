//go:build integration

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/billing"
)

func TestProRepeatAcceptanceFreezesReleaseAndSurvivesOffWithBoundReplay(t *testing.T) {
	testProRepeatAcceptanceCredit(t, 25000)
}

func TestProUpgradeAcceptanceFreezesIndependentCredit(t *testing.T) {
	for _, credit := range []int64{50000, 10000, 1} {
		t.Run(fmt.Sprint(credit), func(t *testing.T) { testProRepeatAcceptanceCredit(t, credit) })
	}
}

func testProRepeatAcceptanceCredit(t *testing.T, monthlyCredit int64) {
	f := newPlanChangeV2Fixture(t, planKindSubscription)
	f.committedCheckout(t)
	change, err := f.request(t, "starter", "repeat-admission")
	if err != nil {
		t.Fatal(err)
	}
	f.stripe.set(func(s *renewalStripe) { s.status, s.endedAt = "canceled", time.Now().Add(-time.Minute).Unix() })
	f.tick(t)
	if c := f.reload(t, change.ID); c.State != "completed" {
		t.Fatalf("release: %+v", c)
	}
	previous := f.plan(t)
	var anchor time.Time
	if err = f.h.Pool.QueryRow(t.Context(), `SELECT commercial_billing_anchor FROM team_billing_account WHERE team_id=$1`, f.team).Scan(&anchor); err != nil {
		t.Fatal(err)
	}
	if _, err = f.h.Pool.Exec(t.Context(), `UPDATE billing_pricing_switch SET pricing_version='v2' WHERE singleton`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.h.Pool.Exec(context.Background(), `UPDATE billing_pricing_switch SET pricing_version='legacy' WHERE singleton`)
	})
	var epoch uuid.UUID
	if err = f.h.Pool.QueryRow(t.Context(), `SELECT epoch FROM billing_pricing_adoption WHERE singleton`).Scan(&epoch); err != nil {
		t.Fatal(err)
	}
	system := uuid.New()
	evidence, _ := json.Marshal(map[string]any{"epoch": epoch.String(), "region": "usw", "system_team_id": system.String(), "assembled_sha": "1111111111111111111111111111111111111111", "schema_sha": "1111111111111111111111111111111111111111", "worker_sha": "1111111111111111111111111111111111111111", "verified_worker": true, "deployment_reference": "disposable-fixture", "worker_reference": "disposable-fixture"})
	if _, err = f.h.Pool.Exec(t.Context(), `UPDATE billing_pricing_adoption SET region='usw',system_team_id=$1,state='released',released_at=clock_timestamp(),evidence=$2 WHERE singleton`, system, evidence); err != nil {
		t.Fatal(err)
	}
	admission, err := f.h.publicPricingState(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	key := publishProCreditTestOffer(t, f.h, monthlyCredit)
	terms, err := f.h.planTermsForPricingVersion(t.Context(), key, "v2")
	if err != nil {
		t.Fatal(err)
	}
	offer := proOffer{Key: terms.OfferKey, Name: terms.DisplayName, Price: "price_repeat", Amount: terms.FeeCents, Months: 1, Credit: terms.MonthlyCreditCents, VersionID: terms.VersionID, Version: terms.Version, Family: terms.Family, Pricing: "v2", Limits: &terms.Limits, Grants: terms.Grants, Allowance: terms.Allowance, PricingV2: true}
	start, end, ok := billing.AnniversaryPeriod(anchor, time.Now())
	if !ok {
		t.Fatal("invalid calendar")
	}
	quote := start.Add(end.Sub(start)/2 + time.Second)
	f.h.Now = func() time.Time { return quote }
	expectedFee, _ := proratedProAmount(offer.Amount, start, end, quote)
	expectedCredit, _ := proratedProAmount(monthlyCredit, start, end, quote)
	op := uuid.New()
	params := StripeCreateCheckoutSessionParams{OperationID: op, CustomerID: f.stripe.customer, ClientReferenceID: f.team.String(), BasePriceID: offer.Price, AllowPromotionCodes: true, PlanTerms: &StripeCheckoutPlanTerms{Amount: offer.Amount, Months: 1, Credit: offer.Credit, VersionID: offer.VersionID, Version: offer.Version, Family: offer.Family, DisplayName: offer.Name, PricingV2: true, Limits: offer.Limits, Grants: offer.Grants, Allowance: offer.Allowance}}
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "provider temporarily unavailable", 503) }))
	defer provider.Close()
	f.h.Stripe = &stripeHTTPClient{baseURL: provider.URL, apiVersion: "2026-07-29.dahlia", httpClient: provider.Client()}
	response := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(response)
	c.Request = httptest.NewRequest(http.MethodPost, "/stripe/pro-checkout", nil)
	f.h.createProUpgrade(c, f.team, f.actor, offer, params, admission)
	if response.Code != http.StatusAccepted {
		t.Fatalf("repeat paid acceptance: %d %s", response.Code, response.Body.String())
	}
	accepted, err := f.h.proUpgrade(t.Context(), f.team)
	if err != nil || accepted.Amount != expectedFee || accepted.BridgeCredit == nil || accepted.bridgeCreditAmount() != expectedCredit {
		t.Fatalf("independent durable quote: %+v %v", accepted, err)
	}
	if _, err = f.h.Pool.Exec(t.Context(), `UPDATE billing_pro_upgrade SET bridge_credit_cents=bridge_credit_cents+1 WHERE id=$1`, op); err == nil {
		t.Fatal("accepted bridge credit changed")
	}
	var bound bool
	if err = f.h.Pool.QueryRow(t.Context(), `SELECT u.initial_assignment_id=$2 AND u.anchor=$3 AND u.request_payload->>'ReleaseID'=r.id::text
 AND b.trial_ended_at IS NOT NULL AND b.stripe_subscription_id IS NULL
 AND (SELECT count(*)=1 FROM billing_commercial_contract WHERE team_id=$1)
 FROM billing_pro_upgrade u JOIN team_billing_account b USING(team_id) JOIN billing_plan_release r ON r.plan_change_id=$4 WHERE u.id=$5 AND u.team_id=$1`, f.team, previous.ID, anchor, change.ID, op).Scan(&bound); err != nil || !bound {
		t.Fatalf("repeat acceptance lost frozen provenance: %v %v", bound, err)
	}
	if _, err = f.h.Pool.Exec(t.Context(), `UPDATE billing_pricing_switch SET pricing_version='legacy' WHERE singleton`); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		actor, operation uuid.UUID
		status           int
	}{{f.actor, op, http.StatusAccepted}, {f.actor, uuid.New(), http.StatusConflict}, {uuid.New(), op, http.StatusConflict}} {
		response = httptest.NewRecorder()
		c, _ = gin.CreateTestContext(response)
		c.Request = httptest.NewRequest(http.MethodPost, "/stripe/pro-checkout", nil)
		f.h.createProCheckout(c, f.team, tc.actor, billingCheckoutSessionRequest{OperationID: tc.operation, Offer: key})
		if response.Code != tc.status {
			t.Fatalf("OFF replay actor=%s operation=%s: %d %s", tc.actor, tc.operation, response.Code, response.Body.String())
		}
	}
}

func publishProCreditTestOffer(t *testing.T, h *Handlers, monthlyCredit int64) string {
	t.Helper()
	var err error
	key := "pro_monthly"
	if monthlyCredit != 25000 {
		family := "credit" + strings.ReplaceAll(uuid.NewString(), "-", "")
		versionID := uuid.New()
		_, err = h.Pool.Exec(t.Context(), `INSERT INTO billing_plan_version SELECT (jsonb_populate_record(NULL::billing_plan_version,to_jsonb(v)||jsonb_build_object('id',$1::text,'family',$2::text,'version',1,'state','draft','published_at',NULL,'published_by',NULL,'credit_schedule',jsonb_build_array(jsonb_build_object('start_months',0,'every_months',1,'amount_cents',$3::bigint,'expires_after_months',1))))).* FROM billing_plan_version v WHERE family='pro' AND pricing_version='v2' AND state='published'`, versionID, family, monthlyCredit)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = h.Pool.Exec(t.Context(), `SELECT publish_billing_plan_version($1,NULL)`, versionID); err != nil {
			t.Fatal(err)
		}
		key = family + "_monthly"
	}
	return key
}
