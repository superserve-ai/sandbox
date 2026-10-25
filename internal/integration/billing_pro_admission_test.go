//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"net/http"
	"testing"
)

func TestIntegration_ProKnownOfferRejectsPreparingBeforeProvider(t *testing.T) {
	f, r, key := newProFixture(t, "pro_monthly")
	if _, err := testPool.Exec(t.Context(), `UPDATE billing_pricing_switch SET pricing_version='v2' WHERE singleton`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := testPool.Exec(context.Background(), `UPDATE billing_pricing_switch SET pricing_version='legacy' WHERE singleton`); err != nil {
			t.Error(err)
		}
	})
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody("pro_monthly"), http.StatusConflict, "plan_conflict")
	f.mu.Lock()
	creates, prices := f.creates, len(f.priceCreates)
	f.mu.Unlock()
	if creates != 0 || prices != 0 {
		t.Fatalf("closed entry touched provider: sessions=%d prices=%d", creates, prices)
	}
	var state string
	var intents, contracts int
	if err := testPool.QueryRow(t.Context(), `SELECT state,(SELECT count(*) FROM billing_pro_upgrade WHERE team_id=$1),(SELECT count(*) FROM billing_commercial_contract WHERE team_id=$1) FROM billing_signup_choice WHERE team_id=$1`, f.team).Scan(&state, &intents, &contracts); err != nil {
		t.Fatal(err)
	}
	if state != "selecting" || intents != 0 || contracts != 0 {
		t.Fatalf("closed entry committed authority: %s/%d/%d", state, intents, contracts)
	}
}

func TestIntegration_ProReleasedAcceptanceAndOperationReplay(t *testing.T) {
	if _, err := testPool.Exec(t.Context(), `UPDATE billing_pricing_switch SET pricing_version='v2' WHERE singleton`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `UPDATE billing_pricing_switch SET pricing_version='legacy' WHERE singleton`)
	})
	var epoch uuid.UUID
	if err := testPool.QueryRow(t.Context(), `SELECT epoch FROM billing_pricing_adoption WHERE singleton`).Scan(&epoch); err != nil {
		t.Fatal(err)
	}
	evidence, _ := json.Marshal(map[string]any{"epoch": epoch.String(), "region": "usw", "system_team_id": testSystemTeamID.String(), "assembled_sha": "1111111111111111111111111111111111111111", "schema_sha": "1111111111111111111111111111111111111111", "worker_sha": "1111111111111111111111111111111111111111", "verified_worker": true, "deployment_reference": "disposable-fixture", "worker_reference": "disposable-fixture"})
	if _, err := testPool.Exec(t.Context(), `UPDATE billing_pricing_adoption SET region='usw',system_team_id=$1,state='released',released_at=clock_timestamp(),evidence=$2 WHERE singleton`, testSystemTeamID, evidence); err != nil {
		t.Fatal(err)
	}
	f, r, key := newProFixture(t, "pro_monthly")
	var body map[string]any
	if err := json.Unmarshal([]byte(proCheckoutBody("pro_monthly")), &body); err != nil {
		t.Fatal(err)
	}
	op := uuid.New()
	body["operation_id"] = op.String()
	request, _ := json.Marshal(body)
	assertProResponse(t, r, key, "/stripe/checkout-session", string(request), http.StatusAccepted, "payment_confirmation_pending")
	var frozen bool
	if err := testPool.QueryRow(t.Context(), `SELECT id=$2 AND request_payload->'PlanTerms'->>'PricingV2'='true' AND initial_assignment_id=(SELECT id FROM team_plan_assignment WHERE team_id=$1 AND effective_to IS NULL) FROM billing_pro_upgrade WHERE team_id=$1`, f.team, op).Scan(&frozen); err != nil || !frozen {
		t.Fatalf("released intent/predecessor not frozen: %v %v", frozen, err)
	}
	f.mu.Lock()
	prices := len(f.priceCreates)
	f.mu.Unlock()
	if _, err := testPool.Exec(t.Context(), `UPDATE billing_pricing_switch SET pricing_version='legacy' WHERE singleton`); err != nil {
		t.Fatal(err)
	}
	assertProResponse(t, r, key, "/stripe/checkout-session", string(request), http.StatusAccepted, "payment_confirmation_pending")
	body["operation_id"] = uuid.NewString()
	changed, _ := json.Marshal(body)
	assertProResponse(t, r, key, "/stripe/checkout-session", string(changed), http.StatusConflict, "plan_conflict")
	f.mu.Lock()
	after := len(f.priceCreates)
	f.mu.Unlock()
	if prices != after {
		t.Fatalf("frozen replay created prices: %s", fmt.Sprint(prices, after))
	}
}
