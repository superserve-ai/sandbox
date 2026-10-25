//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestIntegration_BillingPlanWithoutAssignment(t *testing.T) {
	teamID, key := seedTeamAndKey(t)
	r := newRouter(t)
	w := do(r, "GET", "/billing/plan", key, "")
	var body struct {
		Plan   *json.RawMessage `json:"plan"`
		Period struct {
			Start time.Time `json:"start"`
			End   time.Time `json:"end"`
		} `json:"period"`
		Pending *json.RawMessage `json:"pending_change"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &body) != nil {
		t.Fatalf("billing plan: %d %s", w.Code, w.Body.String())
	}
	if body.Plan != nil || body.Pending != nil || !body.Period.End.After(body.Period.Start) {
		t.Fatalf("team %s without an assignment: %s", teamID, w.Body.String())
	}
}

func TestIntegration_BillingPlanIgnoresAssignmentsWhilePricingV2IsOff(t *testing.T) {
	ctx := context.Background()
	teamID, key := seedTeamAndKey(t)
	if _, err := testPool.Exec(ctx, `INSERT INTO team_plan_assignment(team_id,plan_key,kind,terms,limits,effective_from,source,reason)
        VALUES($1,'starter','prepaid','{"display_name":"Starter"}','{"max_concurrent":100}',clock_timestamp(),'credit_purchase','first purchase')`, teamID); err != nil {
		t.Fatal(err)
	}
	r := newRouter(t)
	w := do(r, "GET", "/billing/plan", key, "")
	var body struct {
		Plan *json.RawMessage `json:"plan"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Plan != nil {
		t.Fatalf("assignment shown while pricing v2 is off: %d %s", w.Code, w.Body.String())
	}
	w = do(r, "GET", "/billing/plan-change-preview?target_plan=pro_monthly", key, "")
	var preview struct {
		Blocked string `json:"blocked"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &preview) != nil || preview.Blocked == "" {
		t.Fatalf("plan change previewed while pricing v2 is off: %d %s", w.Code, w.Body.String())
	}
}


func TestIntegration_BillingPlanUnderPricingV2(t *testing.T) {
	ctx := context.Background()
	internal := newInternalRouter(t)
	admin := seedPlatformAdminProfile(t).String()
	if w := operatorRequest(internal, http.MethodPost, "/internal/billing/pricing-version", admin, `{"pricing_version":"v2","reason":"plan read test"}`); w.Code != http.StatusOK {
		t.Fatalf("flip to v2: %d %s", w.Code, w.Body)
	}
	t.Cleanup(func() {
		if w := operatorRequest(internal, http.MethodPost, "/internal/billing/pricing-version", admin, `{"pricing_version":"legacy","reason":"test cleanup"}`); w.Code != http.StatusOK {
			t.Errorf("restore switch: %d %s", w.Code, w.Body)
		}
	})
	teamID, key := seedTeamAndKey(t)
	viewerKey := seedKeyForExistingTeamWithRole(t, teamID, "viewer")
	if _, err := testPool.Exec(ctx, `UPDATE team_plan_assignment SET effective_to=clock_timestamp() WHERE team_id=$1 AND effective_to IS NULL`, teamID); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `INSERT INTO team_plan_assignment(team_id,plan_key,kind,terms,limits,effective_from,source,reason)
        VALUES($1,'starter','prepaid','{"display_name":"Starter"}','{"max_concurrent":100,"max_vcpu":2}',clock_timestamp(),'credit_purchase','first purchase')`, teamID); err != nil {
		t.Fatal(err)
	}
	r := newRouter(t)
	for _, k := range []string{key, viewerKey} {
		w := do(r, "GET", "/billing/plan", k, "")
		var body struct {
			Plan *struct {
				PlanKey     string `json:"plan_key"`
				Kind        string `json:"kind"`
				DisplayName string `json:"display_name"`
				Limits      struct {
					MaxConcurrent *int32 `json:"max_concurrent"`
					MaxVCPU       *int32 `json:"max_vcpu"`
				} `json:"limits"`
			} `json:"plan"`
		}
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Plan == nil {
			t.Fatalf("billing plan: %d %s", w.Code, w.Body.String())
		}
		p := body.Plan
		if p.PlanKey != "starter" || p.Kind != "prepaid" || p.DisplayName != "Starter" || p.Limits.MaxConcurrent == nil || *p.Limits.MaxConcurrent != 100 || p.Limits.MaxVCPU == nil || *p.Limits.MaxVCPU != 2 {
			t.Fatalf("plan not reported: %s", w.Body.String())
		}
	}
	w := do(r, "GET", "/billing/plan-change-preview?target_plan=pro_monthly", key, "")
	var preview struct {
		Timing  string `json:"timing"`
		Blocked string `json:"blocked"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &preview) != nil || preview.Blocked != "" || preview.Timing != "after_purchase" {
		t.Fatalf("starter team's upgrade preview: %d %s", w.Code, w.Body.String())
	}
}
