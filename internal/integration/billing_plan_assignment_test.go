//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
	upgradeResponse := do(r, http.MethodGet, "/billing/plan-change-preview?target_plan=pro_monthly", key, "")
	var upgrade struct {
		Timing       string `json:"timing"`
		Blocked      string `json:"blocked"`
		PreviewToken string `json:"preview_token"`
	}
	if upgradeResponse.Code != http.StatusOK || json.Unmarshal(upgradeResponse.Body.Bytes(), &upgrade) != nil || upgrade.Blocked == "" || upgrade.Timing != "" || upgrade.PreviewToken != "" {
		t.Fatalf("upgrade offered before adoption release: %d %s", upgradeResponse.Code, upgradeResponse.Body)
	}
	if w := operatorRequest(internal, http.MethodPost, "/internal/billing/pricing-version", admin, `{"pricing_version":"legacy","reason":"test entry gate"}`); w.Code != http.StatusOK {
		t.Fatal(w.Body.String())
	}
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
	w := do(r, "GET", "/billing/plan-change-preview?target_plan=free", key, "")
	var preview struct {
		Timing  string `json:"timing"`
		Blocked string `json:"blocked"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &preview) != nil {
		t.Fatalf("preview: %d %s", w.Code, w.Body)
	}
	if !planChangePauseSupportAvailable(t) {
		if preview.Blocked == "" || preview.Timing != "" {
			t.Fatalf("Free offered before pause deployment: %s", w.Body)
		}
		return
	}
	if preview.Blocked != "" || preview.Timing != "immediate" {
		t.Fatalf("starter team's upgrade preview: %d %s", w.Code, w.Body.String())
	}
}

func TestIntegration_BillingPlanChangeWrites(t *testing.T) {
	teamID, key := seedTeamAndKey(t)
	viewerKey := seedKeyForExistingTeamWithRole(t, teamID, "viewer")
	r := newRouter(t)
	body := `{"target_plan":"free","idempotency_key":"k1"}`
	if w := do(r, "POST", "/billing/plan-changes", viewerKey, body); w.Code != http.StatusForbidden {
		t.Fatalf("viewer scheduled a plan change: %d %s", w.Code, w.Body.String())
	}
	if w := do(r, "POST", "/billing/plan-changes", key, `{"target_plan":"free","idempotency_key":"k1","expires_at":"x"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown field accepted: %d", w.Code)
	}
	if w := do(r, "POST", "/billing/plan-changes", key, body); w.Code != http.StatusBadRequest && w.Code != http.StatusConflict {
		t.Fatalf("team without a plan changed plans: %d %s", w.Code, w.Body.String())
	}
	if w := do(r, "POST", "/billing/plan-changes/"+teamID.String()+"/undo", key, ""); w.Code != http.StatusNotFound {
		t.Fatalf("undo of an unknown change: %d %s", w.Code, w.Body.String())
	}
}

func TestIntegration_BillingPlanChangeStaffPendingAndUndoReason(t *testing.T) {
	team, key := seedTeamAndKey(t)
	if _, err := testPool.Exec(t.Context(), `INSERT INTO team_plan_assignment(team_id,plan_key,kind,terms,limits,effective_from,source,reason)
        VALUES($1,'custom_example','custom','{"display_name":"Example plan"}','{"max_concurrent":100}',clock_timestamp(),'staff','agreement')`, team); err != nil {
		t.Fatal(err)
	}
	anchor := time.Now().UTC().AddDate(0, -1, 0).Add(30 * time.Minute).Truncate(time.Second)
	if _, err := testPool.Exec(t.Context(), `INSERT INTO team_billing_account(team_id,commercial_billing_anchor) VALUES($1,$2)`, team, anchor); err != nil {
		t.Fatal(err)
	}
	previewResponse := do(newRouter(t), http.MethodGet, "/billing/plan-change-preview?target_plan=free", key, "")
	var preview struct {
		EffectiveAt time.Time `json:"effective_at"`
		Blocked     string    `json:"blocked"`
	}
	if previewResponse.Code != http.StatusOK || json.Unmarshal(previewResponse.Body.Bytes(), &preview) != nil || preview.Blocked == "" && !preview.EffectiveAt.After(time.Now().Add(24*time.Hour)) {
		t.Fatalf("preview ignored minimum notice: %d %s", previewResponse.Code, previewResponse.Body)
	}
	staff := seedPlatformAdminProfile(t).String()
	router := newInternalRouter(t)
	path := "/internal/teams/" + team.String() + "/billing/plan-changes"
	w := operatorRequest(router, http.MethodPost, path, staff, `{"target_plan":"free","idempotency_key":"staff-exit","reason":"end agreement"}`)
	var change struct {
		ID          string    `json:"id"`
		EffectiveAt time.Time `json:"effective_at"`
	}
	if !planChangePauseSupportAvailable(t) {
		if preview.Blocked == "" || w.Code != http.StatusConflict {
			t.Fatalf("staff Free accepted before pause deployment: %d %s", w.Code, w.Body)
		}
		if err := testPool.QueryRow(t.Context(), `INSERT INTO team_plan_change(team_id,from_assignment_id,target_plan_key,target_kind,target_terms,target_limits,effective_at,pauses_running,requested_by,requested_via,reason,idempotency_key)
            SELECT team_id,id,'free','free','{}','{"max_concurrent":1}',clock_timestamp()+interval '2 days',true,$2,'staff','committed exit','staff-exit'
            FROM team_plan_assignment WHERE team_id=$1 AND effective_to IS NULL RETURNING id::text,effective_at`, team, staff).Scan(&change.ID, &change.EffectiveAt); err != nil {
			t.Fatal(err)
		}
	} else {
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &change) != nil || change.ID == "" {
			t.Fatalf("staff exit while entry off: %d %s", w.Code, w.Body)
		}
		if !change.EffectiveAt.Equal(preview.EffectiveAt) {
			t.Fatalf("preview and scheduling disagree: %s != %s", preview.EffectiveAt, change.EffectiveAt)
		}
	}
	for index, response := range []*httptest.ResponseRecorder{
		doInternal(router, http.MethodGet, "/internal/teams/"+team.String()+"/billing/plan-assignments", staff, ""),
		do(newRouter(t), http.MethodGet, "/billing/plan", key, ""),
	} {
		var body struct {
			Pending *struct {
				ID            string `json:"id"`
				Undoable      bool   `json:"undoable"`
				PausesRunning bool   `json:"pauses_running"`
			} `json:"pending_change"`
		}
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &body) != nil || body.Pending == nil || body.Pending.ID != change.ID || body.Pending.Undoable != (index == 0) || !body.Pending.PausesRunning {
			t.Fatalf("pending exit missing from billing read: %d %s", response.Code, response.Body)
		}
	}
	if w := do(newRouter(t), http.MethodPost, "/billing/plan-changes/"+change.ID+"/undo", key, ""); w.Code != http.StatusNotFound {
		t.Fatalf("customer undid staff-originated change: %d %s", w.Code, w.Body)
	}
	var state string
	if err := testPool.QueryRow(t.Context(), `SELECT state FROM team_plan_change WHERE id=$1`, change.ID).Scan(&state); err != nil || state != "scheduled" {
		t.Fatalf("denied customer undo mutated staff change: %s %v", state, err)
	}
	undo := path + "/" + change.ID + "/undo"
	if w := operatorRequest(router, http.MethodPost, undo, staff, `{}`); w.Code != http.StatusBadRequest {
		t.Fatalf("staff undo accepted without reason: %d %s", w.Code, w.Body)
	}
	if w := operatorRequest(router, http.MethodPost, undo, staff, `{"reason":"keep agreement"}`); w.Code != http.StatusOK {
		t.Fatalf("staff undo failed with entry off: %d %s", w.Code, w.Body)
	}
	var reason string
	if err := testPool.QueryRow(t.Context(), `SELECT undo_reason FROM team_plan_change WHERE id=$1`, change.ID).Scan(&reason); err != nil || reason != "keep agreement" {
		t.Fatalf("undo reason not recorded: %q %v", reason, err)
	}
	w = doInternal(router, http.MethodGet, "/internal/teams/"+team.String()+"/billing/plan-assignments", staff, "")
	var body struct {
		Pending *json.RawMessage `json:"pending_change"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Pending != nil {
		t.Fatalf("undone change still pending: %d %s", w.Code, w.Body)
	}
}

func TestIntegration_BillingPlanChangeCustomerConsent(t *testing.T) {
	team, key := seedTeamAndKey(t)
	if _, err := testPool.Exec(t.Context(), `INSERT INTO team_plan_assignment(team_id,plan_key,kind,terms,limits,effective_from,source,reason)
        VALUES($1,'custom_example','custom','{"display_name":"Example"}','{"max_concurrent":100}',clock_timestamp(),'staff','agreement')`, team); err != nil {
		t.Fatal(err)
	}
	r := newRouter(t)
	w := do(r, http.MethodGet, "/billing/plan-change-preview?target_plan=free", key, "")
	var preview struct {
		Token       string    `json:"preview_token"`
		EffectiveAt time.Time `json:"effective_at"`
		Blocked     string    `json:"blocked"`
	}
	if !planChangePauseSupportAvailable(t) {
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &preview) != nil || preview.Blocked == "" || preview.Token != "" {
			t.Fatalf("Free preview not blocked before deployment: %d %s", w.Code, w.Body)
		}
		body := `{"target_plan":"free","idempotency_key":"unavailable","preview_token":"` + strings.Repeat("a", 64) + `","expected_effective_at":"` + time.Now().Add(48*time.Hour).Format(time.RFC3339Nano) + `","confirm_pauses_running":true}`
		if w := do(r, http.MethodPost, "/billing/plan-changes", key, body); w.Code != http.StatusConflict {
			t.Fatalf("customer Free accepted before deployment: %d %s", w.Code, w.Body)
		}
		var count int
		if err := testPool.QueryRow(t.Context(), `SELECT count(*) FROM team_plan_change WHERE team_id=$1`, team).Scan(&count); err != nil || count != 0 {
			t.Fatalf("unavailable Free created work: %d %v", count, err)
		}
		return
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &preview) != nil || len(preview.Token) != 64 {
		t.Fatalf("exit preview missing consent token with entry off: %d %s", w.Code, w.Body)
	}
	for _, body := range []string{
		`{"target_plan":"free","idempotency_key":"consent","confirm_pauses_running":true}`,
		`{"target_plan":"free","idempotency_key":"consent","preview_token":"` + preview.Token + `"}`,
	} {
		if w := do(r, http.MethodPost, "/billing/plan-changes", key, body); w.Code != http.StatusBadRequest {
			t.Fatalf("missing consent accepted: %d %s", w.Code, w.Body)
		}
	}
	body := `{"target_plan":"free","idempotency_key":"consent","preview_token":"` + preview.Token + `","confirm_pauses_running":true}`
	if w := do(r, http.MethodPost, "/billing/plan-changes", key, body); w.Code != http.StatusConflict {
		t.Fatalf("scheduled date precondition was optional: %d %s", w.Code, w.Body)
	}
	stale := `{"target_plan":"free","idempotency_key":"consent","preview_token":"` + preview.Token + `","expected_effective_at":"` + preview.EffectiveAt.Add(time.Second).Format(time.RFC3339Nano) + `","confirm_pauses_running":true}`
	if w := do(r, http.MethodPost, "/billing/plan-changes", key, stale); w.Code != http.StatusConflict {
		t.Fatalf("changed confirmed date accepted: %d %s", w.Code, w.Body)
	}
	body = `{"target_plan":"free","idempotency_key":"consent","preview_token":"` + preview.Token + `","expected_effective_at":"` + preview.EffectiveAt.Format(time.RFC3339Nano) + `","confirm_pauses_running":true}`
	w = do(r, http.MethodPost, "/billing/plan-changes", key, body)
	var change struct {
		ID string `json:"id"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &change) != nil || change.ID == "" {
		t.Fatalf("confirmed exit refused with entry off: %d %s", w.Code, w.Body)
	}
	read := do(r, http.MethodGet, "/billing/plan", key, "")
	var active struct {
		Plan *struct {
			Key string `json:"plan_key"`
		} `json:"plan"`
		Pending *struct {
			ID string `json:"id"`
		} `json:"pending_change"`
	}
	if read.Code != http.StatusOK || json.Unmarshal(read.Body.Bytes(), &active) != nil || active.Plan == nil || active.Plan.Key != "custom_example" || active.Pending == nil || active.Pending.ID != change.ID {
		t.Fatalf("entry rollback hid the current assignment or pending exit: %d %s", read.Code, read.Body)
	}
	if w = do(r, http.MethodPost, "/billing/plan-changes/"+change.ID+"/undo", key, ""); w.Code != http.StatusOK {
		t.Fatalf("undo refused with entry off: %d %s", w.Code, w.Body)
	}
}

func planChangePauseSupportAvailable(t *testing.T) bool {
	t.Helper()
	var available bool
	if err := testPool.QueryRow(t.Context(), `SELECT to_regprocedure('request_team_pause_all(uuid,text)') IS NOT NULL`).Scan(&available); err != nil {
		t.Fatal(err)
	}
	return available
}
