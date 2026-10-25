//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestIntegration_PlanChangeUnicodeFieldLimits(t *testing.T) {
	team, customerKey := seedTeamAndKey(t)
	admin := seedPlatformAdminProfile(t)
	assignment, change := uuid.New(), uuid.New()
	key, reason := strings.Repeat("😀", 200), strings.Repeat("😀", 2000)
	if _, err := testPool.Exec(t.Context(), `INSERT INTO team_plan_assignment(id,team_id,plan_key,kind,terms,limits,effective_from,source,reason)
        VALUES($1,$2,'example_plan','custom','{}','{"max_concurrent":10}',clock_timestamp(),'staff','example agreement')`, assignment, team); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(t.Context(), `INSERT INTO team_plan_change(id,team_id,from_assignment_id,target_plan_key,target_kind,target_terms,target_limits,effective_at,pauses_running,requested_by,requested_via,reason,idempotency_key)
        VALUES($1,$2,$3,'free','free','{}','{"max_concurrent":1}',clock_timestamp()+interval '2 days',true,$4,'customer',$5,$6)`, change, team, assignment, admin, reason, key); err != nil {
		t.Fatal(err)
	}
	customer, staff := newRouter(t), newInternalRouter(t)
	staffPath := "/internal/teams/" + team.String() + "/billing/plan-changes"
	for _, tc := range []struct {
		name, key, reason string
		escaped           bool
		want              int
	}{
		{"maximum", key, reason, false, http.StatusOK},
		{"escaped maximum", key, reason, true, http.StatusOK},
		{"oversized key", key + "😀", reason, false, http.StatusBadRequest},
		{"oversized reason", key, reason + "😀", false, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{"target_plan": "free", "idempotency_key": tc.key, "reason": tc.reason, "preview_token": strings.Repeat("a", 64), "confirm_pauses_running": true})
			if err != nil {
				t.Fatal(err)
			}
			payload := string(body)
			if tc.escaped {
				payload = strings.ReplaceAll(payload, "😀", `\ud83d\ude00`)
			}
			for _, w := range []*httptest.ResponseRecorder{
				do(customer, http.MethodPost, "/billing/plan-changes", customerKey, payload),
				operatorRequest(staff, http.MethodPost, staffPath, admin.String(), payload),
			} {
				if w.Code != tc.want || tc.want == http.StatusOK && !strings.Contains(w.Body.String(), change.String()) {
					t.Fatalf("schedule status=%d want=%d body=%s", w.Code, tc.want, w.Body)
				}
			}
		})
	}
	var count int
	if err := testPool.QueryRow(t.Context(), `SELECT count(*) FROM team_plan_change WHERE team_id=$1`, team).Scan(&count); err != nil || count != 1 {
		t.Fatalf("schedule validation/replay changed history: %d %v", count, err)
	}
	undoPath := staffPath + "/" + change.String() + "/undo"
	body, err := json.Marshal(map[string]string{"reason": reason + "😀"})
	if err != nil {
		t.Fatal(err)
	}
	if w := operatorRequest(staff, http.MethodPost, undoPath, admin.String(), string(body)); w.Code != http.StatusBadRequest {
		t.Fatalf("oversized undo accepted: %d %s", w.Code, w.Body)
	}
	var state string
	if err := testPool.QueryRow(t.Context(), `SELECT state FROM team_plan_change WHERE id=$1`, change).Scan(&state); err != nil || state != "scheduled" {
		t.Fatalf("invalid undo changed state: %s %v", state, err)
	}
	body, err = json.Marshal(map[string]string{"reason": reason})
	if err != nil {
		t.Fatal(err)
	}
	for _, payload := range []string{string(body), strings.ReplaceAll(string(body), "😀", `\ud83d\ude00`)} {
		if w := operatorRequest(staff, http.MethodPost, undoPath, admin.String(), payload); w.Code != http.StatusOK {
			t.Fatalf("valid undo/replay rejected: %d %s", w.Code, w.Body)
		}
	}
	var storedReason string
	if err := testPool.QueryRow(t.Context(), `SELECT state,undo_reason FROM team_plan_change WHERE id=$1`, change).Scan(&state, &storedReason); err != nil || state != "undone" || storedReason != reason {
		t.Fatalf("undo reason changed: %s %v", state, err)
	}
}
