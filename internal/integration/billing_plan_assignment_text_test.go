//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestIntegration_StaffPlanAssignmentUnicodeFieldLimits(t *testing.T) {
	ctx := t.Context()
	team, _ := seedTeamAndKey(t)
	admin := seedPlatformAdminProfile(t)
	version, assignment := uuid.New(), uuid.New()
	family := "example_" + strings.ReplaceAll(version.String(), "-", "")
	if _, err := testPool.Exec(ctx, `INSERT INTO billing_plan_version(id,pricing_version,family,version,kind,display_name,max_sandboxes) VALUES($1,'v2',$2,1,'custom','Example plan',10)`, version, family); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `SELECT publish_billing_plan_version($1,$2)`, version, admin); err != nil {
		t.Fatal(err)
	}
	key, reason := strings.Repeat("😀", 200), strings.Repeat("😀", 2000)
	if _, err := testPool.Exec(ctx, `INSERT INTO team_plan_assignment(id,team_id,plan_key,kind,plan_version_id,terms,limits,effective_from,source,assigned_by,reason,idempotency_key) VALUES($1,$2,$7,'custom',$3,'{}','{"max_concurrent":10}',clock_timestamp(),'staff',$4,$5,$6)`, assignment, team, version, admin, reason, key, family); err != nil {
		t.Fatal(err)
	}
	r := newInternalRouter(t)
	path := "/internal/teams/" + team.String() + "/billing/plan-assignments"
	for _, tc := range []struct {
		name, key, reason string
		want              int
	}{
		{"maximum characters", key, reason, http.StatusOK},
		{"key exceeds maximum", key + "😀", reason, http.StatusBadRequest},
		{"reason exceeds maximum", key, reason + "😀", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{"idempotency_key": tc.key, "version_id": version, "reason": tc.reason})
			if err != nil {
				t.Fatal(err)
			}
			w := operatorRequest(r, http.MethodPost, path, admin.String(), string(body))
			if w.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tc.want, w.Body)
			}
			if tc.want == http.StatusOK && !strings.Contains(w.Body.String(), assignment.String()) {
				t.Fatalf("recorded assignment not replayed: %s", w.Body)
			}
		})
	}
	t.Run("escaped maximum characters", func(t *testing.T) {
		body := fmt.Sprintf(`{"idempotency_key":"%s","version_id":"%s","reason":"%s"}`, strings.Repeat(`\ud83d\ude00`, 200), version, strings.Repeat(`\ud83d\ude00`, 2000))
		w := operatorRequest(r, http.MethodPost, path, admin.String(), body)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), assignment.String()) {
			t.Fatalf("escaped replay status=%d body=%s", w.Code, w.Body)
		}
	})
	var count int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM team_plan_assignment WHERE team_id=$1`, team).Scan(&count); err != nil || count != 1 {
		t.Fatalf("validation/replay changed assignment history: %d %v", count, err)
	}
}
