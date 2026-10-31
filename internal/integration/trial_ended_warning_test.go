//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestIntegration_NewTeamTrialEmailsOnceWhenItEnds(t *testing.T) {
	pool, system, actor := cohortFixture(t)
	cohortRelease(t, pool, system)
	team := cohortCreate(t, pool, actor)
	rolloutExec(t, pool, `INSERT INTO team_memberships(team_id,user_id,status) VALUES($1,$2,'active') ON CONFLICT DO NOTHING`, team, actor)
	rolloutExec(t, pool, `INSERT INTO user_role_assignments(user_id,role_id,scope_type,team_id) SELECT $2,id,'team',$1 FROM roles WHERE name='team_owner'
 AND NOT EXISTS(SELECT 1 FROM user_role_assignments a WHERE a.user_id=$2 AND a.team_id=$1 AND a.role_id=roles.id)`, team, actor)
	ctx := context.Background()
	q := db.New(pool)
	var mu sync.Mutex
	var subjects []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Subject, HTML string }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		mu.Lock()
		subjects = append(subjects, body.Subject)
		mu.Unlock()
		if !strings.Contains(body.HTML, "Nothing has been deleted") {
			t.Errorf("trial ended email lacks its copy: %s", body.HTML)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	h := &api.Handlers{DB: q, TrialWarningSender: api.NewTrialCreditWarningSenderForTest(q, server.URL, server.Client())}
	discovered := func() bool {
		t.Helper()
		teams, err := q.ListTrialCreditWarningTeams(ctx, db.ListTrialCreditWarningTeamsParams{BatchLimit: 100000})
		if err != nil {
			t.Fatal(err)
		}
		return slices.Contains(teams, team)
	}

	b, err := q.GetTeamTrialBalance(ctx, team)
	if err != nil {
		t.Fatal(err)
	}
	if b.Kind != "trial" || b.State != "active" || b.LowCreditUsd.Valid {
		t.Fatalf("running trial balance = %+v", b)
	}
	api.ProcessTrialCreditWarningForTest(h, ctx, team)
	var runway int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM team_trial_runway WHERE team_id=$1`, team).Scan(&runway); err != nil {
		t.Fatal(err)
	}
	if discovered() || len(subjects) != 0 || runway != 0 {
		t.Fatalf("running trial was warned or forecast: discovered=%v emails=%v runway=%d", discovered(), subjects, runway)
	}

	rolloutExec(t, pool, `INSERT INTO team_trial_eligibility_cache(team_id,eligible,updated_at) VALUES($1,false,now())
 ON CONFLICT(team_id) DO UPDATE SET eligible=false,updated_at=now()`, team)
	var entry string
	if err := pool.QueryRow(ctx, `SELECT billing_team_entry_state($1)`, team).Scan(&entry); err != nil || entry != "trial_ended" {
		t.Fatalf("entry state = %s, %v", entry, err)
	}
	settling := uuid.New()
	rolloutExec(t, pool, `SET session_replication_role=replica;
 INSERT INTO billing_pro_upgrade(id,team_id,actor_id,customer_id,offer_key,request_payload,anchor,period_start,period_end,quoted_at,amount_cents,state,payment_evidence)
 VALUES('`+settling.String()+`','`+team.String()+`','`+actor.String()+`','cus_fixture','developer_monthly','{}',now(),now(),now()+interval '1 month',now(),100,'paid','{}');
 RESET session_replication_role`)
	api.ProcessTrialCreditWarningForTest(h, ctx, team)
	if discovered() || len(subjects) != 0 {
		t.Fatalf("told a team whose checkout is settling that its trial ended: %v", subjects)
	}
	rolloutExec(t, pool, `SET session_replication_role=replica; UPDATE billing_pro_upgrade SET state='expired' WHERE id='`+settling.String()+`'; RESET session_replication_role`)
	if !discovered() {
		t.Fatal("ended trial was not discovered")
	}
	for range 2 {
		api.ProcessTrialCreditWarningForTest(h, ctx, team)
	}
	if len(subjects) != 1 || !strings.Contains(subjects[0], "free trial has ended") {
		t.Fatalf("ended trial emails = %v, want exactly one", subjects)
	}
	if discovered() {
		t.Fatal("a warned trial stays in discovery")
	}
}

func TestIntegration_NewTeamTrialWithoutGrantIsNotEmailed(t *testing.T) {
	pool, system, actor := cohortFixture(t)
	cohortRelease(t, pool, system)
	team := cohortCreate(t, pool, actor)
	rolloutExec(t, pool, `DELETE FROM team_credit_grant WHERE team_id=$1`, team)
	q := db.New(pool)
	teams, err := q.ListTrialCreditWarningTeams(context.Background(), db.ListTrialCreditWarningTeamsParams{BatchLimit: 100000})
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(teams, team) {
		t.Fatal("a team that never had trial credit is told its trial ended")
	}
}
