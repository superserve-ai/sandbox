//go:build integration

package integration

import (
	"context"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestTrialWarningDiscoveryRetainedAndPagination(t *testing.T) {
	ctx := context.Background()
	tx, err := testPool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	q := db.New(tx)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	expected := map[uuid.UUID]bool{}
	for _, tc := range []struct {
		name                                                string
		activation, started                                 string
		closed, noGrant, ended, noInterval, duplicate, want bool
	}{
		{name: "retained only without billing account", activation: "-1 day", started: "-1 hour", want: true},
		{name: "duplicate grants", activation: "-1 day", started: "-1 hour", duplicate: true, want: true},
		{name: "future activation", activation: "1 day", started: "-1 hour"},
		{name: "activation boundary", activation: "0 seconds", started: "-1 hour"},
		{name: "future interval", activation: "-1 day", started: "1 hour"},
		{name: "closed interval", activation: "-1 day", started: "-1 hour", closed: true},
		{name: "no trial grant", activation: "-1 day", started: "-1 hour", noGrant: true},
		{name: "ended trial", activation: "-1 day", started: "-1 hour", ended: true},
		{name: "nonconsuming trial", activation: "-1 day", noInterval: true},
	} {
		team, err := q.CreateTeam(ctx, "discovery-"+uuid.NewString())
		if err != nil {
			t.Fatal(err)
		}
		expected[team.ID] = tc.want
		exec(`DELETE FROM team_credit_grant WHERE team_id=$1`, team.ID)
		if !tc.noGrant {
			exec(`INSERT INTO team_credit_grant(team_id,amount_usd,remaining_usd,reason) VALUES($1,5,5,'signup trial credit')`, team.ID)
			if tc.duplicate {
				exec(`INSERT INTO team_credit_grant(team_id,amount_usd,remaining_usd,reason) VALUES($1,5,5,'signup trial credit')`, team.ID)
			}
		}
		exec(`INSERT INTO team_storage_billing_activation(team_id,effective_at,approved_cutoff) VALUES($1,now()+$2::interval,now()+$2::interval)`, team.ID, tc.activation)
		if tc.ended {
			exec(`INSERT INTO team_billing_account(team_id,trial_ended_at) VALUES($1,now()) ON CONFLICT(team_id) DO UPDATE SET trial_ended_at=now()`, team.ID)
		}
		if !tc.noInterval {
			exec(`INSERT INTO retained_storage_interval(host_id,team_id,owner_kind,owner_id,generation,extents,started_at,ended_at) VALUES('test-host',$1,'snapshot',$2,'test','[]',now()+$3::interval,CASE WHEN $4 THEN now() END)`, team.ID, uuid.New(), tc.started, tc.closed)
		}
	}
	all, err := q.ListTrialCreditWarningTeams(ctx, db.ListTrialCreditWarningTeamsParams{BatchLimit: 100000})
	if err != nil {
		t.Fatal(err)
	}
	for team, want := range expected {
		if got := slices.Contains(all, team); got != want {
			t.Errorf("team %s discovered=%v, want %v", team, got, want)
		}
	}
	var paged []uuid.UUID
	var cursor pgtype.UUID
	for range len(all) + 1 {
		page, err := q.ListTrialCreditWarningTeams(ctx, db.ListTrialCreditWarningTeamsParams{AfterTeamID: cursor, BatchLimit: 1})
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			break
		}
		paged = append(paged, page...)
		cursor = pgtype.UUID{Bytes: page[len(page)-1], Valid: true}
	}
	if !slices.Equal(paged, all) {
		t.Fatalf("paged results %v differ from complete results %v", paged, all)
	}
}
