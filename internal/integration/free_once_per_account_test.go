//go:build integration

package integration

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func freeOnceCreate(t *testing.T, pool *pgxpool.Pool, user uuid.UUID, additional bool) uuid.UUID {
	t.Helper()
	op, name := uuid.New(), "team-"+uuid.NewString()
	var raw []byte
	if err := pool.QueryRow(t.Context(), `SELECT prepare_team_promotion_creation($1,$2,$3,'use',false,$4)`, op, user, name, additional).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var prepared struct {
		AttemptID uuid.UUID `json:"attempt_id"`
		TeamID    uuid.UUID `json:"team_id"`
	}
	if err := json.Unmarshal(raw, &prepared); err != nil {
		t.Fatal(err)
	}
	rolloutExec(t, pool, `SELECT complete_team_promotion_creation($1,$2,$3,$4,$5,'use',false,$6)`, op, prepared.AttemptID, prepared.TeamID, user, name, additional)
	return prepared.TeamID
}

func freeOnceState(t *testing.T, pool *pgxpool.Pool, team uuid.UUID) (entry string, free, eligible bool) {
	t.Helper()
	if err := pool.QueryRow(t.Context(), `SELECT billing_team_entry_state($1),
  EXISTS(SELECT 1 FROM team_plan_assignment WHERE team_id=$1 AND effective_to IS NULL AND kind='free'),
  team_sandbox_billing_eligible($1)`, team).Scan(&entry, &free, &eligible); err != nil {
		t.Fatal(err)
	}
	return entry, free, eligible
}

func TestIntegration_FreeOncePerAccount(t *testing.T) {
	pool, system, actor := cohortFixture(t)
	// Production sells Pro alone, so signups start on Free rather than the trial.
	rolloutExec(t, pool, `SELECT retire_billing_plan_version((SELECT id FROM billing_plan_version WHERE family='developer' AND pricing_version='v2' AND state='published'),NULL)`)
	cohortRelease(t, pool, system)

	first := freeOnceCreate(t, pool, actor, false)
	if entry, free, eligible := freeOnceState(t, pool, first); entry != "active" || !free || !eligible {
		t.Fatalf("first team: entry=%s free=%t eligible=%t", entry, free, eligible)
	}
	second := freeOnceCreate(t, pool, actor, true)
	if entry, free, eligible := freeOnceState(t, pool, second); entry != "plan_required" || free || eligible {
		t.Fatalf("additional team: entry=%s free=%t eligible=%t", entry, free, eligible)
	}
	var maxSandboxes int
	if err := pool.QueryRow(t.Context(), `SELECT max_sandboxes FROM team WHERE id=$1`, second).Scan(&maxSandboxes); err != nil || maxSandboxes != 0 {
		t.Fatalf("additional team admits sandboxes: %d %v", maxSandboxes, err)
	}

	// A retry cannot change which kind of team an operation creates.
	op := uuid.New()
	rolloutExec(t, pool, `SELECT prepare_team_promotion_creation($1,$2,'retried','use',false,true)`, op, actor)
	for _, call := range []string{
		`SELECT prepare_team_promotion_creation($1,$2,'retried','use',false,false)`,
		`SELECT prepare_team_promotion_creation($1,$2,'retried','use',false)`,
	} {
		_, err := pool.Exec(t.Context(), call, op, actor)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
			t.Fatalf("flag change accepted by %q: %v", call, err)
		}
	}

	// The same rule holds once every team is on the v2 switch.
	rolloutExec(t, pool, `UPDATE billing_pricing_switch SET pricing_version='v2'`)
	other := uuid.New()
	rolloutExec(t, pool, `INSERT INTO profile(id,email) VALUES($1,$2)`, other, other.String()+"@example.invalid")
	if entry, free, _ := freeOnceState(t, pool, freeOnceCreate(t, pool, other, false)); entry != "active" || !free {
		t.Fatalf("v2 first team: entry=%s free=%t", entry, free)
	}
	if entry, free, eligible := freeOnceState(t, pool, freeOnceCreate(t, pool, other, true)); entry != "plan_required" || free || eligible {
		t.Fatalf("v2 additional team: entry=%s free=%t eligible=%t", entry, free, eligible)
	}
}
