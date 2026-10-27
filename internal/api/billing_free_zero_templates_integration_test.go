//go:build integration

package api

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Exercise the real Go snapshot serializer, including the compute allowance's
// resolved display value being removed before terms are frozen.
func TestPlanAssignmentFreeZeroTemplatesGoSnapshot(t *testing.T) {
	for _, fixed := range []bool{false, true} {
		name := "compute basis"
		if fixed {
			name = "fixed cents"
		}
		t.Run(name, func(t *testing.T) { freeZeroGoSnapshot(t, fixed) })
	}
}

func freeZeroGoSnapshot(t *testing.T, fixed bool) {
	h, _ := newPlanAssignmentFixture(t)
	tx, err := h.Pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	exec := func(q string, args ...any) {
		t.Helper()
		if _, e := tx.Exec(t.Context(), q, args...); e != nil {
			t.Fatal(e)
		}
	}
	helpers, err := os.ReadFile("../../scripts/billing/free-zero-templates.sql")
	if err != nil {
		t.Fatal(err)
	}
	exec(string(helpers))
	exec(`UPDATE billing_pricing_switch SET pricing_version='v2'`)
	if fixed {
		var old uuid.UUID
		if err = tx.QueryRow(t.Context(), `SELECT id FROM billing_plan_version WHERE family='free' AND pricing_version='v2' AND state='published'`).Scan(&old); err != nil {
			t.Fatal(err)
		}
		// Publish a distinct fixed-cent Free version via the normal lifecycle.
		exec(`INSERT INTO billing_plan_version(family,version,pricing_version,kind,public,display_name,price_label,tagline,features,sort_order,display_only,self_serve,monthly_fee_cents,annual_fee_cents,credit_schedule,matching_bps,cap_cents,allowance_period,allowance_on_exhausted,allowance_cents,allowance_compute_seconds,allowance_compute_vcpu,allowance_compute_memory_gib,max_sandboxes,max_template_vcpu,max_template_memory_mib,max_template_disk_mib,max_templates) SELECT family,(SELECT max(version)+1 FROM billing_plan_version WHERE family='free'),pricing_version,kind,public,display_name,price_label,tagline,features,sort_order,display_only,self_serve,monthly_fee_cents,annual_fee_cents,credit_schedule,matching_bps,cap_cents,allowance_period,allowance_on_exhausted,5,NULL,NULL,NULL,max_sandboxes,max_template_vcpu,max_template_memory_mib,max_template_disk_mib,max_templates FROM billing_plan_version WHERE id=$1`, old)
		exec(`SELECT publish_billing_plan_version(id,NULL) FROM billing_plan_version WHERE family='free' AND state='draft' ORDER BY version DESC LIMIT 1`)
	}
	terms, err := h.planTermsForPricingVersion(t.Context(), "free", "v2", tx)
	if err != nil {
		t.Fatal(err)
	}
	frozen, err := json.Marshal(freezePlanTerms(terms))
	if err != nil {
		t.Fatal(err)
	}
	limits, err := json.Marshal(terms.Limits)
	if err != nil {
		t.Fatal(err)
	}
	team, actor := uuid.New(), uuid.New()
	exec(`INSERT INTO profile(id,email,provider,provider_id) VALUES($1::uuid,$1::uuid::text||'@example.com','google',$1::uuid::text)`, actor)
	exec(`INSERT INTO team(id,name) VALUES($1,'Go frozen Free')`, team)
	var originalFloor time.Time
	if err = tx.QueryRow(t.Context(), `SELECT free_since FROM billing_free_plan($1)`, team).Scan(&originalFloor); err != nil {
		t.Fatal(err)
	}
	var sqlTeam, sqlAssignment uuid.UUID
	if fixed {
		sqlTeam = uuid.New()
		exec(`INSERT INTO team(id,name) VALUES($1,'SQL fixed-cent Free')`, sqlTeam)
		if err = tx.QueryRow(t.Context(), `SELECT id FROM team_plan_assignment WHERE team_id=$1 AND effective_to IS NULL`, sqlTeam).Scan(&sqlAssignment); err != nil {
			t.Fatal(err)
		}
	}
	var current uuid.UUID
	if err = tx.QueryRow(t.Context(), `WITH closed AS (UPDATE team_plan_assignment SET effective_to=clock_timestamp() WHERE team_id=$1 AND effective_to IS NULL RETURNING effective_to) INSERT INTO team_plan_assignment(team_id,plan_key,kind,plan_version_id,terms,limits,effective_from,source,reason) SELECT $1,'free','free',$2,$3,$4,effective_to,'migration','Go serializer fixture' FROM closed RETURNING id`, team, terms.VersionID, frozen, limits).Scan(&current); err != nil {
		t.Fatal(err)
	}
	replacement := uuid.New()
	exec(`SELECT pg_temp.publish_free_zero_templates($1,$2,$3,'Go snapshot acceptance',true)`, terms.VersionID, replacement, actor)
	if fixed {
		// The derived display value is accepted only when it equals the exact
		// configured cents. Preserve the true snapshot and immutable history.
		exec("SAVEPOINT tampered_display")
		var tampered uuid.UUID
		if err = tx.QueryRow(t.Context(), `WITH closed AS (UPDATE team_plan_assignment SET effective_to=clock_timestamp() WHERE id=$1 RETURNING *) INSERT INTO team_plan_assignment(team_id,plan_key,kind,plan_version_id,terms,limits,effective_from,source,reason) SELECT team_id,plan_key,kind,plan_version_id,jsonb_set(terms,'{allowance,amount_usd}','"0.06"'),limits,effective_to,'migration','tampered display fixture' FROM closed RETURNING id`, current).Scan(&tampered); err != nil {
			t.Fatal(err)
		}
		exec("SAVEPOINT rejected_display")
		if _, err = tx.Exec(t.Context(), `SELECT pg_temp.transition_free_zero_templates($1,$2,$3,$4,'Go snapshot acceptance')`, team, tampered, replacement, actor); err == nil {
			t.Fatal("tampered fixed-cent derived amount accepted")
		}
		exec("ROLLBACK TO SAVEPOINT tampered_display")
	}
	exec(`SELECT pg_temp.transition_free_zero_templates($1,$2,$3,$4,'Go snapshot acceptance')`, team, current, replacement, actor)
	var finalFloor time.Time
	if err = tx.QueryRow(t.Context(), `SELECT free_since FROM billing_free_plan($1)`, team).Scan(&finalFloor); err != nil || !finalFloor.Equal(originalFloor) {
		t.Fatalf("serializer transition reset allowance floor: original=%s final=%s err=%v", originalFloor, finalFloor, err)
	}
	if fixed {
		exec(`SELECT pg_temp.transition_free_zero_templates($1,$2,$3,$4,'Go snapshot acceptance')`, sqlTeam, sqlAssignment, replacement, actor)
	}
}

// freezePlanTerms represents an absent allowance as JSON null. Normal staff
// assignment and delayed prepaid settlement must remain compatible with it.
func TestPlanAssignmentFreeZeroTemplatesAbsentAllowance(t *testing.T) {
	h, team := newPlanAssignmentFixture(t)
	terms := testPlanTerms("free", planKindFree, 2, nil)
	first, err := assignInTx(t, h, planAssignment{Team: team, Terms: terms, Source: planSourceStaff, Reason: "ordinary Free with nil allowance"})
	if err != nil {
		t.Fatal(err)
	}
	next, err := assignInTx(t, h, planAssignment{Team: team, Terms: terms, Source: planSourceStaff, Reason: "unchanged nil allowance"})
	if err != nil {
		t.Fatal(err)
	}
	var since time.Time
	var allowance string
	if err = h.Pool.QueryRow(t.Context(), `SELECT free_since,allowance::text FROM billing_free_plan($1)`, team).Scan(&since, &allowance); err != nil || !since.Equal(first.EffectiveFrom) || allowance != "{}" {
		t.Fatalf("nil allowance continuity since=%s allowance=%s err=%v", since, allowance, err)
	}
	if next.ID == first.ID {
		t.Fatal("assignment transition did not occur")
	}
}
