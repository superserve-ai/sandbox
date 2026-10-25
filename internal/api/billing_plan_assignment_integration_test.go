//go:build integration

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/db"
)

func newPlanAssignmentFixture(t *testing.T) (*Handlers, uuid.UUID) {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(os.Getenv("DATABASE_URL"))
	if err != nil || !strings.HasSuffix(cfg.ConnConfig.Database, "_test") {
		t.Fatal("DATABASE_URL must name a migrated disposable test database")
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	h := &Handlers{Pool: pool, DB: db.New(pool)}
	team, err := h.DB.CreateTeam(t.Context(), "plan-assignment-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	return h, team.ID
}

func testPlanTerms(key, kind string, maxConcurrent int32, vcpu *int32) planTerms {
	return planTerms{OfferKey: key, DisplayName: key, Kind: kind, Limits: planLimits{MaxConcurrent: &maxConcurrent, MaxVCPU: vcpu}}
}

func assignInTx(t *testing.T, h *Handlers, a planAssignment) (teamPlan, error) {
	t.Helper()
	tx, err := h.Pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.WithoutCancel(t.Context()))
	p, err := assignTeamPlan(t.Context(), tx, a)
	if err != nil {
		return p, err
	}
	return p, tx.Commit(t.Context())
}

func limitsOf(t *testing.T, h *Handlers, team uuid.UUID) (int32, *int32) {
	t.Helper()
	var max int32
	var vcpu *int32
	if err := h.Pool.QueryRow(t.Context(), `SELECT max_sandboxes,max_template_vcpu FROM team WHERE id=$1`, team).Scan(&max, &vcpu); err != nil {
		t.Fatal(err)
	}
	return max, vcpu
}

func TestPlanAssignmentMovesTeamAndAppliesLimits(t *testing.T) {
	h, team := newPlanAssignmentFixture(t)
	if _, ok, err := currentTeamPlan(t.Context(), h.Pool, team); err != nil || ok {
		t.Fatalf("new team already has a plan: %v %v", ok, err)
	}
	actor := uuid.New()
	free, err := assignInTx(t, h, planAssignment{Team: team, Terms: testPlanTerms("free", planKindFree, 1, nil), Source: planSourceSignup, Reason: "signed up"})
	if err != nil {
		t.Fatal(err)
	}
	if max, vcpu := limitsOf(t, h, team); max != 1 || vcpu != nil {
		t.Fatalf("free limits not applied: %d %v", max, vcpu)
	}
	eight := int32(8)
	pro, err := assignInTx(t, h, planAssignment{Team: team, Terms: testPlanTerms("pro_monthly", planKindSubscription, 1000, &eight), Source: planSourceCheckout, Actor: &actor, Reason: "paid"})
	if err != nil {
		t.Fatal(err)
	}
	if max, vcpu := limitsOf(t, h, team); max != 1000 || vcpu == nil || *vcpu != 8 {
		t.Fatalf("pro limits not applied: %d %v", max, vcpu)
	}
	current, ok, err := currentTeamPlan(t.Context(), h.Pool, team)
	if err != nil || !ok || current.ID != pro.ID || current.Kind != planKindSubscription || *current.AssignedBy != actor {
		t.Fatalf("current plan is not the latest assignment: %+v %v", current, err)
	}
	history, err := teamPlanHistory(t.Context(), h.Pool, team, 10)
	if err != nil || len(history) != 2 || history[1].ID != free.ID || history[1].EffectiveTo == nil || !history[1].EffectiveTo.Equal(pro.EffectiveFrom) {
		t.Fatalf("previous plan was not closed where the next began: %+v %v", history, err)
	}
}

func TestPlanAssignmentKeepsCustomizedLimits(t *testing.T) {
	h, team := newPlanAssignmentFixture(t)
	setPricingVersion(t, h, "v2")
	if _, err := h.Pool.Exec(t.Context(), `UPDATE team SET max_sandboxes=77 WHERE id=$1`, team); err != nil {
		t.Fatal(err)
	}
	if _, err := assignInTx(t, h, planAssignment{Team: team, Terms: testPlanTerms("free", planKindFree, 1, nil), Source: planSourceMigration, Reason: "migration"}); err != nil {
		t.Fatal(err)
	}
	if max, _ := limitsOf(t, h, team); max != 77 {
		t.Fatalf("hand-set limits were overwritten: %d", max)
	}
}

func TestPlanAssignmentRefusesRetiredAndReusedKeys(t *testing.T) {
	h, team := newPlanAssignmentFixture(t)
	setPricingVersion(t, h, "v2")
	retired := testPlanTerms("custom_example", planKindCustom, 50, nil)
	retired.Retired = true
	if _, err := assignInTx(t, h, planAssignment{Team: team, Terms: retired, Source: planSourceStaff, Reason: "r"}); !errors.Is(err, errPlanRetired) {
		t.Fatalf("retired plan assigned: %v", err)
	}
	a := planAssignment{Team: team, Terms: testPlanTerms("custom_example", planKindCustom, 50, nil), Source: planSourceStaff, Reason: "r", Key: "assign-1"}
	first, err := assignInTx(t, h, a)
	if err != nil {
		t.Fatal(err)
	}
	a.Terms.Retired = true
	again, err := assignInTx(t, h, a)
	if err != nil || again.ID != first.ID {
		t.Fatalf("repeated request assigned again: %+v %v", again, err)
	}
	other := a
	other.Terms = testPlanTerms("free", planKindFree, 1, nil)
	if _, err = assignInTx(t, h, other); !errors.Is(err, errPlanAssignmentReused) {
		t.Fatalf("idempotency key reused for another plan: %v", err)
	}
}

func TestPlanAssignmentHistoryIsImmutable(t *testing.T) {
	h, team := newPlanAssignmentFixture(t)
	setPricingVersion(t, h, "v2")
	p, err := assignInTx(t, h, planAssignment{Team: team, Terms: testPlanTerms("free", planKindFree, 1, nil), Source: planSourceSignup, Reason: "signed up"})
	if err != nil {
		t.Fatal(err)
	}
	other, err := h.DB.CreateTeam(t.Context(), "plan-assignment-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.Pool.Exec(t.Context(), `INSERT INTO team_plan_assignment(team_id,plan_key,kind,terms,limits,effective_from,source,reason) VALUES($1,'free','free','{}','{"max_concurrent":1}',clock_timestamp()+interval '1 day','staff','r')`, other.ID); err == nil {
		t.Error("future assignment was allowed")
	}
	for name, stmt := range map[string]string{
		"edit terms":     `UPDATE team_plan_assignment SET plan_key='pro_monthly' WHERE id=$1`,
		"delete":         `DELETE FROM team_plan_assignment WHERE id=$1`,
		"second open":    `INSERT INTO team_plan_assignment(team_id,plan_key,kind,terms,limits,effective_from,source,reason) SELECT team_id,'pro_monthly','subscription',terms,limits,clock_timestamp(),'staff','r' FROM team_plan_assignment WHERE id=$1`,
		"backdated":      `INSERT INTO team_plan_assignment(team_id,plan_key,kind,terms,limits,effective_from,source,reason) SELECT team_id,'pro_monthly','subscription',terms,limits,effective_from-interval '1 day','staff','r' FROM team_plan_assignment WHERE id=$1`,
		"missing limits": `INSERT INTO team_plan_assignment(team_id,plan_key,kind,terms,limits,effective_from,source,reason) SELECT team_id,'free','free',terms,'{}',clock_timestamp(),'staff','r' FROM team_plan_assignment WHERE id=$1`,
	} {
		if _, err := h.Pool.Exec(t.Context(), stmt, p.ID); err == nil {
			t.Errorf("%s was allowed", name)
		}
	}
	if _, err := h.Pool.Exec(t.Context(), `UPDATE team_plan_assignment SET effective_to=clock_timestamp() WHERE id=$1`, p.ID); err != nil {
		t.Fatalf("closing an assignment was refused: %v", err)
	}
	if _, err := h.Pool.Exec(t.Context(), `UPDATE team_plan_assignment SET effective_to=clock_timestamp() WHERE id=$1`, p.ID); err == nil {
		t.Fatal("a closed assignment was closed again")
	}
}

func TestPlanAssignmentRequiresConcurrencyWithCustomizedLimits(t *testing.T) {
	h, team := newPlanAssignmentFixture(t)
	if _, err := h.Pool.Exec(t.Context(), `UPDATE team SET max_sandboxes=77 WHERE id=$1`, team); err != nil {
		t.Fatal(err)
	}
	setPricingVersion(t, h, "v2")
	if _, err := h.Pool.Exec(t.Context(), `INSERT INTO team_plan_assignment(team_id,plan_key,kind,terms,limits,effective_from,source,reason) VALUES($1,'free','free','{}','{}',clock_timestamp(),'staff','missing limits')`, team); err == nil {
		t.Fatal("assignment without concurrency persisted on customized team")
	}
}

func TestPlanAssignmentStaffViewRequiresStaff(t *testing.T) {
	h, team := newPlanAssignmentFixture(t)
	for _, actor := range []struct {
		header string
		want   int
	}{{"", http.StatusUnauthorized}, {uuid.NewString(), http.StatusForbidden}} {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		if actor.header != "" {
			c.Request.Header.Set(internalActorHeader, actor.header)
		}
		c.Params = gin.Params{{Key: "team_id", Value: team.String()}}
		h.GetTeamPlanAssignments(c)
		if w.Code != actor.want {
			t.Fatalf("plan assignments with actor %q: got %d want %d", actor.header, w.Code, actor.want)
		}
	}
}

func TestPlanAssignmentInitialBackfill(t *testing.T) {
	h, assigned := newPlanAssignmentFixture(t)
	setPricingVersion(t, h, "v2")
	if _, err := assignInTx(t, h, planAssignment{Team: assigned, Terms: testPlanTerms("free", planKindFree, 1, nil), Source: planSourceSignup, Reason: "signed up"}); err != nil {
		t.Fatal(err)
	}
	setPricingVersion(t, h, "legacy")
	var fresh []uuid.UUID
	for range 3 {
		team, err := h.DB.CreateTeam(t.Context(), "plan-backfill-"+uuid.NewString())
		if err != nil {
			t.Fatal(err)
		}
		fresh = append(fresh, team.ID)
	}
	setPricingVersion(t, h, "v2")
	busy := fresh[2]
	locker, err := h.Pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = locker.Exec(t.Context(), `SELECT 1 FROM team WHERE id=$1 FOR UPDATE`, busy); err != nil {
		t.Fatal(err)
	}
	batch := []planAssignment{
		{Team: assigned, Terms: testPlanTerms("legacy_payg", planKindLegacyPAYG, 20, nil), Source: planSourceMigration, Reason: "pricing v2"},
		{Team: fresh[0], Terms: testPlanTerms("legacy_payg", planKindLegacyPAYG, 20, nil), Source: planSourceMigration, Reason: "pricing v2"},
		{Team: fresh[1], Terms: testPlanTerms("free", planKindFree, 1, nil), Source: planSourceMigration, Reason: "pricing v2"},
		{Team: busy, Terms: testPlanTerms("free", planKindFree, 1, nil), Source: planSourceMigration, Reason: "pricing v2"},
	}
	run := func() []uuid.UUID {
		tx, err := h.Pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.WithoutCancel(t.Context()))
		done, err := assignInitialTeamPlans(t.Context(), tx, batch)
		if err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		return done
	}
	done := run()
	if len(done) != 2 || !slices.Contains(done, fresh[0]) || !slices.Contains(done, fresh[1]) {
		t.Fatalf("first pass assigned %v", done)
	}
	if p, _, _ := currentTeamPlan(t.Context(), h.Pool, assigned); p.Kind != planKindFree {
		t.Fatalf("backfill replaced an existing plan: %+v", p)
	}
	if max, _ := limitsOf(t, h, fresh[1]); max != 1 {
		t.Fatalf("backfilled limits not applied: %d", max)
	}
	if err = locker.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if done = run(); len(done) != 1 || done[0] != busy {
		t.Fatalf("second pass should pick up only the busy team: %v", done)
	}
	if done = run(); len(done) != 0 {
		t.Fatalf("re-run assigned again: %v", done)
	}
}

func TestStaffPlanAssignmentRefusedWhilePricingV2IsOff(t *testing.T) {
	h, team := newPlanAssignmentFixture(t)
	if _, err := h.assignStaffPlan(t.Context(), team, uuid.New(), staffPlanAssignmentBody{Key: "k", VersionID: uuid.New(), Reason: "enterprise approval"}); !errors.Is(err, errPricingV2Off) {
		t.Fatalf("plan assigned with pricing v2 off: %v", err)
	}
	if _, ok, _ := currentTeamPlan(t.Context(), h.Pool, team); ok {
		t.Fatal("refused assignment left a plan behind")
	}
	for _, actor := range []struct {
		header string
		want   int
	}{{"", http.StatusUnauthorized}, {uuid.NewString(), http.StatusForbidden}} {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"idempotency_key":"k","version_id":"`+uuid.NewString()+`","reason":"r"}`))
		if actor.header != "" {
			c.Request.Header.Set(internalActorHeader, actor.header)
		}
		c.Params = gin.Params{{Key: "team_id", Value: team.String()}}
		h.AssignTeamPlan(c)
		if w.Code != actor.want {
			t.Fatalf("staff assign with actor %q: got %d want %d", actor.header, w.Code, actor.want)
		}
	}
}

func setPricingVersion(t *testing.T, h *Handlers, version string) {
	t.Helper()
	if _, err := h.Pool.Exec(t.Context(), `UPDATE billing_pricing_switch SET pricing_version=$1`, version); err != nil {
		t.Fatal(err)
	}
	forgetPricingVersion()
	t.Cleanup(func() {
		if _, err := h.Pool.Exec(context.WithoutCancel(t.Context()), `UPDATE billing_pricing_switch SET pricing_version='legacy'`); err != nil {
			t.Error(err)
		}
		forgetPricingVersion()
	})
}

func TestPlanAssignmentNewTeamStartsOnFreeOnlyUnderV2(t *testing.T) {
	h, legacyTeam := newPlanAssignmentFixture(t)
	if _, ok, err := currentTeamPlan(t.Context(), h.Pool, legacyTeam); err != nil || ok {
		t.Fatalf("team created with pricing v2 off got a plan: %v %v", ok, err)
	}
	setPricingVersion(t, h, "v2")
	team, err := h.DB.CreateTeam(t.Context(), "plan-v2-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	plan, ok, err := currentTeamPlan(t.Context(), h.Pool, team.ID)
	if err != nil || !ok || plan.Kind != planKindFree || plan.Source != planSourceSignup {
		t.Fatalf("new team under v2 is not on Free: %+v %v", plan, err)
	}
	free, err := h.planTerms(t.Context(), "free")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan.Terms, freezePlanTerms(free)) || !reflect.DeepEqual(plan.Limits, free.Limits) {
		t.Fatalf("terms frozen at signup differ from the backend's:\n%+v\n%+v\n%+v\n%+v", plan.Terms, freezePlanTerms(free), plan.Limits, free.Limits)
	}
	if max, _ := limitsOf(t, h, team.ID); max != *free.Limits.MaxConcurrent {
		t.Fatalf("Free limits not applied to the new team: %d", max)
	}
}

func TestPlanAssignmentSignupRequiresPublishedFree(t *testing.T) {
	h, _ := newPlanAssignmentFixture(t)
	setPricingVersion(t, h, "v2")
	tx, err := h.Pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.WithoutCancel(t.Context()))
	if _, err := tx.Exec(t.Context(), `SELECT retire_billing_plan_version(id,NULL) FROM billing_plan_version WHERE family='free' AND pricing_version='v2' AND state='published'`); err != nil {
		t.Fatal(err)
	}
	name := "unpublished-free-" + uuid.NewString()
	if _, err := db.New(tx).CreateTeam(t.Context(), name); err == nil || !strings.Contains(err.Error(), "published v2 Free plan is required") {
		t.Fatalf("team creation did not fail closed without Free: %v", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	var exists bool
	if err := h.Pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM team WHERE name=$1)`, name).Scan(&exists); err != nil || exists {
		t.Fatalf("planless team persisted: %v %v", exists, err)
	}
}

func TestPlanAssignmentSignupLocksAcceptanceRows(t *testing.T) {
	h, _ := newPlanAssignmentFixture(t)
	setPricingVersion(t, h, "v2")
	for name, mutation := range map[string]string{
		"switch rollback": `UPDATE billing_pricing_switch SET pricing_version='legacy'`,
		"Free retirement": `SELECT retire_billing_plan_version(id,NULL) FROM billing_plan_version WHERE family='free' AND pricing_version='v2' AND state='published'`,
	} {
		t.Run(name, func(t *testing.T) {
			signup, err := h.Pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer signup.Rollback(context.WithoutCancel(t.Context()))
			team, err := db.New(signup).CreateTeam(t.Context(), "serialized-signup-"+uuid.NewString())
			if err != nil {
				t.Fatal(err)
			}
			if plan, assigned, err := currentTeamPlan(t.Context(), signup, team.ID); err != nil || !assigned || plan.Kind != planKindFree {
				t.Fatalf("signup missing Free: %+v %v %v", plan, assigned, err)
			}
			contender, err := h.Pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer contender.Rollback(context.WithoutCancel(t.Context()))
			if _, err := contender.Exec(t.Context(), `SET LOCAL lock_timeout='100ms'`); err != nil {
				t.Fatal(err)
			}
			if _, err := contender.Exec(t.Context(), mutation); err == nil || !strings.Contains(err.Error(), "lock timeout") {
				t.Fatalf("%s overtook uncommitted signup: %v", name, err)
			}
			if err := contender.Rollback(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := signup.Rollback(t.Context()); err != nil {
				t.Fatal(err)
			}
			released, err := h.Pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer released.Rollback(context.WithoutCancel(t.Context()))
			if _, err := released.Exec(t.Context(), mutation); err != nil {
				t.Fatalf("%s failed after signup released locks: %v", name, err)
			}
		})
	}
}

func TestPlanAssignmentOwnsLimitsAfterSwitchOff(t *testing.T) {
	h, team := newPlanAssignmentFixture(t)
	terms := testPlanTerms("starter", planKindPrepaid, 5, nil)
	setPricingVersion(t, h, "v2")
	if _, err := assignInTx(t, h, planAssignment{Team: team, Terms: terms, Source: planSourceCreditPurchase, Reason: "credit"}); err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"v2", "legacy"} {
		setPricingVersion(t, h, version)
		if _, err := h.Pool.Exec(t.Context(), `SELECT apply_plan_limits($1,'free')`, team); err != nil {
			t.Fatal(err)
		}
		if max, _ := limitsOf(t, h, team); max != 5 {
			t.Fatalf("%s overwrote assigned limits: %d", version, max)
		}
	}
	if _, err := assignInTx(t, h, planAssignment{Team: team, Terms: testPlanTerms("free", planKindFree, 1, nil), Source: planSourcePlanChange, Reason: "exit"}); err != nil {
		t.Fatal(err)
	}
	if max, _ := limitsOf(t, h, team); max != 1 {
		t.Fatalf("exit after switch off failed: %d", max)
	}
}

func TestPlanAssignmentConcurrentSameKeyReturnsOneAssignment(t *testing.T) {
	h, team := newPlanAssignmentFixture(t)
	setPricingVersion(t, h, "v2")
	a := planAssignment{Team: team, Terms: testPlanTerms("custom_example", planKindCustom, 50, nil), Source: planSourceStaff, Reason: "r", Key: "same"}
	first, err := h.Pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Rollback(context.WithoutCancel(t.Context()))
	p1, err := assignTeamPlan(t.Context(), first, a)
	if err != nil {
		t.Fatal(err)
	}
	second := make(chan teamPlan, 1)
	failed := make(chan error, 1)
	go func() {
		p, err := assignInTx(t, h, a)
		if err != nil {
			failed <- err
			return
		}
		second <- p
	}()
	time.Sleep(200 * time.Millisecond)
	if err = first.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case p2 := <-second:
		if p2.ID != p1.ID {
			t.Fatalf("concurrent retry made a second assignment: %s %s", p1.ID, p2.ID)
		}
	case err = <-failed:
		t.Fatalf("concurrent retry failed instead of returning the assignment: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent retry did not finish")
	}
}

func TestStaffPlanAssignmentWaitsForAdoptionAndReplaysCommitment(t *testing.T) {
	h, team := newPlanAssignmentFixture(t)
	config := h.Pool.Config()
	config.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	h.Pool, h.DB = pool, db.New(pool)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	var version uuid.UUID
	if err := h.Pool.QueryRow(t.Context(), `INSERT INTO billing_plan_version(pricing_version,family,version,kind,display_name,max_sandboxes,allowance_period,allowance_on_exhausted,allowance_compute_seconds,allowance_compute_vcpu,allowance_compute_memory_gib)
        VALUES('v2','custom_'||substr(md5(random()::text),1,8),1,'custom','Example deal',250,'day_window','pause',7200,1,1) RETURNING id`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Pool.Exec(t.Context(), `SELECT publish_billing_plan_version($1,$2)`, version, uuid.New()); err != nil {
		t.Fatal(err)
	}
	setPricingVersion(t, h, "v2")
	actor := uuid.New()
	body := staffPlanAssignmentBody{Key: "enterprise-approval:1", VersionID: version, Reason: "enterprise approval"}
	if _, err := h.assignStaffPlan(ctx, team, actor, body); !errors.Is(err, errPricingV2Off) {
		t.Fatalf("staff entry before adoption: %v", err)
	}
	catalogVersion, err := scanPlanVersion(h.Pool.QueryRow(ctx, `SELECT `+planVersionColumns+` FROM billing_plan_version WHERE id=$1`, version))
	if err != nil {
		t.Fatal(err)
	}
	terms, err := h.termsOfVersion(ctx, catalogVersion, 0)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := assignInTx(t, h, planAssignment{Team: team, Terms: terms, Source: planSourceStaff, Actor: &actor, Reason: body.Reason, Key: body.Key})
	if err != nil || plan.Kind != planKindCustom || plan.Source != planSourceStaff || *plan.AssignedBy != actor || *plan.VersionID != version {
		t.Fatalf("staff assignment: %+v %v", plan, err)
	}
	if again, err := h.assignStaffPlan(ctx, team, actor, body); err != nil || again.ID != plan.ID {
		t.Fatalf("replayed staff assignment: %+v %v", again, err)
	}
	if max, _ := limitsOf(t, h, team); max != 250 {
		t.Fatalf("custom limits not applied: %d", max)
	}
	free, err := h.planTerms(t.Context(), "free")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.assignStaffPlan(ctx, team, actor, staffPlanAssignmentBody{Key: "k2", VersionID: free.VersionID, Reason: "r"}); !errors.Is(err, errPricingV2Off) {
		t.Fatalf("staff entry before adoption assigned a non-custom plan: %v", err)
	}
	setPricingVersion(t, h, "legacy")
	if _, err := h.assignStaffPlan(ctx, team, actor, staffPlanAssignmentBody{Key: "new-after-off", VersionID: version, Reason: "new custom deal"}); !errors.Is(err, errPricingV2Off) {
		t.Fatalf("new staff assignment for assigned team while off: %v", err)
	}
	if _, err := h.Pool.Exec(t.Context(), `SELECT retire_billing_plan_version($1,$2)`, version, actor); err != nil {
		t.Fatal(err)
	}
	if again, err := h.assignStaffPlan(ctx, team, actor, body); err != nil || again.ID != plan.ID {
		t.Fatalf("recorded staff commitment did not replay after off and retirement: %+v %v", again, err)
	}
	if _, err := h.assignStaffPlan(ctx, team, actor, staffPlanAssignmentBody{Key: body.Key, VersionID: uuid.New(), Reason: body.Reason}); !errors.Is(err, errPlanAssignmentReused) {
		t.Fatalf("replayed key accepted different version while off: %v", err)
	}
	history, err := teamPlanHistory(t.Context(), h.Pool, team, 10)
	if err != nil || len(history) != 1 || history[0].ID != plan.ID {
		t.Fatalf("off requests changed assignment history: %+v %v", history, err)
	}

}

func TestStaffPlanAssignmentRejectsOtherPricingVersion(t *testing.T) {
	h, team := newPlanAssignmentFixture(t)
	ctx := t.Context()
	schema := "staff_entry_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := h.Pool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := h.Pool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	if _, err := h.Pool.Exec(ctx, "CREATE FUNCTION "+schema+`.billing_lock_pricing_public_state()
RETURNS TABLE(entry_open boolean) LANGUAGE sql AS 'SELECT true'`); err != nil {
		t.Fatal(err)
	}
	config := h.Pool.Config()
	config.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	staff := &Handlers{Pool: pool, DB: db.New(pool)}
	actor, outsider := uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{actor, outsider} {
		if _, err := h.Pool.Exec(ctx, `INSERT INTO profile(id,email,provider,provider_id) VALUES($1,$2,'google',$3)`, id, "staff-"+id.String()+"@superserve.ai", id.String()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.Pool.Exec(ctx, `INSERT INTO user_role_assignments(user_id,role_id,scope_type)
SELECT $1,id,'platform' FROM roles WHERE name='platform_admin'`, actor); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPERATOR_API_TOKEN", "staff-model-operator")
	t.Setenv("INTERNAL_API_TOKEN", "staff-model-internal")
	router := SetupRouter(ctx, staff, pool)
	request := func(body staffPlanAssignmentBody, user uuid.UUID, token string) *httptest.ResponseRecorder {
		t.Helper()
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/internal/teams/"+team.String()+"/billing/plan-assignments", strings.NewReader(string(payload)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set(internalActorHeader, user.String())
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	versions := make(map[string]uuid.UUID)
	for _, model := range []string{"legacy", "v2"} {
		var id uuid.UUID
		if err := h.Pool.QueryRow(ctx, `INSERT INTO billing_plan_version(pricing_version,family,version,kind,display_name,max_sandboxes)
VALUES($1,'custom_'||substr(md5(random()::text),1,8),1,'custom','Example deal',250) RETURNING id`, model).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if _, err := h.Pool.Exec(ctx, `SELECT publish_billing_plan_version($1,$2)`, id, uuid.New()); err != nil {
			t.Fatal(err)
		}
		versions[model] = id
	}
	setPricingVersion(t, h, "v2")
	beforeMax, beforeCPU := limitsOf(t, h, team)
	body := staffPlanAssignmentBody{Key: "custom-entry", VersionID: versions["legacy"], Reason: "custom approval"}
	if w := request(body, actor, "staff-model-internal"); w.Code != http.StatusUnauthorized {
		t.Fatalf("infrastructure token accepted: %d %s", w.Code, w.Body)
	}
	if w := request(body, outsider, "staff-model-operator"); w.Code != http.StatusForbidden {
		t.Fatalf("actor without platform role accepted: %d %s", w.Code, w.Body)
	}
	if w := request(body, actor, "staff-model-operator"); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_plan") {
		t.Fatalf("legacy custom entry under v2: %d %s", w.Code, w.Body)
	}
	history, err := teamPlanHistory(ctx, h.Pool, team, 10)
	if err != nil || len(history) != 0 {
		t.Fatalf("rejected entry changed history: %+v %v", history, err)
	}
	if max, cpu := limitsOf(t, h, team); max != beforeMax || !reflect.DeepEqual(cpu, beforeCPU) {
		t.Fatalf("rejected entry changed limits: %d %v", max, cpu)
	}
	body.VersionID = versions["v2"]
	w := request(body, actor, "staff-model-operator")
	var plan teamPlan
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &plan) != nil || plan.VersionID == nil || *plan.VersionID != body.VersionID {
		t.Fatalf("v2 custom entry: %d %s", w.Code, w.Body)
	}
	setPricingVersion(t, h, "legacy")
	w = request(body, actor, "staff-model-operator")
	var replay teamPlan
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &replay) != nil || replay.ID != plan.ID {
		t.Fatalf("persisted entry replay after pricing rollback: %d %s", w.Code, w.Body)
	}
	body.Key = "new-after-off"
	if w := request(body, actor, "staff-model-operator"); w.Code != http.StatusConflict {
		t.Fatalf("new staff entry while off: %d %s", w.Code, w.Body)
	}
	if current, ok, err := currentTeamPlan(ctx, h.Pool, team); err != nil || !ok || current.ID != plan.ID {
		t.Fatalf("pricing rollback changed assignment authority: %+v %v %v", current, ok, err)
	}
}

func TestPlanAssignmentHistorySurvivesTeamDeletion(t *testing.T) {
	h, _ := newPlanAssignmentFixture(t)
	setPricingVersion(t, h, "v2")
	team, err := h.DB.CreateTeam(t.Context(), "plan-delete-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	plan, ok, err := currentTeamPlan(t.Context(), h.Pool, team.ID)
	if err != nil || !ok {
		t.Fatalf("new v2 assignment: %v %v", ok, err)
	}
	if err := h.DB.DeleteTeam(t.Context(), team.ID); err != nil {
		t.Fatal(err)
	}
	retained, ok, err := currentTeamPlan(t.Context(), h.Pool, team.ID)
	if err != nil || !ok || retained.ID != plan.ID {
		t.Fatalf("deleted team's history lost: %+v %v", retained, err)
	}
	if _, err := assignInTx(t, h, planAssignment{Team: team.ID, Terms: testPlanTerms("free", planKindFree, 1, nil), Source: planSourceSignup, Reason: "deleted"}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("assignment to deleted team: %v", err)
	}
}

func TestPlanAssignmentMigrationBypassCannotEnterV2(t *testing.T) {
	h, _ := newPlanAssignmentFixture(t)
	setPricingVersion(t, h, "v2")
	team := uuid.New()
	tx, err := h.Pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(t.Context(), `SELECT set_config('superserve.migrating_team_id',$1,true)`, team.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO team(id,name) VALUES($1,'isolated-import')`, team); err == nil || !strings.Contains(err.Error(), "regional team import is unavailable") {
		t.Fatalf("v2 migration bypass accepted: %v", err)
	}
	tx.Rollback(t.Context())
	var published bool
	if err := h.Pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM team WHERE id=$1)`, team).Scan(&published); err != nil || published {
		t.Fatalf("refused import persisted: %t %v", published, err)
	}
}
