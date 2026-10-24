//go:build integration

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func prepaidPlanFixture(t *testing.T) (*prepaidFixture, teamPlan) {
	t.Helper()
	f := newPrepaidFixture(t)
	terms, err := f.h.planTerms(t.Context(), "free")
	if err != nil {
		t.Fatal(err)
	}
	p, err := assignInTx(t, f.h, planAssignment{Team: f.team, Terms: terms, Source: planSourcePlanChange, Reason: "fixture Free predecessor"})
	if err != nil {
		t.Fatal(err)
	}
	assignStarterAfterPurchase = settlePrepaidPlan
	return f, p
}

func prepaidPlanReader(t *testing.T, f *prepaidFixture, team uuid.UUID) func(teamPlan) {
	t.Helper()
	actor := uuid.New()
	f.exec(`INSERT INTO profile(id,email,provider,provider_id) VALUES($1,$2,'google',$3)`, actor, actor.String()+"@example.com", actor.String())
	f.exec(`INSERT INTO team_memberships(team_id,user_id,status) VALUES($1,$2,'active')`, team, actor)
	f.exec(`INSERT INTO user_role_assignments(user_id,role_id,scope_type,team_id) SELECT $1,id,'team',$2 FROM roles WHERE name='team_owner'`, actor, team)
	f.exec(`INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'tenant_usage_dashboard',true) ON CONFLICT(team_id,key) DO UPDATE SET enabled=true`, team)
	r := gin.New()
	r.GET("/billing/plan", func(c *gin.Context) {
		c.Set("team_id", team.String())
		c.Set("actor_id", actor)
		f.h.GetBillingPlan(c)
	})
	return func(want teamPlan) {
		t.Helper()
		response := httptest.NewRecorder()
		r.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/billing/plan", nil).WithContext(t.Context()))
		if response.Code != http.StatusOK {
			t.Fatal("customer plan read", response.Code, response.Body.String())
		}
		var body struct {
			Plan *customerPlan `json:"plan"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.Plan == nil || body.Plan.Kind != want.Kind || body.Plan.PlanKey != want.PlanKey {
			t.Fatal("customer plan differs from committed authority", body.Plan, want)
		}
		for _, limits := range []struct{ got, want *int32 }{
			{body.Plan.Limits.MaxConcurrent, want.Limits.MaxConcurrent},
			{body.Plan.Limits.MaxVCPU, want.Limits.MaxVCPU},
			{body.Plan.Limits.MaxMemoryMiB, want.Limits.MaxMemoryMiB},
			{body.Plan.Limits.MaxDiskMiB, want.Limits.MaxDiskMiB},
		} {
			if limits.want != nil && !reflect.DeepEqual(limits.got, limits.want) {
				t.Fatal("customer limits differ from frozen assignment", body.Plan.Limits, want.Limits)
			}
		}
	}
}

func freezePaidPrepaidPurchase(t *testing.T, f *prepaidFixture) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if err := f.h.recordCheckoutPurchase(t.Context(), id, f.team, f.customer, uuid.New(), 500, ""); err != nil {
		t.Fatal(err)
	}
	f.exec(`UPDATE billing_prepaid_purchase SET payment_state='succeeded',paid_at=clock_timestamp(),payment_evidence=jsonb_build_object('amount_cents',amount_cents,'customer',customer_id) WHERE id=$1`, id)
	return id
}

func TestPrepaidFrozenPlanSettlesAfterSwitchOff(t *testing.T) {
	f, predecessor := prepaidPlanFixture(t)
	id := freezePaidPrepaidPurchase(t, f)
	var raw []byte
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT plan_snapshot FROM billing_prepaid_purchase WHERE id=$1`, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var snapshot prepaidPurchasePlan
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Predecessor == nil || *snapshot.Predecessor != predecessor.ID || snapshot.Terms.VersionID == uuid.Nil || snapshot.Retain {
		t.Fatalf("purchase lacks frozen authority: %+v", snapshot)
	}
	if _, err := f.h.Pool.Exec(t.Context(), `UPDATE billing_prepaid_purchase SET plan_snapshot='{}' WHERE id=$1`, id); err == nil {
		t.Fatal("accepted terms can be rewritten")
	}
	setPricingVersion(t, f.h, "legacy")
	if err := f.h.settlePrepaidPurchase(t.Context(), f.client, id); err != nil {
		t.Fatal(err)
	}
	p, ok, err := currentTeamPlan(t.Context(), f.h.Pool, f.team)
	if err != nil || !ok || p.Kind != planKindPrepaid || !reflect.DeepEqual(p.Terms, freezePlanTerms(snapshot.Terms)) || !reflect.DeepEqual(p.Limits, snapshot.Terms.Limits) {
		t.Fatalf("settlement lost accepted terms: %+v %v", p, err)
	}
	if r := f.rows(); r[0].Credit != "issued" || len(f.grantPosts) != 1 {
		t.Fatalf("paid purchase not credited: %+v", r)
	}
	newer, err := assignInTx(t, f.h, planAssignment{Team: f.team, Terms: testPlanTerms("free", planKindFree, 1, nil), Source: planSourcePlanChange, Reason: "later downgrade"})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.h.settlePrepaidPurchase(t.Context(), f.client, id); err != nil {
		t.Fatal(err)
	}
	p, _, err = currentTeamPlan(t.Context(), f.h.Pool, f.team)
	if err != nil || p.ID != newer.ID || len(f.grantPosts) != 1 {
		t.Fatal("replay overwrote a later assignment", p, err)
	}
}

func TestPrepaidSettlementDoesNotOverwriteLaterFreeAssignment(t *testing.T) {
	f, _ := prepaidPlanFixture(t)
	id := freezePaidPrepaidPurchase(t, f)
	newer, err := assignInTx(t, f.h, planAssignment{Team: f.team, Terms: testPlanTerms("free", planKindFree, 2, nil), Source: planSourceStaff, Reason: "newer Free authority"})
	if err != nil {
		t.Fatal(err)
	}
	setPricingVersion(t, f.h, "legacy")
	if err = f.h.settlePrepaidPurchase(t.Context(), f.client, id); err != nil {
		t.Fatal(err)
	}
	p, _, err := currentTeamPlan(t.Context(), f.h.Pool, f.team)
	if err != nil || p.ID != newer.ID {
		t.Fatal("late payment overwrote newer Free", p, err)
	}
	prepaidPlanReader(t, f, f.team)(p)
	if r := f.rows(); r[0].Credit != "issued" {
		t.Fatalf("later assignment stranded paid credit: %+v", r)
	}
}

func TestPrepaidTopupRetainsCurrentAssignment(t *testing.T) {
	f := newPrepaidFixture(t)
	assignStarterAfterPurchase = settlePrepaidPlan
	before, _, err := currentTeamPlan(t.Context(), f.h.Pool, f.team)
	if err != nil {
		t.Fatal(err)
	}
	id := freezePaidPrepaidPurchase(t, f)
	if err = f.h.settlePrepaidPurchase(t.Context(), f.client, id); err != nil {
		t.Fatal(err)
	}
	after, _, err := currentTeamPlan(t.Context(), f.h.Pool, f.team)
	if err != nil || before.ID != after.ID {
		t.Fatal("topup replaced current plan", after, err)
	}
}

func TestPrepaidUnassignedEntryClosedButAcceptedAbsenceSettles(t *testing.T) {
	for _, newer := range []bool{false, true} {
		t.Run(map[bool]string{false: "still absent", true: "newer Free"}[newer], func(t *testing.T) {
			f := newPrepaidFixture(t)
			assignStarterAfterPurchase = settlePrepaidPlan
			terms, err := f.h.planTerms(t.Context(), "starter")
			if err != nil {
				t.Fatal(err)
			}
			setPricingVersion(t, f.h, "legacy")
			team, err := f.h.DB.CreateTeam(t.Context(), "unassigned-"+uuid.NewString())
			if err != nil {
				t.Fatal(err)
			}
			tx, err := f.h.Pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if err = f.h.preparePrepaidPurchase(t.Context(), tx, uuid.New(), team.ID, f.customer, uuid.New(), 500); !errors.Is(err, errPricingV2Off) {
				t.Fatal("entry while off", err)
			}
			tx.Rollback(t.Context())
			setPricingVersion(t, f.h, "v2")
			tx, err = f.h.Pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if err = f.h.preparePrepaidPurchase(t.Context(), tx, uuid.New(), team.ID, f.customer, uuid.New(), 500); err == nil {
				t.Fatal("absence was treated as Free")
			}
			tx.Rollback(t.Context())
			snapshot, err := json.Marshal(prepaidPurchasePlan{Terms: terms})
			if err != nil {
				t.Fatal(err)
			}
			id := uuid.New()
			f.exec(`INSERT INTO billing_prepaid_purchase(id,team_id,customer_id,source,amount_cents,actor_id,payment_idempotency_key,credit_idempotency_key,plan_snapshot) VALUES($1,$2,$3,'checkout',500,$4,'','',$5)`, id, team.ID, f.customer, uuid.New(), snapshot)
			f.exec(`UPDATE billing_prepaid_purchase SET payment_state='succeeded',paid_at=clock_timestamp(),payment_evidence=jsonb_build_object('amount_cents',amount_cents,'customer',customer_id) WHERE id=$1`, id)
			var expected uuid.UUID
			if newer {
				p, err := assignInTx(t, f.h, planAssignment{Team: team.ID, Terms: testPlanTerms("free", planKindFree, 1, nil), Source: planSourceStaff, Reason: "newer authority"})
				if err != nil {
					t.Fatal(err)
				}
				expected = p.ID
			}
			setPricingVersion(t, f.h, "legacy")
			if err = settlePrepaidPlan(t.Context(), f.h, team.ID, id); err != nil {
				t.Fatal(err)
			}
			p, ok, err := currentTeamPlan(t.Context(), f.h.Pool, team.ID)
			if err != nil || !ok || (newer && p.ID != expected) || (!newer && p.Kind != planKindPrepaid) {
				t.Fatal("accepted absence mishandled", p, err)
			}
			prepaidPlanReader(t, f, team.ID)(p)
			f.exec(`UPDATE billing_prepaid_purchase SET next_attempt_at='9999-01-01' WHERE id=$1`, id)
		})
	}
}

func TestPrepaidEnforcementSerializesWithDeparture(t *testing.T) {
	f := newPrepaidFixture(t)
	f.enableAutoRecharge(5000, 500)
	f.observe(0, true)
	if err := f.tick(); err != nil {
		t.Fatal(err)
	}
	f.observe(500, true)
	tx, err := f.h.Pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.WithoutCancel(t.Context()))
	if _, err = assignTeamPlan(t.Context(), tx, planAssignment{Team: f.team, Terms: testPlanTerms("free", planKindFree, 1, nil), Source: planSourcePlanChange, Reason: "concurrent departure"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err = f.h.startPrepaidEnforcement(ctx); err != nil {
		t.Fatal("enforcement blocked behind a departure", err)
	}
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = f.h.startPrepaidEnforcement(t.Context()); err != nil {
		t.Fatal(err)
	}
	var prepaid bool
	if err = f.h.Pool.QueryRow(t.Context(), `SELECT prepaid FROM billing_funding_account WHERE team_id=$1`, f.team).Scan(&prepaid); err != nil || prepaid {
		t.Fatal("departure left prepaid enforcement", prepaid, err)
	}
}

func TestPrepaidEnforcementSkipsTeamsWithoutIssuedPurchases(t *testing.T) {
	f := newPrepaidFixture(t)
	f.enableAutoRecharge(5000, 500)
	f.observe(0, true)
	if err := f.tick(); err != nil {
		t.Fatal(err)
	}
	f.observe(500, true)
	terms, err := f.h.planTerms(t.Context(), "starter")
	if err != nil {
		t.Fatal(err)
	}
	var dormant []uuid.UUID
	var budget int32
	if err = f.h.Pool.QueryRow(t.Context(), `SELECT max_observed_teams FROM billing_funding_policy`).Scan(&budget); err != nil {
		t.Fatal(err)
	}
	f.exec(`UPDATE billing_funding_policy SET max_observed_teams=greatest(max_observed_teams,(SELECT count(*)+20 FROM billing_funding_account WHERE observe))`)
	t.Cleanup(func() {
		_, _ = f.h.Pool.Exec(context.Background(), `UPDATE billing_funding_account SET observe=false WHERE team_id=ANY($1)`, dormant)
		_, _ = f.h.Pool.Exec(context.Background(), `UPDATE billing_funding_policy SET max_observed_teams=$1`, budget)
	})
	id := f.team
	for i := 0; i < 20; i++ {
		for j := len(id) - 1; j >= 0; j-- {
			id[j]--
			if id[j] != 255 {
				break
			}
		}
		dormant = append(dormant, id)
		f.exec(`INSERT INTO team(id,name) VALUES($1,$2)`, id, "dormant-"+id.String())
		if _, err = assignInTx(t, f.h, planAssignment{Team: id, Terms: terms, Source: planSourceStaff, Reason: "dormant prepaid fixture"}); err != nil {
			t.Fatal(err)
		}
		f.exec(`INSERT INTO billing_funding_account(team_id,observe,customer_id,subscription_id,credit_usd,credit_valid_until,credit_checked_at,observed_generation) VALUES($1,true,'cus_dormant','sub_dormant',5,clock_timestamp()+interval '1 minute',clock_timestamp(),1) ON CONFLICT(team_id) DO UPDATE SET observe=true,customer_id=EXCLUDED.customer_id,subscription_id=EXCLUDED.subscription_id,credit_usd=EXCLUDED.credit_usd,credit_valid_until=EXCLUDED.credit_valid_until,credit_checked_at=EXCLUDED.credit_checked_at,observed_generation=billing_funding_account.generation`, id)
		f.exec(`UPDATE billing_funding_account SET observed_generation=generation WHERE team_id=$1`, id)
	}
	if err = f.h.startPrepaidEnforcement(t.Context()); err != nil {
		t.Fatal(err)
	}
	var prepaid bool
	if err = f.h.Pool.QueryRow(t.Context(), `SELECT prepaid FROM billing_funding_account WHERE team_id=$1`, f.team).Scan(&prepaid); err != nil || !prepaid {
		t.Fatal("dormant candidates starved funded prepaid team", prepaid, err)
	}
}

func TestPrepaidInitialCheckoutRecoversSessionAfterLostResponse(t *testing.T) {
	f, _ := prepaidPlanFixture(t)
	id := uuid.New()
	if err := f.h.recordCheckoutPurchase(t.Context(), id, f.team, f.customer, uuid.New(), 500, ""); err != nil {
		t.Fatal(err)
	}
	if err := f.tick(); err != nil {
		t.Fatal(err)
	}
	if r := f.rows(); r[0].Payment != "uncertain" || r[0].Credit != "none" {
		t.Fatalf("dispatch raced settlement: %+v", r)
	}
	session := "cs_" + uuid.NewString()
	f.mu.Lock()
	f.sessions[session] = map[string]any{"id": session, "mode": "subscription", "status": "open", "customer": f.customer, "metadata": map[string]string{"prepaid_purchase_id": id.String()}}
	f.mu.Unlock()
	setPricingVersion(t, f.h, "legacy")
	if err := f.tick(); err != nil {
		t.Fatal(err)
	}
	var bound *string
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT checkout_session_id FROM billing_prepaid_purchase WHERE id=$1`, id).Scan(&bound); err != nil || bound == nil || *bound != session {
		t.Fatal("lost response was not recovered", bound, err)
	}
	if err := f.tick(); err != nil {
		t.Fatal(err)
	}
	if r := f.rows(); r[0].Payment != "processing" || r[0].Credit != "none" {
		t.Fatalf("open recovered checkout was credited: %+v", r)
	}
}

func TestPrepaidTeamDeletionKeepsPurchaseAuditAndDropsSettings(t *testing.T) {
	h, team := newPlanAssignmentFixture(t)
	id := uuid.New()
	if _, err := h.Pool.Exec(t.Context(), `INSERT INTO billing_prepaid_auto_recharge(team_id,enabled) VALUES($1,false)`, team); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Pool.Exec(t.Context(), `INSERT INTO billing_prepaid_purchase(id,team_id,customer_id,source,amount_cents,actor_id,payment_idempotency_key,credit_idempotency_key) VALUES($1,$2,'cus_deleted_fixture','checkout',500,$3,'','')`, id, team, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if err := h.DB.DeleteTeam(t.Context(), team); err != nil {
		t.Fatal("prepaid state blocked team deletion", err)
	}
	var audit, settings bool
	if err := h.Pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM billing_prepaid_purchase WHERE id=$1 AND team_id=$2),EXISTS(SELECT 1 FROM billing_prepaid_auto_recharge WHERE team_id=$2)`, id, team).Scan(&audit, &settings); err != nil || !audit || settings {
		t.Fatal("deleted team's prepaid state", audit, settings, err)
	}
	if _, err := h.Pool.Exec(t.Context(), `INSERT INTO billing_prepaid_purchase(team_id,customer_id,source,amount_cents,actor_id,payment_idempotency_key,credit_idempotency_key) VALUES($1,'cus_deleted_fixture','checkout',500,$2,'','')`, team, uuid.New()); err == nil {
		t.Fatal("purchase accepted for deleted team")
	}
	if _, err := h.Pool.Exec(t.Context(), `UPDATE billing_prepaid_purchase SET next_attempt_at='9999-01-01' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
}

func TestPrepaidAutoRechargeStopsOnDeparture(t *testing.T) {
	for _, kind := range []string{planKindFree, planKindSubscription, planKindCustom} {
		for _, queued := range []bool{false, true} {
			t.Run(kind+"/queued="+fmt.Sprint(queued), func(t *testing.T) {
				f := newPrepaidFixture(t)
				f.enableAutoRecharge(2000, 5000)
				f.observe(0, true)
				if queued {
					if err := f.h.recordAutoRecharges(t.Context()); err != nil {
						t.Fatal(err)
					}
					if rows := f.rows(); len(rows) != 1 || rows[0].Payment != "pending" {
						t.Fatal("purchase not queued", rows)
					}
				}
				if _, err := assignInTx(t, f.h, planAssignment{Team: f.team, Terms: testPlanTerms("exit", kind, 1, nil), Source: planSourceStaff, Reason: "leave prepaid"}); err != nil {
					t.Fatal(err)
				}
				if err := f.tick(); err != nil {
					t.Fatal(err)
				}
				if len(f.intentPosts) != 0 {
					t.Fatal("charged after prepaid departure", f.intentPosts)
				}
				for _, row := range f.rows() {
					if row.Payment != "failed" {
						t.Fatal("unsent departure purchase still dispatchable", row)
					}
				}
				var enabled bool
				if err := f.h.Pool.QueryRow(t.Context(), `SELECT enabled FROM billing_prepaid_auto_recharge WHERE team_id=$1`, f.team).Scan(&enabled); err != nil || enabled {
					t.Fatal("departure retained auto-recharge authority", enabled, err)
				}
			})
		}
	}
}

func TestPrepaidAutoRechargeDispatchWaitsForDeparture(t *testing.T) {
	f := newPrepaidFixture(t)
	f.enableAutoRecharge(2000, 5000)
	f.observe(0, true)
	if err := f.h.recordAutoRecharges(t.Context()); err != nil {
		t.Fatal(err)
	}
	var id uuid.UUID
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT id FROM billing_prepaid_purchase WHERE team_id=$1`, f.team).Scan(&id); err != nil {
		t.Fatal(err)
	}
	tx, err := f.h.Pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.WithoutCancel(t.Context()))
	if _, err = assignTeamPlan(t.Context(), tx, planAssignment{Team: f.team, Terms: testPlanTerms("free", planKindFree, 1, nil), Source: planSourceStaff, Reason: "concurrent departure"}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- f.h.chargeAutoRecharge(t.Context(), f.client, id) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting bool
		if err = f.h.Pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query='SELECT id FROM team WHERE id=$1 FOR NO KEY UPDATE')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-done:
			t.Fatal("dispatch did not wait for assignment", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("dispatch never reached team lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if len(f.intentPosts) != 0 || f.rows()[0].Payment != "failed" {
		t.Fatal("concurrent departure dispatched charge", f.rows())
	}
}

func TestPrepaidAutoRechargeRecoversAcceptedChargeAfterDeparture(t *testing.T) {
	f := newPrepaidFixture(t)
	f.enableAutoRecharge(2000, 5000)
	f.observe(0, true)
	f.loseIntent = true
	if err := f.tick(); err == nil {
		t.Fatal("expected lost response")
	}
	if rows := f.rows(); len(rows) != 1 || rows[0].Payment != "uncertain" {
		t.Fatal("charge intent not accepted", rows)
	}
	newer, err := assignInTx(t, f.h, planAssignment{Team: f.team, Terms: testPlanTerms("free", planKindFree, 1, nil), Source: planSourceStaff, Reason: "departure after accepted charge"})
	if err != nil {
		t.Fatal(err)
	}
	setPricingVersion(t, f.h, "legacy")
	if err = f.tick(); err != nil {
		t.Fatal(err)
	}
	if len(f.intents) != 1 || len(f.grantPosts) != 1 || len(f.intentKeys) != 2 || f.intentKeys[0] != f.intentKeys[1] {
		t.Fatal("accepted charge lost or duplicated", f.rows(), f.intentKeys)
	}
	current, _, err := currentTeamPlan(t.Context(), f.h.Pool, f.team)
	if err != nil || current.ID != newer.ID || f.rows()[0].Credit != "issued" {
		t.Fatal("accepted charge overwrote departure or lost credit", current, err)
	}
}

func TestPrepaidAutoRechargeDispatchWaitsForDisable(t *testing.T) {
	f := newPrepaidFixture(t)
	f.enableAutoRecharge(2000, 5000)
	f.observe(0, true)
	if err := f.h.recordAutoRecharges(t.Context()); err != nil {
		t.Fatal(err)
	}
	var id uuid.UUID
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT id FROM billing_prepaid_purchase WHERE team_id=$1`, f.team).Scan(&id); err != nil {
		t.Fatal(err)
	}
	tx, err := f.h.Pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.WithoutCancel(t.Context()))
	if _, err = tx.Exec(t.Context(), `UPDATE billing_prepaid_auto_recharge SET enabled=false WHERE team_id=$1`, f.team); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- f.h.chargeAutoRecharge(t.Context(), f.client, id) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting bool
		if err = f.h.Pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query='SELECT enabled FROM billing_prepaid_auto_recharge WHERE team_id=$1 FOR SHARE')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-done:
			t.Fatal("dispatch did not wait for disable", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("dispatch never reached settings lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if len(f.intentPosts) != 0 || f.rows()[0].Payment != "failed" {
		t.Fatal("concurrent disable dispatched charge", f.rows())
	}
}

func TestPrepaidAutoRechargeEnableWaitsForDeparture(t *testing.T) {
	f := newPrepaidFixture(t)
	f.enableAutoRecharge(2000, 5000)
	actor := uuid.New()
	f.exec(`INSERT INTO profile(id,email,provider,provider_id) VALUES($1,$2,'google',$3)`, actor, actor.String()+"@example.com", actor.String())
	f.exec(`INSERT INTO team_memberships(team_id,user_id,status) VALUES($1,$2,'active')`, f.team, actor)
	f.exec(`INSERT INTO user_role_assignments(user_id,role_id,scope_type,team_id) SELECT $1,id,'team',$2 FROM roles WHERE name='team_owner'`, actor, f.team)
	tx, err := f.h.Pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.WithoutCancel(t.Context()))
	if _, err = assignTeamPlan(t.Context(), tx, planAssignment{Team: f.team, Terms: testPlanTerms("free", planKindFree, 1, nil), Source: planSourceStaff, Reason: "departure during enable"}); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(response)
	c.Request = httptest.NewRequest(http.MethodPut, "/billing/prepaid/auto-recharge", strings.NewReader(`{"enabled":true,"threshold_cents":2000,"amount_cents":5000}`)).WithContext(t.Context())
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("team_id", f.team.String())
	c.Set("actor_id", actor)
	done := make(chan struct{})
	go func() { defer close(done); f.h.PutPrepaidAutoRecharge(c) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting bool
		if err = f.h.Pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND (query='SELECT id FROM team WHERE id=$1 FOR NO KEY UPDATE' OR query LIKE 'INSERT INTO billing_prepaid_auto_recharge%'))`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case <-done:
			t.Fatal("enable did not wait for departure", response.Code, response.Body.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("enable never reached authority lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	<-done
	if response.Code != http.StatusConflict {
		t.Fatal("enable accepted after departure", response.Code, response.Body.String())
	}
	var enabled bool
	if err = f.h.Pool.QueryRow(t.Context(), `SELECT enabled FROM billing_prepaid_auto_recharge WHERE team_id=$1`, f.team).Scan(&enabled); err != nil || enabled {
		t.Fatal("enable revived departed settings", enabled, err)
	}
}
