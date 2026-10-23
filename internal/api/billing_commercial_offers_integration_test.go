//go:build integration

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

func commercialOfferFixture(t *testing.T) (*Handlers, uuid.UUID, uuid.UUID, CommercialOfferRequest) {
	t.Helper()
	h, team := fundingTransitionFixture(t)
	ensureYCTestAuthority(t, h.Pool)
	h.PromotionAuthPool = h.Pool
	h.Config = &config.Config{TeamCreationRegion: "use"}
	if _, err := h.Pool.Exec(t.Context(), `INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_commercial_offer_assignments_enabled',true)`, team); err != nil {
		t.Fatal(err)
	}
	actor := uuid.New()
	r := CommercialOfferRequest{Key: uuid.NewString(), OfferKey: "yc_2026", Version: 1, Company: "https://www.ycombinator.com/companies/fixture-" + uuid.NewString(), Region: "use", Reason: "synthetic approval", Reference: "fixture"}
	if _, err := h.Pool.Exec(t.Context(), `UPDATE team SET home_region='use' WHERE id=$1`, team); err != nil {
		t.Fatal(err)
	}
	if err := h.Pool.QueryRow(t.Context(), `SELECT approval_id FROM reserve_yc_activation_authority($1,$2,'use',$3,'operator','fixture',NULL)`, r.Company, team, actor).Scan(&r.ApprovalID); err != nil {
		t.Fatal(err)
	}
	return h, team, actor, r
}

func TestYCCommercialOfferAssignmentAuthorityAndRetry(t *testing.T) {
	h, team, actor, r := commercialOfferFixture(t)
	ctx := t.Context()
	// The authority RPC returns company OR team matches. Neither alone authorizes another binding.
	other, err := h.DB.CreateTeam(ctx, "other-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.assignCommercialOffer(ctx, other.ID, actor, r, true); !errors.Is(err, errCommercialOfferConflict) {
		t.Fatalf("cross-team approval accepted: %v", err)
	}
	bad := r
	bad.Company = "https://www.ycombinator.com/companies/different-fixture"
	if _, err = h.assignCommercialOffer(ctx, team, actor, bad, true); !errors.Is(err, errCommercialOfferConflict) {
		t.Fatalf("cross-company approval accepted: %v", err)
	}
	if _, err = h.assignCommercialOffer(ctx, team, actor, r, false); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = h.Pool.QueryRow(ctx, `SELECT count(*) FROM billing_commercial_offer_assignment WHERE team_id=$1`, team).Scan(&count); err != nil || count != 0 {
		t.Fatalf("preflight assigned: %d %v", count, err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := h.assignCommercialOffer(ctx, team, actor, r, true); results <- err }()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	var before json.RawMessage
	if err = h.Pool.QueryRow(ctx, `SELECT resource_rates FROM billing_commercial_offer_assignment WHERE team_id=$1`, team).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err = h.Pool.QueryRow(ctx, `SELECT count(*) FROM billing_commercial_offer_assignment WHERE team_id=$1`, team).Scan(&count); err != nil || count != 1 {
		t.Fatalf("duplicate assignment: %d %v", count, err)
	}
	if err = h.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM billing_commercial_offer_period WHERE team_id=$1)+(SELECT count(*) FROM billing_commercial_contract WHERE team_id=$1)+(SELECT count(*) FROM billing_usage_entitlement WHERE team_id=$1)`, team).Scan(&count); err != nil || count != 0 {
		t.Fatalf("acceptance activated benefits: %d %v", count, err)
	}
	bad = r
	bad.Version = 2
	if _, err = h.assignCommercialOffer(ctx, team, actor, bad, true); err == nil {
		t.Fatal("changed version accepted")
	}
	bad = r
	bad.Key = uuid.NewString()
	if _, err = h.assignCommercialOffer(ctx, team, actor, bad, true); !errors.Is(err, errCommercialOfferConflict) {
		t.Fatalf("second key accepted: %v", err)
	}
	// A later catalog publication cannot replace accepted rates on retry.
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `UPDATE pricing_rate SET price_usd=price_usd+0.000000000001 WHERE plan_key='payg'`); err != nil {
		t.Fatal(err)
	}
	var frozen json.RawMessage
	if err = tx.QueryRow(ctx, `SELECT resource_rates FROM billing_commercial_offer_assignment WHERE team_id=$1`, team).Scan(&frozen); err != nil || string(frozen) != string(before) {
		t.Fatalf("accepted pricing changed: %v", err)
	}
	for _, test := range []struct {
		query string
		args  []any
	}{
		{`UPDATE billing_commercial_offer_version SET charge_amount_cents=1 WHERE offer_key='yc_2026' AND version=1`, nil},
		{`UPDATE billing_commercial_offer_assignment SET offer_version=2 WHERE team_id=$1`, []any{team}},
		{`DELETE FROM billing_commercial_offer_assignment WHERE team_id=$1`, []any{team}},
	} {
		if _, err = h.Pool.Exec(ctx, test.query, test.args...); err == nil || !strings.Contains(err.Error(), "immutable") {
			t.Fatalf("immutability guard failed: %v", err)
		}
	}

}

func TestYCCommercialOfferFrozenCalendar(t *testing.T) {
	for _, anchor := range []time.Time{time.Date(time.Now().UTC().Year(), 1, 31, 12, 34, 56, 0, time.UTC), time.Date(time.Now().UTC().Year(), 2, 28, 23, 59, 59, 0, time.UTC)} {
		if anchor.After(time.Now().UTC()) {
			anchor = anchor.AddDate(-1, 0, 0)
		}
		t.Run(anchor.Format("2006-01-02"), func(t *testing.T) {
			h, team, actor, r := commercialOfferFixture(t)
			ctx := t.Context()
			if _, err := h.assignCommercialOffer(ctx, team, actor, r, true); err != nil {
				t.Fatal(err)
			}
			var assignment uuid.UUID
			if err := h.Pool.QueryRow(ctx, `SELECT id FROM billing_commercial_offer_assignment WHERE team_id=$1`, team).Scan(&assignment); err != nil {
				t.Fatal(err)
			}
			adminPool := h.Pool
			exec := func(q string, args ...any) {
				t.Helper()
				if _, err := adminPool.Exec(ctx, q, args...); err != nil {
					t.Fatal(err)
				}
			}
			contract := uuid.New()
			customer, subscription := "cus_"+team.String(), "sub_"+team.String()
			end := annualBoundary(anchor, 12)
			exec(`INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,commercial_billing_anchor) VALUES($1,$2,$3,$4) ON CONFLICT(team_id) DO UPDATE SET stripe_customer_id=$2,stripe_subscription_id=$3,commercial_billing_anchor=$4`, team, customer, subscription, anchor)
			var resourceTerms json.RawMessage
			if err := h.Pool.QueryRow(ctx, `SELECT jsonb_build_object('ResourceTerms',jsonb_agg(jsonb_build_object('ResourceKey',r->>'resource','UnitAmountDecimal',((r->>'price_usd')::numeric*360000)::text,'PriceID','price_'||(r->>'resource'),'MeterID','meter_'||(r->>'resource'),'EventName',r->>'resource'))) FROM billing_commercial_offer_assignment a CROSS JOIN LATERAL jsonb_array_elements(a.resource_rates) r WHERE a.id=$1`, assignment).Scan(&resourceTerms); err != nil {
				t.Fatal(err)
			}
			request, _ := json.Marshal(map[string]any{"company_identity": r.Company, "home_region": "use", "merchant_account": "acct_fixture", "live_mode": false})
			exec(`INSERT INTO billing_yc_operation(id,team_id,contract_id,approved_by,evidence_reference,request,resource_terms,customer_id,subscription_id,state,starts_at,ends_at,payment_method_ready,payment_method_checked_at) VALUES($1,$2,$3,$4,'fixture',$5,$6,$7,$8,'active',$9,$10,true,clock_timestamp())`, r.ApprovalID, team, contract, actor.String(), request, resourceTerms, customer, subscription, anchor, end)
			exec(`INSERT INTO billing_commercial_contract(id,team_id,offer_key,starts_at,ends_at,customer_id,subscription_id,base_price_id,charge_kind,charge_amount_cents,charge_interval_months,entitlement_amount_cents,entitlement_cadence,entitlement_anchor) VALUES($1,$2,'yc_2026',$3,$4,$5,$6,'price_annual','subscription',1200000,12,3000000,'scheduled',$3)`, contract, team, anchor, end, customer, subscription)
			exec(`INSERT INTO billing_contract_entitlement_schedule(team_id,contract_id,month_offset,amount_cents) SELECT $1,$2,n,CASE WHEN n<3 THEN 3000000 ELSE 100000 END FROM generate_series(0,11) n`, team, contract)
			exec(`INSERT INTO billing_contract_waiver(id,team_id,contract_id,offer_key,offer_version,customer_id,subscription_id,starts_at,ends_at,collectible_base_cents) VALUES($1,$2,$3,'yc_2026',1,$4,$5,$6,$7,0)`, r.ApprovalID, team, contract, customer, subscription, anchor, end)
			exec(`UPDATE team_feature_flag SET enabled=false WHERE team_id=$1 AND key='billing_commercial_offer_assignments_enabled'`, team)
			if err := h.materializeCommercialOffer(ctx, team, assignment, contract, "acct_fixture", false); !errors.Is(err, errCommercialOfferDisabled) {
				t.Fatalf("materialization service bypassed closed gate: %v", err)
			}
			if _, err := h.Pool.Exec(ctx, `INSERT INTO billing_commercial_offer_activation(assignment_id,team_id,contract_id,anchor,ends_at,merchant_account,live_mode) VALUES($1,$2,$3,$4,$5,'acct_fixture',false)`, assignment, team, contract, anchor, end); err == nil || !strings.Contains(err.Error(), "assignments are disabled") {
				t.Fatalf("direct activation bypassed closed gate: %v", err)
			}
			exec(`UPDATE team_feature_flag SET enabled=true WHERE team_id=$1 AND key='billing_commercial_offer_assignments_enabled'`, team)
			if err := h.materializeCommercialOffer(ctx, team, assignment, contract, "acct_fixture", false); err == nil {
				t.Fatal("pending contract supplied activation authority")
			}
			exec(`UPDATE billing_commercial_contract SET status='active',revision=revision+1 WHERE id=$1`, contract)
			if err := h.materializeCommercialOffer(ctx, team, assignment, contract, "acct_other", false); err == nil {
				t.Fatal("wrong merchant accepted")
			}
			if err := h.materializeCommercialOffer(ctx, team, assignment, contract, "acct_fixture", true); err == nil {
				t.Fatal("wrong provider mode accepted")
			}
			// Exercise first materialization and concurrent retries with the backend's
			// restricted new-table grants, including the database trigger chain.
			restricted := *h
			restricted.Pool = commercialOfferRestrictedPool(t, h.Pool)
			h = &restricted
			results := make(chan error, 4)
			for range 4 {
				go func() {
					results <- h.materializeCommercialOffer(ctx, team, assignment, contract, "acct_fixture", false)
				}()
			}
			for range 4 {
				if err := <-results; err != nil {
					t.Fatal(err)
				}
			}
			rows, err := h.Pool.Query(ctx, `SELECT month_offset,starts_at,ends_at,expires_at,amount_cents FROM billing_commercial_offer_period WHERE assignment_id=$1 ORDER BY month_offset`, assignment)
			if err != nil {
				t.Fatal(err)
			}
			n := 0
			for rows.Next() {
				var offset int
				var start, finish, expiry time.Time
				var amount int64
				if err = rows.Scan(&offset, &start, &finish, &expiry, &amount); err != nil {
					t.Fatal(err)
				}
				expected := int64(100000)
				if offset < 3 {
					expected = 3000000
				}
				if offset != n || !start.Equal(annualBoundary(anchor, n)) || !finish.Equal(annualBoundary(anchor, n+1)) || !expiry.Equal(finish) || amount != expected {
					t.Fatalf("incorrect period %d: %s %s %s %d", offset, start, finish, expiry, amount)
				}
				n++
			}
			rows.Close()
			if rows.Err() != nil || n != 12 {
				t.Fatalf("periods=%d err=%v", n, rows.Err())
			}
			if _, err = h.Pool.Exec(ctx, `UPDATE billing_commercial_offer_period SET amount_cents=1 WHERE assignment_id=$1`, assignment); err == nil {
				t.Fatal("frozen period mutated")
			}
			exec(`UPDATE billing_commercial_contract SET status='ended',revision=revision+1 WHERE id=$1`, contract)
			if err = h.materializeCommercialOffer(ctx, team, assignment, contract, "acct_fixture", false); err != nil {
				t.Fatalf("terminal replay failed: %v", err)
			}
			if err = h.materializeCommercialOffer(ctx, team, assignment, uuid.New(), "acct_fixture", false); !errors.Is(err, errCommercialOfferConflict) {
				t.Fatalf("changed binding accepted: %v", err)
			}
		})
	}
}

func TestYCCommercialOfferHTTPAuthorization(t *testing.T) {
	h, team, _, _ := commercialOfferFixture(t)
	for _, provider := range []string{"google", "email"} {
		actor := uuid.New()
		if _, err := h.Pool.Exec(t.Context(), `INSERT INTO profile(id,email,provider,provider_id) VALUES($1,$2,$3,$4)`, actor, "fixture-"+actor.String()+"@superserve.ai", provider, actor.String()); err != nil {
			t.Fatal(err)
		}
		for _, endpoint := range []struct{ method, path string }{{"POST", ""}, {"POST", "/preflight"}, {"GET", ""}} {
			router := gin.New()
			h.registerCommercialOfferRoutes(router.Group("/internal"))
			req := httptest.NewRequest(endpoint.method, "/internal/teams/"+team.String()+"/billing/commercial-offer-assignment"+endpoint.path, strings.NewReader(`{}`))
			req.Header.Set("X-Actor-User-Id", actor.String())
			response := httptest.NewRecorder()
			router.ServeHTTP(response, req)
			if response.Code != http.StatusForbidden {
				t.Fatalf("%s %s: got %d: %s", provider, endpoint.path, response.Code, response.Body.String())
			}
		}
	}
	for _, role := range []string{"anon", "authenticated"} {
		for _, table := range []string{"billing_commercial_offer_version", "billing_commercial_offer_assignment", "billing_commercial_offer_activation", "billing_commercial_offer_period", "billing_commercial_offer_audit", "billing_commercial_checkout_attempt"} {
			var allowed bool
			if err := h.Pool.QueryRow(t.Context(), `SELECT has_table_privilege($1,$2,'INSERT') OR has_table_privilege($1,$2,'UPDATE') OR has_table_privilege($1,$2,'SELECT')`, role, table).Scan(&allowed); err != nil || allowed {
				t.Fatalf("public role has access to %s: %v %v", table, allowed, err)
			}
		}
	}
}

// Use a unique, narrowly granted synthetic role so the test cannot accidentally
// pass because its fixture connection owns the tables. Cleanup removes its ACLs
// and policies; no application role or default privileges are changed.
func commercialOfferRestrictedPool(t *testing.T, admin *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	ctx := t.Context()
	role := pgx.Identifier{"offer_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE ROLE "+role+" NOLOGIN"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP OWNED BY "+role+"; DROP ROLE "+role); err != nil {
			t.Error(err)
		}
	})
	if _, err := admin.Exec(ctx, "GRANT USAGE ON SCHEMA public TO "+role+"; GRANT EXECUTE ON FUNCTION billing_anniversary_boundary(timestamptz,integer) TO "+role); err != nil {
		t.Fatal(err)
	}
	for _, grant := range []struct{ table, privileges string }{
		{"feature_flag", "SELECT"},
		{"team_feature_flag", "SELECT"},
		{"billing_commercial_offer_version", "SELECT"},
		{"billing_commercial_offer_assignment", "SELECT,INSERT"},
		{"billing_commercial_offer_activation", "SELECT,INSERT"},
		{"billing_commercial_offer_period", "SELECT,INSERT"},
		{"team", "SELECT,UPDATE"},
		{"billing_signup_choice", "SELECT,UPDATE"},
		{"billing_funding_account", "SELECT,INSERT,UPDATE"},
		{"billing_commercial_checkout_attempt", "SELECT,INSERT,UPDATE"},
		{"team_billing_account", "SELECT,INSERT,UPDATE"},
		{"billing_commercial_contract", "SELECT,UPDATE"},
		{"billing_contract_provider_binding", "SELECT"},
		{"billing_yc_operation", "SELECT,UPDATE"},
		{"billing_contract_waiver", "SELECT"},
		{"billing_contract_entitlement_schedule", "SELECT"},
	} {
		table := pgx.Identifier{grant.table}.Sanitize()
		if _, err := admin.Exec(ctx, "GRANT "+grant.privileges+" ON "+table+" TO "+role+"; CREATE POLICY "+role+" ON "+table+" TO "+role+" USING(true) WITH CHECK(true)"); err != nil {
			t.Fatal(err)
		}
	}
	cfg := admin.Config().Copy()
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET ROLE "+role)
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	var canUpdate bool
	if err = pool.QueryRow(ctx, `SELECT has_table_privilege(current_user,'billing_commercial_offer_assignment','UPDATE')`).Scan(&canUpdate); err != nil || canUpdate {
		t.Fatalf("fixture permits assignment updates: %v %v", canUpdate, err)
	}
	return pool
}

func TestYCCommercialOfferAssignmentWaitsForCheckout(t *testing.T) {
	for _, apply := range []bool{false, true} {
		t.Run(map[bool]string{false: "preflight", true: "apply"}[apply], func(t *testing.T) {
			h, team, actor, r := commercialOfferFixture(t)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if _, err := h.Pool.Exec(ctx, `INSERT INTO team_billing_account(team_id) VALUES($1)`, team); err != nil {
				t.Fatal(err)
			}
			checkout, err := h.Pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer checkout.Rollback(context.Background())
			var pid int
			if err = checkout.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
				t.Fatal(err)
			}
			// Model the account write made by checkout while its transaction is open.
			if _, err = checkout.Exec(ctx, `UPDATE team_billing_account SET stripe_customer_id=$2 WHERE team_id=$1`, team, "cus_"+team.String()); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() { _, err := h.assignCommercialOffer(ctx, team, actor, r, apply); result <- err }()
			// Observe the actual lock wait rather than relying on a timing-only assertion.
			for {
				select {
				case err = <-result:
					t.Fatalf("assignment did not wait for checkout: %v", err)
				default:
				}
				var waiting bool
				if err = h.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))`, pid).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err = checkout.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err = <-result; !errors.Is(err, errCommercialOfferConflict) {
				t.Fatalf("committed checkout not rejected: %v", err)
			}
			var count int
			if err = h.Pool.QueryRow(ctx, `SELECT count(*) FROM billing_commercial_offer_assignment WHERE team_id=$1`, team).Scan(&count); err != nil || count != 0 {
				t.Fatalf("checkout race assigned offer: count=%d err=%v", count, err)
			}
		})
	}
}

func TestYCCommercialOfferPromotionRecoveryLockOrder(t *testing.T) {
	for _, path := range []string{"checkout", "assignment", "attempt trigger"} {
		t.Run(path, func(t *testing.T) {
			h, team, actor, request := commercialOfferFixture(t)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			sponsor := uuid.New()
			if _, err := h.Pool.Exec(ctx, `INSERT INTO team_billing_account(team_id) VALUES($1)`, team); err != nil {
				t.Fatal(err)
			}
			if _, err := h.Pool.Exec(ctx, `INSERT INTO billing_sponsored_operation(id,team_id,idempotency_key,request,resource_terms,approved_by,reason,reference,state)
 VALUES($1,$2,'fixture','{}','{}',$3,'fixture','fixture','active')`, sponsor, team, actor); err != nil {
				t.Fatal(err)
			}
			recovery, err := h.Pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer recovery.Rollback(context.Background())
			if err = lockCommercialOfferAccount(ctx, recovery, team); err != nil {
				t.Fatal(err)
			}
			var pid int
			if err = recovery.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() {
				var err error
				switch path {
				case "checkout":
					_, err = h.prepareCommercialCheckout(ctx, team)
				case "assignment":
					_, err = h.assignCommercialOffer(ctx, team, actor, request, true)
				default:
					_, err = h.Pool.Exec(ctx, `INSERT INTO billing_commercial_checkout_attempt(team_id) VALUES($1)`, team)
				}
				result <- err
			}()
			for {
				select {
				case err = <-result:
					t.Fatalf("offer path did not wait for recovery account lock: %v", err)
				default:
				}
				var waiting bool
				if err = h.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))`, pid).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			// Recovery holds the account before this insert takes the team's FK lock.
			if _, err = recovery.Exec(ctx, `INSERT INTO billing_sponsored_promotion_recovery(team_id,sponsorship_id,idempotency_key,request,approved_by,reason,reference,customer_id,subscription_id,user_id,event_id)
 VALUES($1,$2,'fixture','{}',$3,'fixture','fixture','cus_fixture','sub_fixture',$3,'evt_fixture')`, team, sponsor, actor); err != nil {
				t.Fatalf("recovery insert blocked by offer team lock: %v", err)
			}
			if err = recovery.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			err = <-result
			if path == "assignment" {
				if !errors.Is(err, errCommercialOfferConflict) {
					t.Fatalf("assignment must still reject sponsorship: %v", err)
				}
			} else if err != nil {
				t.Fatalf("checkout did not resume after recovery: %v", err)
			}
		})
	}
}

func TestYCCommercialOfferCheckoutAttemptStates(t *testing.T) {
	t.Run("expired preparation cannot adopt an assigned customer", func(t *testing.T) {
		h, team, actor, r := commercialOfferFixture(t)
		ctx := t.Context()
		var attempt uuid.UUID
		if err := h.Pool.QueryRow(ctx, `INSERT INTO billing_commercial_checkout_attempt(team_id,created_at,prepared_until) VALUES($1,clock_timestamp()-interval '2 minutes',clock_timestamp()-interval '1 minute') RETURNING id`, team).Scan(&attempt); err != nil {
			t.Fatal(err)
		}
		if _, err := h.assignCommercialOffer(ctx, team, actor, r, true); err != nil {
			t.Fatal(err)
		}
		customer := "cus_" + team.String()
		// Simulate the assigned-offer provisioner persisting its own customer.
		if _, err := h.Pool.Exec(ctx, `UPDATE team_billing_account SET stripe_customer_id=$2 WHERE team_id=$1`, team, customer); err != nil {
			t.Fatal(err)
		}
		got, err := h.ensureStripeCustomerBeforeCreate(ctx, team, func() error {
			t.Error("existing customer attempted creation")
			return errors.New("unexpected dispatch")
		})
		if err != nil || got != customer {
			t.Fatalf("existing customer not observed: %s %v", got, err)
		}
		if err = h.finishCommercialCheckout(ctx, team, attempt, got); !errors.Is(err, errCommercialOfferConflict) {
			t.Fatalf("stale ordinary checkout adopted assigned customer: %v", err)
		}
		if _, err = h.Pool.Exec(ctx, `UPDATE billing_commercial_checkout_attempt SET state='customer_observed',customer_id=$2 WHERE id=$1`, attempt, customer); err == nil {
			t.Fatal("direct observation bypassed assignment fence")
		}
	})

	t.Run("restricted backend can prepare and dispatch", func(t *testing.T) {
		h, team, _, _ := commercialOfferFixture(t)
		h.Pool = commercialOfferRestrictedPool(t, h.Pool)
		id, err := h.prepareCommercialCheckout(t.Context(), team)
		if err != nil {
			t.Fatal(err)
		}
		if err = h.dispatchCommercialCheckout(t.Context(), team, id); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("release only undispatched token", func(t *testing.T) {
		h, team, actor, r := commercialOfferFixture(t)
		ctx := t.Context()
		first, err := h.prepareCommercialCheckout(ctx, team)
		if err != nil {
			t.Fatal(err)
		}
		if err = h.finishCommercialCheckout(ctx, team, first, ""); err != nil {
			t.Fatal(err)
		}
		if _, err = h.assignCommercialOffer(ctx, team, actor, r, true); err != nil {
			t.Fatalf("no-effect attempt poisoned eligibility: %v", err)
		}
		if err = h.dispatchCommercialCheckout(ctx, team, first); !errors.Is(err, errCommercialOfferConflict) {
			t.Fatalf("released token dispatched: %v", err)
		}
	})
	t.Run("another retry cannot clear uncertainty", func(t *testing.T) {
		h, team, actor, r := commercialOfferFixture(t)
		ctx := t.Context()
		first, err := h.prepareCommercialCheckout(ctx, team)
		if err != nil {
			t.Fatal(err)
		}
		if err = h.dispatchCommercialCheckout(ctx, team, first); err != nil {
			t.Fatal(err)
		}
		second, err := h.prepareCommercialCheckout(ctx, team)
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range []uuid.UUID{first, second} {
			if err = h.finishCommercialCheckout(ctx, team, id, ""); err != nil {
				t.Fatal(err)
			}
		}
		if _, err = h.assignCommercialOffer(ctx, team, actor, r, true); !errors.Is(err, errCommercialOfferConflict) {
			t.Fatalf("prior dispatched attempt cleared: %v", err)
		}
		var state string
		if err = h.Pool.QueryRow(ctx, `SELECT state FROM billing_commercial_checkout_attempt WHERE id=$1`, first).Scan(&state); err != nil || state != "dispatched" {
			t.Fatalf("lost uncertainty: %s %v", state, err)
		}
	})
	t.Run("expired callback cannot pass a winning assignment", func(t *testing.T) {
		h, team, actor, r := commercialOfferFixture(t)
		ctx := t.Context()
		var attempt uuid.UUID
		if err := h.Pool.QueryRow(ctx, `INSERT INTO billing_commercial_checkout_attempt(team_id,created_at,prepared_until) VALUES($1,clock_timestamp()-interval '2 minutes',clock_timestamp()-interval '1 minute') RETURNING id`, team).Scan(&attempt); err != nil {
			t.Fatal(err)
		}
		if _, err := h.assignCommercialOffer(ctx, team, actor, r, true); err != nil {
			t.Fatal(err)
		}
		var posts atomic.Int32
		commercialCheckoutProvider(t, h, func(w http.ResponseWriter, r *http.Request) { posts.Add(1); fmt.Fprint(w, `{"id":"cus_example"}`) })
		_, err := h.ensureStripeCustomerBeforeCreate(ctx, team, func() error { return h.dispatchCommercialCheckout(ctx, team, attempt) })
		if !errors.Is(err, errCommercialOfferConflict) || posts.Load() != 0 {
			t.Fatalf("stale callback reached provider: posts=%d err=%v", posts.Load(), err)
		}
	})
	t.Run("cleanup racing dispatch", func(t *testing.T) {
		h, team, actor, r := commercialOfferFixture(t)
		ctx := t.Context()
		id, err := h.prepareCommercialCheckout(ctx, team)
		if err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() { result <- h.dispatchCommercialCheckout(ctx, team, id) }()
		if err = h.finishCommercialCheckout(ctx, team, id, ""); err != nil {
			t.Fatal(err)
		}
		dispatchErr := <-result
		_, assignErr := h.assignCommercialOffer(ctx, team, actor, r, true)
		if dispatchErr == nil && !errors.Is(assignErr, errCommercialOfferConflict) {
			t.Fatalf("dispatch winner lost reservation: %v", assignErr)
		}
		if errors.Is(dispatchErr, errCommercialOfferConflict) && assignErr != nil {
			t.Fatalf("no-effect winner retained reservation: %v", assignErr)
		}
		if dispatchErr != nil && !errors.Is(dispatchErr, errCommercialOfferConflict) {
			t.Fatal(dispatchErr)
		}
	})
}

func commercialCheckoutProvider(t *testing.T, h *Handlers, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	h.Stripe = &stripeHTTPClient{baseURL: srv.URL, secretKey: "sk_test_example", apiVersion: "2026-07-29.dahlia", httpClient: srv.Client()}
	return srv
}

func TestYCCommercialOfferCheckoutProviderFence(t *testing.T) {
	t.Run("assignment prevents provider creation", func(t *testing.T) {
		h, team, actor, r := commercialOfferFixture(t)
		ctx := t.Context()
		if _, err := h.assignCommercialOffer(ctx, team, actor, r, true); err != nil {
			t.Fatal(err)
		}
		var posts atomic.Int32
		commercialCheckoutProvider(t, h, func(w http.ResponseWriter, r *http.Request) { posts.Add(1); fmt.Fprint(w, `{"id":"cus_example"}`) })
		if _, err := h.ensureCheckoutStripeCustomer(ctx, team); !errors.Is(err, errCommercialOfferConflict) || posts.Load() != 0 {
			t.Fatalf("assigned team reached provider: posts=%d err=%v", posts.Load(), err)
		}
	})
	t.Run("provider request holds durable eligibility reservation", func(t *testing.T) {
		h, team, actor, r := commercialOfferFixture(t)
		ctx := t.Context()
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		customer := "cus_" + team.String()
		commercialCheckoutProvider(t, h, func(w http.ResponseWriter, r *http.Request) {
			close(entered)
			<-release
			fmt.Fprintf(w, `{"id":%q}`, customer)
		})
		t.Cleanup(func() { once.Do(func() { close(release) }) })
		result := make(chan error, 1)
		go func() { _, err := h.ensureCheckoutStripeCustomer(ctx, team); result <- err }()
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("provider not reached")
		}
		if _, err := h.assignCommercialOffer(ctx, team, actor, r, true); !errors.Is(err, errCommercialOfferConflict) {
			t.Fatalf("in-flight provider attempt allowed assignment: %v", err)
		}
		once.Do(func() { close(release) })
		if err := <-result; err != nil {
			t.Fatal(err)
		}
		if got, err := h.ensureCheckoutStripeCustomer(ctx, team); err != nil || got != customer {
			t.Fatalf("existing-customer replay failed: %s %v", got, err)
		}
		var pending int
		if err := h.Pool.QueryRow(ctx, `SELECT count(*) FROM billing_commercial_checkout_attempt WHERE team_id=$1 AND state<>'customer_observed'`, team).Scan(&pending); err != nil || pending != 0 {
			t.Fatalf("existing customer remained pending: %d %v", pending, err)
		}
	})
	t.Run("lost response preserves uncertainty and idempotency", func(t *testing.T) {
		h, team, actor, r := commercialOfferFixture(t)
		ctx := t.Context()
		var calls atomic.Int32
		customer := "cus_" + team.String()
		commercialCheckoutProvider(t, h, func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Idempotency-Key") != customerCreationIdempotencyKey(team) {
				t.Error("changed customer idempotency")
			}
			if calls.Add(1) == 1 {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				conn.Close()
				return
			}
			fmt.Fprintf(w, `{"id":%q}`, customer)
		})
		if _, err := h.ensureCheckoutStripeCustomer(ctx, team); err == nil {
			t.Fatal("lost response accepted")
		}
		if _, err := h.assignCommercialOffer(ctx, team, actor, r, true); !errors.Is(err, errCommercialOfferConflict) {
			t.Fatalf("lost response released eligibility: %v", err)
		}
		if got, err := h.ensureCheckoutStripeCustomer(ctx, team); err != nil || got != customer {
			t.Fatalf("ordinary retry blocked: %s %v", got, err)
		}
		var count int
		if err := h.Pool.QueryRow(ctx, `SELECT count(*) FROM billing_commercial_checkout_attempt WHERE team_id=$1 AND state='dispatched'`, team).Scan(&count); err != nil || count != 1 {
			t.Fatalf("prior uncertainty erased: %d %v", count, err)
		}
	})
}

func TestYCCommercialOfferRolloutGate(t *testing.T) {
	h, team, actor, r := commercialOfferFixture(t)
	ctx := t.Context()
	if _, err := h.Pool.Exec(ctx, `DELETE FROM team_feature_flag WHERE team_id=$1 AND key='billing_commercial_offer_assignments_enabled'`, team); err != nil {
		t.Fatal(err)
	}
	if _, err := h.assignCommercialOffer(ctx, team, actor, r, true); !errors.Is(err, errCommercialOfferDisabled) {
		t.Fatalf("default-closed service admitted assignment: %v", err)
	}
	// Checkout remains usable while assignment rollout is closed.
	id, err := h.prepareCommercialCheckout(ctx, team)
	if err != nil {
		t.Fatal(err)
	}
	if err = h.finishCommercialCheckout(ctx, team, id, ""); err != nil {
		t.Fatal(err)
	}
	source, sourceTeam, sourceActor, sourceRequest := commercialOfferFixture(t)
	if _, err = source.assignCommercialOffer(ctx, sourceTeam, sourceActor, sourceRequest, true); err != nil {
		t.Fatal(err)
	}
	_, err = h.Pool.Exec(ctx, `INSERT INTO billing_commercial_offer_assignment(team_id,approval_id,company_identity,home_region,offer_key,offer_version,idempotency_key,rate_card_key,rate_ids,pricing_at,request,assigned_by,reason,reference,resource_rates)
 SELECT $1,$2,company_identity,home_region,offer_key,offer_version,idempotency_key,rate_card_key,rate_ids,pricing_at,request,assigned_by,reason,reference,resource_rates FROM billing_commercial_offer_assignment WHERE team_id=$3`, team, r.ApprovalID, sourceTeam)
	if err == nil || !strings.Contains(err.Error(), "assignments are disabled") {
		t.Fatalf("direct insert bypassed rollout gate: %v", err)
	}
}

func TestYCCommercialOfferCheckoutFailureBoundaries(t *testing.T) {
	t.Run("read failure before dispatch releases only preparation", func(t *testing.T) {
		h, team, actor, r := commercialOfferFixture(t)
		ctx := t.Context()
		var calls atomic.Int32
		commercialCheckoutProvider(t, h, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); fmt.Fprint(w, `{"id":"cus_example"}`) })
		closed, err := pgxpool.NewWithConfig(ctx, h.Pool.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		closed.Close()
		original := h.DB
		h.DB = db.New(closed)
		if _, err = h.ensureCheckoutStripeCustomer(ctx, team); err == nil {
			t.Fatal("failed fixture read accepted")
		}
		h.DB = original
		if calls.Load() != 0 {
			t.Fatal("provider called despite pre-dispatch read failure")
		}
		var state string
		if err = h.Pool.QueryRow(ctx, `SELECT state FROM billing_commercial_checkout_attempt WHERE team_id=$1`, team).Scan(&state); err != nil || state != "no_effect" {
			t.Fatalf("proven no-effect failure retained reservation: %s %v", state, err)
		}
		if _, err = h.assignCommercialOffer(ctx, team, actor, r, true); err != nil {
			t.Fatalf("no-effect failure prohibited new assignment: %v", err)
		}
	})
	t.Run("customer success with local failure remains uncertain", func(t *testing.T) {
		h, team, actor, r := commercialOfferFixture(t)
		ctx := t.Context()
		name := pgx.Identifier{"offer_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")}.Sanitize()
		if _, err := h.Pool.Exec(ctx, "ALTER TABLE team_billing_account ADD CONSTRAINT "+name+" CHECK (team_id<>'"+team.String()+"'::uuid OR stripe_customer_id IS NULL)"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if _, err := h.Pool.Exec(context.Background(), "ALTER TABLE team_billing_account DROP CONSTRAINT IF EXISTS "+name); err != nil {
				t.Error(err)
			}
		})
		var calls atomic.Int32
		commercialCheckoutProvider(t, h, func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			fmt.Fprintf(w, `{"id":%q}`, "cus_"+team.String())
		})
		if _, err := h.ensureCheckoutStripeCustomer(ctx, team); err == nil || calls.Load() != 1 {
			t.Fatalf("persistence fault not exercised: calls=%d err=%v", calls.Load(), err)
		}
		var state string
		if err := h.Pool.QueryRow(ctx, `SELECT state FROM billing_commercial_checkout_attempt WHERE team_id=$1`, team).Scan(&state); err != nil || state != "dispatched" {
			t.Fatalf("lost provider success evidence: %s %v", state, err)
		}
		if _, err := h.assignCommercialOffer(ctx, team, actor, r, true); !errors.Is(err, errCommercialOfferConflict) {
			t.Fatalf("local failure released assignment: %v", err)
		}
		if _, err := h.Pool.Exec(ctx, "ALTER TABLE team_billing_account DROP CONSTRAINT "+name); err != nil {
			t.Fatal(err)
		}
		if _, err := h.ensureCheckoutStripeCustomer(ctx, team); err != nil {
			t.Fatalf("ordinary recovery blocked: %v", err)
		}
	})
}
