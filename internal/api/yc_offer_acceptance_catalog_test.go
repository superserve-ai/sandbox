//go:build integration

package api

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/ycclaims"
)

func acceptedCatalogFixture(t *testing.T) (*YCOfferAcceptanceService, YCAcceptanceRecord) {
	t.Helper()
	h, _ := fundingTransitionFixture(t)
	ctx := t.Context()
	ensureYCTestAuthority(t, h.Pool)
	h.PromotionAuthPool = h.Pool
	h.Config = &config.Config{TeamCreationRegion: "use"}
	var present bool
	if err := h.Pool.QueryRow(ctx, `SELECT to_regclass('public.yc_offer_acceptance_authority') IS NOT NULL`).Scan(&present); err != nil {
		t.Fatal(err)
	}
	if !present {
		b, err := os.ReadFile("../../supabase/shared-auth-migrations/20261021135531_yc_offer_acceptance_authority.sql")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = h.Pool.Exec(ctx, string(b)); err != nil {
			t.Fatal(err)
		}
	}
	email := uuid.NewString() + "@example.test"
	user := uuid.New()
	raw, err := h.ycClaimRPC(ctx, "submit", gin.H{"submitted_email": email, "founder_email": "founder@example.test", "company_identity": "https://www.ycombinator.com/companies/" + uuid.NewString(), "evidence": gin.H{"verified": true}, "verification_reference": ycclaims.Hash(email), "state": "manual_review", "reason": "email_mismatch"})
	if err != nil {
		t.Fatal(err)
	}
	var claim struct {
		ID uuid.UUID `json:"id"`
	}
	if err = json.Unmarshal(raw, &claim); err != nil {
		t.Fatal(err)
	}
	if _, err = h.Pool.Exec(ctx, `INSERT INTO auth.users(id,email,email_confirmed_at,created_at) VALUES($1,$2,clock_timestamp(),clock_timestamp())`, user, email); err != nil {
		t.Fatal(err)
	}
	team, err := h.DB.CreateTeam(ctx, "accepted-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.Pool.Exec(ctx, `UPDATE team SET home_region='use' WHERE id=$1`, team.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = h.Pool.Exec(ctx, `INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_commercial_offer_assignments_enabled',true)`, team.ID); err != nil {
		t.Fatal(err)
	}
	p := gin.H{"id": claim.ID, "user_id": user, "team_id": team.ID, "home_region": "use", "actor_id": uuid.New(), "request_id": uuid.New(), "expected_revision": 0, "reason": "Synthetic approved signup", "evidence_reference": "synthetic"}
	if _, err = h.ycBindWithIntentRPC(ctx, "approve", p, h.ycStaffRPC); err != nil {
		t.Fatal(err)
	}
	s := &YCOfferAcceptanceService{Pool: h.Pool, Shared: h.Pool, Region: "use", Authorize: func(_ context.Context, u, tm uuid.UUID) error {
		if u != user || tm != team.ID {
			return errYCAcceptanceConflict
		}
		return nil
	}}
	s.Catalog = ycAcceptedCatalog{h: h, s: s}
	r, err := s.Offer(ctx, user, team.ID, claim.ID)
	if err != nil {
		t.Fatal(err)
	}
	r, err = s.Accept(ctx, user, acceptanceRequest(r))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.rpc(ctx, s.Shared, "accept", ycAcceptanceParameters(r)); err != nil {
		t.Fatal(err)
	}
	// This disposable database keeps immutable audit rows across serial tests.
	// Only the current fixture may be due for the region-wide consumer.
	if _, err = s.Pool.Exec(ctx, `UPDATE yc_offer_acceptance SET next_attempt_at='infinity' WHERE id<>$1`, r.ID); err != nil {
		t.Fatal(err)
	}
	fixturePool := s.Pool
	t.Cleanup(func() {
		fixturePool.Exec(context.Background(), `UPDATE yc_offer_acceptance SET next_attempt_at='infinity' WHERE id=$1`, r.ID)
	})
	return s, r
}

func TestYCAcceptedCatalogPreservesRatesAcrossPublicationAndRetry(t *testing.T) {
	s, r := acceptedCatalogFixture(t)
	ctx := t.Context()
	admin := s.Pool
	restricted := acceptedCatalogRestrictedPool(t, admin)
	c := s.Catalog.(ycAcceptedCatalog)
	c.h.Pool = restricted
	s.Pool = restricted
	var canUpdate bool
	if err := restricted.QueryRow(ctx, `SELECT has_table_privilege(current_user,'pricing_rate','UPDATE') OR has_table_privilege(current_user,'billing_commercial_offer_version','UPDATE')`).Scan(&canUpdate); err != nil || canUpdate {
		t.Fatal("restricted fixture can mutate pricing/catalog", err)
	}
	boundary := time.Now().UTC()
	newIDs := []uuid.UUID{}
	for _, rate := range r.Terms.ResourceRates {
		if _, err := admin.Exec(ctx, `UPDATE pricing_rate SET effective_to=$2 WHERE id=$1`, rate.ID, boundary); err != nil {
			t.Fatal(err)
		}
		id := uuid.New()
		newIDs = append(newIDs, id)
		if _, err := admin.Exec(ctx, `INSERT INTO pricing_rate(id,plan_key,resource,unit,price_usd,effective_from) VALUES($1,$2,$3,$4,$5::numeric+0.01,$6)`, id, r.Terms.RateCardKey, rate.Resource, rate.Unit, rate.PriceUSD, boundary); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, id := range newIDs {
			admin.Exec(context.Background(), `DELETE FROM pricing_rate WHERE id=$1`, id)
		}
		for _, rate := range r.Terms.ResourceRates {
			admin.Exec(context.Background(), `UPDATE pricing_rate SET effective_to=NULL,price_usd=$2::numeric WHERE id=$1`, rate.ID, rate.PriceUSD)
		}
	})
	assignment, err := s.Catalog.Assign(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if err = verifyAcceptedAssignment(ctx, s.Pool, r, assignment); err != nil {
		t.Fatal("assigned new prices instead of accepted prices", err)
	}
	// Once the immutable assignment exists, privileged historical changes cannot
	// strand an idempotent retry or cause a new snapshot to replace its prices.
	if _, err = admin.Exec(ctx, `UPDATE pricing_rate SET price_usd=price_usd+1 WHERE id=$1`, r.Terms.ResourceRates[0].ID); err != nil {
		t.Fatal(err)
	}
	replay, err := s.Catalog.Assign(ctx, r)
	if err != nil || replay != assignment {
		t.Fatal("historical assignment replay changed", replay, err)
	}
	r.AssignmentID = &assignment
	if _, err = s.rpc(ctx, s.Shared, "link", ycAcceptanceParameters(r)); err != nil {
		t.Fatal(err)
	}
	// Simulate shared link success with a lost regional acknowledgement.
	r.AssignmentID = nil
	if replay, err = s.Catalog.Assign(ctx, r); err != nil || replay != assignment {
		t.Fatal("shared link recovery stranded", replay, err)
	}
}

func acceptedCatalogRestrictedPool(t *testing.T, admin *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	pool := commercialOfferRestrictedPool(t, admin)
	ctx := t.Context()
	var role string
	if err := pool.QueryRow(ctx, `SELECT current_user`).Scan(&role); err != nil {
		t.Fatal(err)
	}
	quoted := pgx.Identifier{role}.Sanitize()
	for _, grant := range []struct{ table, privilege string }{
		{"yc_offer_acceptance", "SELECT"}, {"pricing_rate", "SELECT"}, {"pricing_plan", "SELECT"},
		{"billing_commercial_offer_audit", "SELECT,INSERT"}, {"billing_sponsored_operation", "SELECT"}, {"billing_plan_release", "SELECT"}, {"billing_usage_entitlement", "SELECT"},
	} {
		table := pgx.Identifier{grant.table}.Sanitize()
		if _, err := admin.Exec(ctx, "GRANT "+grant.privilege+" ON "+table+" TO "+quoted+"; CREATE POLICY "+quoted+" ON "+table+" TO "+quoted+" USING(true) WITH CHECK(true)"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := admin.Exec(ctx, "GRANT EXECUTE ON FUNCTION public.lock_yc_accepted_offer_rates(uuid),public.billing_yc_released(uuid) TO "+quoted); err != nil {
		t.Fatal(err)
	}
	return pool
}

func TestYCAcceptedCatalogRejectsChangedOrLockedHistoricalRate(t *testing.T) {
	s, r := acceptedCatalogFixture(t)
	ctx := t.Context()
	rate := r.Terms.ResourceRates[0]
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE pricing_rate SET price_usd=price_usd+1 WHERE id=$1`, rate.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Catalog.Assign(ctx, r); err == nil {
		t.Fatal("assignment raced historical price mutation")
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.Pool.Exec(context.Background(), `UPDATE pricing_rate SET price_usd=$2::numeric WHERE id=$1`, rate.ID, rate.PriceUSD)
	})
	if _, err = s.Catalog.Assign(ctx, r); err == nil {
		t.Fatal("changed price accepted")
	}
	var count int
	if err = s.Pool.QueryRow(ctx, `SELECT count(*) FROM billing_commercial_offer_assignment WHERE team_id=$1`, r.TeamID).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed validation committed an assignment", count, err)
	}
}

func TestYCAcceptedRateHelperRejectsMalformedSnapshotsAndUntrustedRoles(t *testing.T) {
	s, r := acceptedCatalogFixture(t)
	ctx := t.Context()
	for _, role := range []string{"anon", "authenticated"} {
		tx, err := s.Pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
			rollbackYCAcceptance(ctx, tx)
			t.Fatal(err)
		}
		var ok bool
		err = tx.QueryRow(ctx, `SELECT public.lock_yc_accepted_offer_rates($1)`, r.ID).Scan(&ok)
		rollbackYCAcceptance(ctx, tx)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "42501" {
			t.Fatal("untrusted role could invoke rate-lock helper", role, err)
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func([]YCAcceptanceRate) any
	}{
		{"oversized price", func(v []YCAcceptanceRate) any { v[0].PriceUSD = strings.Repeat("9", 1000); return v }},
		{"unsupported resource", func(v []YCAcceptanceRate) any { v[0].Resource = "arbitrary"; return v }},
		{"duplicate resource", func(v []YCAcceptanceRate) any { v[0] = v[1]; return v }},
		{"extra rate", func(v []YCAcceptanceRate) any { return append(v, v[0]) }},
		{"wrong unit", func(v []YCAcceptanceRate) any { v[0].Unit = "hour"; return v }},
		{"wrong currency", func(v []YCAcceptanceRate) any { v[0].Currency = "EUR"; return v }},
		{"missing rates", func([]YCAcceptanceRate) any { return nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rates := append([]YCAcceptanceRate(nil), r.Terms.ResourceRates...)
			raw, err := json.Marshal(tc.mutate(rates))
			if err != nil {
				t.Fatal(err)
			}
			tx, err := s.Pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackYCAcceptance(ctx, tx)
			// Inject corrupt persisted data as the fixture owner. Runtime roles retain
			// the immutable acceptance trigger and cannot perform this setup.
			if _, err = tx.Exec(ctx, `SET LOCAL session_replication_role=replica`); err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, `UPDATE yc_offer_acceptance SET terms=jsonb_set(terms,'{resource_rates}',$2::jsonb) WHERE id=$1`, r.ID, raw); err != nil {
				t.Fatal(err)
			}
			var ok bool
			if err = tx.QueryRow(ctx, `SELECT public.lock_yc_accepted_offer_rates($1)`, r.ID).Scan(&ok); err != nil || ok {
				t.Fatal("malformed snapshot was not rejected", ok, err)
			}
		})
	}
}
