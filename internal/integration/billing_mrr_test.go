//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/config"
)

type mrrTestPlan struct {
	Key      string `json:"key"`
	Name     string `json:"name"`
	Teams    int64  `json:"teams"`
	MRRCents int64  `json:"mrr_cents"`
}

type mrrTestResponse struct {
	Region       string        `json:"region"`
	MRRCents     int64         `json:"mrr_cents"`
	Teams        int64         `json:"teams"`
	RevenueTeams int64         `json:"revenue_teams"`
	Plans        []mrrTestPlan `json:"plans"`
}

func newMRRRouter(t *testing.T, now time.Time) *gin.Engine {
	t.Helper()
	t.Setenv("INTERNAL_API_TOKEN", internalRBACToken)
	t.Setenv("OPERATOR_API_TOKEN", operatorRBACToken)
	h := api.NewHandlers(&stubVMD{}, testQueries, &config.Config{Port: "0", VMDAddress: "localhost:0", SystemTeamID: testSystemTeamID.String(), DefaultHostID: testDefaultHostID, TeamCreationRegion: "use"})
	h.Pool = testPool
	h.Now = func() time.Time { return now }
	registerTestHandlers(h)
	return api.SetupRouter(t.Context(), h, testPool)
}

func getMRR(t *testing.T, r *gin.Engine, actor uuid.UUID) mrrTestResponse {
	t.Helper()
	w := doInternal(r, http.MethodGet, "/internal/billing/mrr", actor.String(), "")
	if w.Code != http.StatusOK {
		t.Fatalf("mrr status %d: %s", w.Code, w.Body.String())
	}
	var out mrrTestResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func (m mrrTestResponse) plan(key string) mrrTestPlan {
	for _, p := range m.Plans {
		if p.Key == key {
			return p
		}
	}
	return mrrTestPlan{Key: key}
}

func TestIntegration_PlatformBillingMRR(t *testing.T) {
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Second)
	r := newMRRRouter(t, now)
	admin := seedPlatformAdminProfile(t)

	if w := doInternal(r, http.MethodGet, "/internal/billing/mrr", seedSuperserveEmailProfile(t).String(), ""); w.Code != http.StatusForbidden {
		t.Fatalf("unprivileged status = %d", w.Code)
	}
	if w := doInternal(r, http.MethodGet, "/internal/billing/mrr", "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d", w.Code)
	}

	before := getMRR(t, r, admin)

	// Fixtures describe contract states directly; the lifecycle triggers that
	// produce them are covered by their own suites.
	var contracts []uuid.UUID
	t.Cleanup(func() {
		ctx := context.Background()
		tx, err := testPool.Begin(ctx)
		if err != nil {
			t.Error(err)
			return
		}
		defer tx.Rollback(ctx)
		for _, sql := range []string{
			`SET LOCAL session_replication_role=replica`,
			`DELETE FROM billing_sponsored_annual_authority WHERE contract_id=ANY($1)`,
			`DELETE FROM billing_commercial_contract WHERE id=ANY($1)`,
		} {
			args := []any{contracts}
			if strings.HasPrefix(sql, "SET") {
				args = nil
			}
			if _, err := tx.Exec(ctx, sql, args...); err != nil {
				t.Error(err)
				return
			}
		}
		if err := tx.Commit(ctx); err != nil {
			t.Error(err)
		}
	})
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role=replica`); err != nil {
		t.Fatal(err)
	}

	newTeam := func(region string) uuid.UUID {
		t.Helper()
		team, err := testQueries.CreateTeam(ctx, "mrr-"+uuid.NewString()[:8])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `UPDATE team SET home_region=$2 WHERE id=$1`, team.ID, region); err != nil {
			t.Fatal(err)
		}
		return team.ID
	}
	type contract struct {
		offer, status, kind string
		amount              int64
		months              int32
		starts              time.Time
		ends                *time.Time
	}
	insert := func(team uuid.UUID, c contract) uuid.UUID {
		t.Helper()
		id := uuid.New()
		price, cadence := "price_"+c.offer, "monthly"
		if c.kind == "sponsored_entitlement" {
			price, cadence = "", "scheduled"
		}
		if _, err := tx.Exec(ctx, `INSERT INTO billing_commercial_contract
			(id,team_id,offer_key,status,starts_at,ends_at,customer_id,subscription_id,base_price_id,charge_kind,charge_amount_cents,charge_interval_months,
			 entitlement_amount_cents,entitlement_cadence,entitlement_anchor)
			VALUES($1::uuid,$2,$3,$4,$5,$6,'cus_'||$1::text,'sub_'||$1::text,$7,$8,$9,$10,100000,$11,$5)`,
			id, team, c.offer, c.status, c.starts, c.ends, price, c.kind, c.amount, c.months, cadence); err != nil {
			t.Fatal(err)
		}
		contracts = append(contracts, id)
		return id
	}
	past, future := now.AddDate(0, -2, 0), now.AddDate(0, 1, 0)
	lapsed, yearEnd := now.Add(-time.Minute), now.AddDate(0, 10, 0)
	proMonthly := contract{"pro_monthly", "active", "subscription", 120000, 1, past, nil}

	insert(newTeam("use"), proMonthly)
	insert(newTeam("use"), contract{"pro_annual", "active", "subscription", 1200000, 12, past, nil})
	insert(newTeam("use"), contract{"starter_monthly", "active", "subscription", 10000, 1, past, nil})
	insert(newTeam("use"), contract{"yc_2026", "active", "upfront", 10000000, 3, past, &yearEnd})
	insert(newTeam("use"), contract{"sponsored_usage", "active", "sponsored_entitlement", 0, 1, past, &yearEnd})
	sponsoredTeam := newTeam("use")
	sponsored := insert(sponsoredTeam, contract{"sponsored_usage", "active", "sponsored_entitlement", 0, 1, past, &yearEnd})
	if _, err := tx.Exec(ctx, `INSERT INTO billing_sponsored_annual_authority
		(team_id,sponsorship_id,contract_id,idempotency_key,request,approved_by,customer_id,subscription_id,item_id,base_price_id,base_product_id,live_mode,home_region,starts_at,waiver_ends_at,provider_evidence)
		VALUES($1,gen_random_uuid(),$2::uuid,'mrr','{}',gen_random_uuid(),'cus_'||$2::text,'sub_'||$2::text,'si_'||$2::text,'price_pro_annual','prod_pro',false,'use',$3,billing_anniversary_boundary($3,12),'{}')`,
		sponsoredTeam, sponsored, past); err != nil {
		t.Fatal(err)
	}
	endedAuthorityTeam := newTeam("use")
	endedAuthority := insert(endedAuthorityTeam, contract{"sponsored_usage", "active", "sponsored_entitlement", 0, 1, past, &yearEnd})
	if _, err := tx.Exec(ctx, `INSERT INTO billing_sponsored_annual_authority
		(team_id,sponsorship_id,contract_id,idempotency_key,request,approved_by,customer_id,subscription_id,item_id,base_price_id,base_product_id,live_mode,home_region,starts_at,waiver_ends_at,provider_evidence,state)
		VALUES($1,gen_random_uuid(),$2::uuid,'mrr','{}',gen_random_uuid(),'cus_'||$2::text,'sub_'||$2::text,'si_'||$2::text,'price_pro_annual','prod_pro',false,'use',$3,billing_anniversary_boundary($3,12),'{}','ended')`,
		endedAuthorityTeam, endedAuthority, past); err != nil {
		t.Fatal(err)
	}

	pending := proMonthly
	pending.status = "pending"
	insert(newTeam("use"), pending)
	ended := proMonthly
	ended.status = "ended"
	insert(newTeam("use"), ended)
	expired := proMonthly
	expired.ends = &lapsed
	insert(newTeam("use"), expired)
	notStarted := proMonthly
	notStarted.starts = future
	insert(newTeam("use"), notStarted)
	insert(newTeam("usw"), proMonthly)
	insert(testSystemTeamID, proMonthly)

	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	after := getMRR(t, r, admin)
	if after.Region != "use" {
		t.Fatalf("region = %q", after.Region)
	}
	if d := after.MRRCents - before.MRRCents; d != 120000+100000+10000+100000+100000 {
		t.Fatalf("mrr delta = %d", d)
	}
	if d := after.Teams - before.Teams; d != 11 {
		t.Fatalf("team delta = %d", d)
	}
	if d := after.RevenueTeams - before.RevenueTeams; d != 5 {
		t.Fatalf("revenue team delta = %d", d)
	}
	for _, want := range []mrrTestPlan{
		{Key: "pro_monthly", Teams: 1, MRRCents: 120000},
		{Key: "pro_annual", Teams: 1, MRRCents: 100000},
		{Key: "starter_monthly", Teams: 1, MRRCents: 10000},
		{Key: "yc_2026", Teams: 1, MRRCents: 100000},
		{Key: "sponsored_annual_pro", Teams: 1, MRRCents: 100000},
		{Key: "sponsored_usage", Teams: 2, MRRCents: 0},
		{Key: "payg", Teams: 4, MRRCents: 0},
	} {
		got, was := after.plan(want.Key), before.plan(want.Key)
		if got.Teams-was.Teams != want.Teams || got.MRRCents-was.MRRCents != want.MRRCents {
			t.Errorf("%s delta = %d teams / %d cents, want %d / %d", want.Key, got.Teams-was.Teams, got.MRRCents-was.MRRCents, want.Teams, want.MRRCents)
		}
	}
	if name := after.plan("starter_monthly").Name; name != "Starter monthly" {
		t.Errorf("starter name = %q", name)
	}
}
