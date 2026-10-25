//go:build integration

package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const closedPrepaidAssertionSQL = `CREATE OR REPLACE FUNCTION billing_assert_pricing_entry_open(p_epoch uuid DEFAULT NULL,p_pricing_version text DEFAULT NULL)
 RETURNS uuid LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'pricing adoption entry is closed or epoch changed' USING ERRCODE='55000'; END $$`

func installPrepaidPublicStateFixture(t *testing.T, h *Handlers) {
	t.Helper()
	_, err := h.Pool.Exec(t.Context(), `CREATE TABLE billing_pricing_adoption(singleton boolean PRIMARY KEY DEFAULT true,fixture_released boolean NOT NULL);
 INSERT INTO billing_pricing_adoption VALUES(true,true);
 CREATE FUNCTION billing_pricing_public_state() RETURNS TABLE(pricing_version text,entry_open boolean,epoch uuid)
 LANGUAGE sql AS $$ SELECT CASE WHEN s.pricing_version='v2' AND a.fixture_released THEN 'v2' ELSE 'legacy' END,
 COALESCE(s.pricing_version='v2' AND a.fixture_released,false),CASE WHEN a.singleton THEN '97cb97ef-7fde-4676-8d81-2d438939d47c'::uuid END FROM (SELECT 1) seed LEFT JOIN billing_pricing_switch s ON s.singleton LEFT JOIN billing_pricing_adoption a ON a.singleton $$`)
	if err != nil {
		t.Fatal(err)
	}

	_, err = h.Pool.Exec(t.Context(), `CREATE FUNCTION billing_assert_pricing_entry_open(p_epoch uuid DEFAULT NULL,p_pricing_version text DEFAULT NULL)
 RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp AS $$
 DECLARE actual_epoch uuid; model text; opened boolean;
 BEGIN
  SELECT pricing_version,entry_open,epoch INTO model,opened,actual_epoch FROM billing_lock_pricing_public_state();
  IF NOT opened OR actual_epoch IS NULL OR (p_epoch IS NULL)<>(p_pricing_version IS NULL)
   OR (p_epoch IS NOT NULL AND p_epoch<>actual_epoch) OR (p_pricing_version IS NOT NULL AND p_pricing_version<>model) THEN
   RAISE EXCEPTION 'pricing adoption entry is closed or epoch changed' USING ERRCODE='55000';
  END IF;
  RETURN actual_epoch;
 END $$`)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := h.Pool.Exec(context.Background(), `DROP FUNCTION billing_assert_pricing_entry_open(uuid,text); DROP FUNCTION billing_pricing_public_state(); DROP TABLE billing_pricing_adoption`); err != nil {
			t.Error(err)
		}
	})
}

func TestPrepaidAdoptionGateReplaysAcceptedPurchaseButRejectsNewEntry(t *testing.T) {
	f, _ := prepaidPlanFixture(t)
	id, actor := uuid.New(), uuid.New()
	if err := f.h.recordCheckoutPurchase(t.Context(), id, f.team, f.customer, actor, 500, ""); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"preparing", "missing-row", "missing", "off"} {
		t.Run(state, func(t *testing.T) {
			switch state {
			case "preparing":
				f.exec(`UPDATE billing_pricing_adoption SET fixture_released=false`)
			case "missing-row":
				f.exec(`DELETE FROM billing_pricing_adoption`)
			case "missing":
				f.exec(`ALTER TABLE billing_pricing_adoption RENAME TO prepaid_fixture_adoption`)
				defer f.exec(`ALTER TABLE prepaid_fixture_adoption RENAME TO billing_pricing_adoption`)
			case "off":
				setPricingVersion(t, f.h, "legacy")
			}
			if err := f.h.recordCheckoutPurchase(t.Context(), id, f.team, f.customer, actor, 500, ""); err != nil {
				t.Fatal("accepted replay refused", err)
			}
			if err := f.h.recordCheckoutPurchase(t.Context(), uuid.New(), f.team, f.customer, actor, 500, ""); !errors.Is(err, errPricingV2Off) {
				t.Fatal("new entry accepted", err)
			}
			if err := f.h.recordCheckoutPurchase(t.Context(), id, f.team, f.customer, uuid.New(), 500, ""); !errors.Is(err, errPricingV2Off) {
				t.Fatal("different actor treated as replay", err)
			}
		})
	}
	var rows int
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT count(*) FROM billing_prepaid_purchase WHERE team_id=$1`, f.team).Scan(&rows); err != nil || rows != 1 {
		t.Fatal(rows, err)
	}
}

func TestPrepaidAutoRechargeAdoptionGatePreservesBoundNoopAndDisable(t *testing.T) {
	f := newPrepaidFixture(t)
	actor := uuid.New()
	f.exec(`INSERT INTO profile(id,email,provider,provider_id) VALUES($1,$2,'google',$3)`, actor, actor.String()+"@example.com", actor.String())
	f.exec(`INSERT INTO team_memberships(team_id,user_id,status) VALUES($1,$2,'active')`, f.team, actor)
	f.exec(`INSERT INTO user_role_assignments(user_id,role_id,scope_type,team_id) SELECT $1,id,'team',$2 FROM roles WHERE name='team_owner'`, actor, f.team)
	put := func(body string) int {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPut, "/billing/prepaid/auto-recharge", strings.NewReader(body)).WithContext(t.Context())
		c.Request.Header.Set("Content-Type", "application/json")
		c.Set("team_id", f.team.String())
		c.Set("actor_id", actor)
		f.h.PutPrepaidAutoRecharge(c)
		return w.Code
	}
	accepted := `{"enabled":true,"threshold_cents":2000,"amount_cents":5000}`
	if status := put(accepted); status != http.StatusOK {
		t.Fatal("released enable", status)
	}
	f.exec(closedPrepaidAssertionSQL)
	if status := put(`{"enabled":true,"threshold_cents":2000,"amount_cents":5500}`); status != http.StatusConflict {
		t.Fatal("assertion SQLSTATE55000 was not mapped to409", status)
	}
	if status := put(accepted); status != http.StatusOK {
		t.Fatal("no-op replay reached closed assertion", status)
	}
	f.exec(`UPDATE billing_pricing_adoption SET fixture_released=false`)
	for _, state := range []string{"preparing", "off"} {
		t.Run(state, func(t *testing.T) {
			if state == "off" {
				setPricingVersion(t, f.h, "legacy")
			}
			if status := put(accepted); status != http.StatusOK {
				t.Fatal("bound noop refused", status)
			}
			if status := put(`{"enabled":true,"threshold_cents":2000,"amount_cents":5500}`); status != http.StatusConflict {
				t.Fatal("fresh edit accepted", status)
			}
		})
	}
	if status := put(`{"enabled":false}`); status != http.StatusOK {
		t.Fatal("disable refused", status)
	}
	if status := put(accepted); status != http.StatusConflict {
		t.Fatal("fresh reenable accepted", status)
	}
}

func TestPrepaidEntryAssertionFailureCannotCommitOrDispatch(t *testing.T) {
	f := newPrepaidFixture(t)
	f.exec(closedPrepaidAssertionSQL)
	if _, err := f.h.startPrepaidPaymentCheckout(t.Context(), f.client, f.team, uuid.New(), f.customer, 500, "https://console.example.com/ok", "https://console.example.com/cancel"); !errors.Is(err, errPricingV2Off) {
		t.Fatal("assertion conflict not mapped", err)
	}
	if rows := f.rows(); len(rows) != 0 {
		t.Fatal("assertion failure committed a purchase", rows)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sessions) != 0 || len(f.intentPosts) != 0 || len(f.grantPosts) != 0 {
		t.Fatal("assertion failure reached payment provider")
	}
}
