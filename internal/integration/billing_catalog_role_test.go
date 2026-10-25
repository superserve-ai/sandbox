//go:build integration

package integration

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestIntegration_BillingCatalogProductionRole(t *testing.T) {
	owner := teamCreationDatabase(t, func(pool *pgxpool.Pool) {
		rolloutExec(t, pool, `ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO anon,authenticated,service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO anon,authenticated,service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO anon,authenticated,service_role`)
	})
	service := teamCreationServiceRolePool(t, owner)
	var role string
	var super bool
	if err := service.QueryRow(t.Context(), `SELECT current_user,rolsuper FROM pg_roles WHERE rolname=current_user`).Scan(&role, &super); err != nil || role != "service_role" || super {
		t.Fatalf("role=%s super=%v err=%v", role, super, err)
	}
	actor, outsider := uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{actor, outsider} {
		rolloutExec(t, owner, `INSERT INTO profile(id,email,provider,provider_id) VALUES($1,$2,'google',$2)`, id, id.String()+"@superserve.ai")
	}
	rolloutExec(t, owner, `INSERT INTO user_role_assignments(user_id,role_id,scope_type) SELECT $1,id,'platform' FROM roles WHERE name='platform_admin'`, actor)
	t.Setenv("INTERNAL_API_TOKEN", internalRBACToken)
	t.Setenv("OPERATOR_API_TOKEN", operatorRBACToken)
	h := api.NewHandlers(&stubVMD{}, db.New(service), &config.Config{SystemTeamID: testSystemTeamID.String()})
	h.Pool = service
	router := api.SetupRouter(t.Context(), h, service)
	body := `{"family":"example","kind":"custom","display_name":"Example","limits":{"max_concurrent":12},"reason":"Catalog maintenance"}`
	if w := operatorRequest(router, http.MethodPost, "/internal/billing/catalog/plans", outsider.String(), body); w.Code != http.StatusForbidden {
		t.Fatalf("unauthorized create=%d %s", w.Code, w.Body)
	}
	if w := doInternal(router, http.MethodPost, "/internal/billing/catalog/plans", actor.String(), body); w.Code != http.StatusUnauthorized {
		t.Fatalf("internal credential create=%d %s", w.Code, w.Body)
	}
	t.Run("create", func(t *testing.T) {
		w := operatorRequest(router, http.MethodPost, "/internal/billing/catalog/plans", actor.String(), body)
		if w.Code != http.StatusCreated {
			t.Fatalf("create=%d %s", w.Code, w.Body)
		}
	})
	for _, action := range []string{"update", "delete", "publish", "retire"} {
		t.Run(action, func(t *testing.T) {
			id := uuid.New()
			family := "example" + strings.ReplaceAll(id.String(), "-", "")
			rolloutExec(t, owner, `INSERT INTO billing_plan_version(id,family,version,pricing_version,kind,display_name,max_sandboxes) VALUES($1,$2,1,'legacy','custom','Example',12)`, id, family)
			method, path, payload := http.MethodPost, "/internal/billing/catalog/plans/"+id.String(), `{"reason":"Catalog maintenance"}`
			switch action {
			case "update":
				method = http.MethodPut
				payload = strings.Replace(strings.Replace(body, `"example"`, fmt.Sprintf("%q", family), 1), `"Example"`, `"Updated"`, 1)
			case "delete":
				method = http.MethodDelete
			case "publish":
				rolloutExec(t, owner, `UPDATE billing_plan_version SET kind='subscription',monthly_fee_cents=120000 WHERE id=$1`, id)
				path += "/publish"
			case "retire":
				rolloutExec(t, owner, `SELECT publish_billing_plan_version($1,$2)`, id, actor)
				path += "/retire"
			}
			w := operatorRequest(router, method, path, actor.String(), payload)
			if w.Code != http.StatusOK && !(action == "delete" && w.Code == http.StatusNoContent) {
				t.Fatalf("%s=%d %s", action, w.Code, w.Body)
			}
			if action == "publish" {
				var fee int64
				var cap int32
				if err := service.QueryRow(t.Context(), `SELECT p.charge_amount_cents,l.max_sandboxes FROM billing_plan p JOIN plan_limits l USING(offer_key) WHERE p.offer_key=$1`, family+"_monthly").Scan(&fee, &cap); err != nil || fee != 120000 || cap != 12 {
					t.Fatalf("synced fee=%d cap=%d err=%v", fee, cap, err)
				}
			}
			var count int
			if err := owner.QueryRow(t.Context(), `SELECT count(*) FROM billing_catalog_audit WHERE version_id=$1`, id).Scan(&count); err != nil || count != 1 {
				t.Fatalf("audit count=%d err=%v", count, err)
			}
		})
	}
	t.Run("frozen contract insert", func(t *testing.T) {
		q := db.New(owner)
		team, err := q.CreateTeam(t.Context(), "catalog-role")
		if err != nil {
			t.Fatal(err)
		}
		anchor := time.Now().UTC().Add(-time.Hour)
		customer, subscription := "cus_"+uuid.NewString(), "sub_"+uuid.NewString()
		rolloutExec(t, owner, `INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,commercial_billing_anchor) VALUES($1,$2,$3,$4)`, team.ID, customer, subscription, anchor)
		c, err := q.CreateCommercialContract(t.Context(), db.CreateCommercialContractParams{TeamID: team.ID, OfferKey: "pro_monthly", StartsAt: anchor, CustomerID: customer, SubscriptionID: subscription, BasePriceID: "price_example", ChargeAmountCents: 120000, ChargeIntervalMonths: 1, EntitlementKind: "metered_usage", EntitlementAmountCents: 100000, EntitlementCadence: "monthly", EntitlementAnchor: anchor})
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if _, err = service.Exec(t.Context(), `INSERT INTO billing_contract_limits(contract_id,max_sandboxes,max_template_vcpu,max_template_memory_mib,max_template_disk_mib,max_templates) VALUES($1,12,4,4096,8192,10) ON CONFLICT DO NOTHING`, c.ID); err != nil {
				t.Fatal(err)
			}
		}
		var limit int
		if err = service.QueryRow(t.Context(), `SELECT max_sandboxes FROM billing_contract_limits WHERE contract_id=$1`, c.ID).Scan(&limit); err != nil || limit != 12 {
			t.Fatalf("limit=%d err=%v", limit, err)
		}
	})
	t.Run("denied authority", func(t *testing.T) {
		for _, sql := range []string{`UPDATE billing_pricing_switch SET pricing_version='v2'`, `UPDATE billing_plan_version SET state='retired'`, `UPDATE billing_catalog_audit SET reason='changed'`, `DELETE FROM billing_catalog_audit`, `TRUNCATE billing_catalog_audit`, `UPDATE billing_contract_limits SET max_sandboxes=1`, `DELETE FROM billing_contract_limits`, `TRUNCATE billing_contract_limits`} {
			_, err := service.Exec(t.Context(), sql)
			var pgerr *pgconn.PgError
			if !errors.As(err, &pgerr) || pgerr.Code != "42501" {
				t.Errorf("%s: %v", sql, err)
			}
		}
		for _, role := range []string{"anon", "authenticated"} {
			for _, sql := range []string{`INSERT INTO billing_plan_version(family,version,kind,display_name) VALUES('denied',1,'custom','Denied')`, `SELECT publish_billing_plan_version(NULL,NULL)`, `SELECT retire_billing_plan_version(NULL,NULL)`} {
				tx, err := owner.Begin(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				if _, err = tx.Exec(t.Context(), "SET LOCAL ROLE "+role); err != nil {
					t.Fatal(err)
				}
				_, err = tx.Exec(t.Context(), sql)
				_ = tx.Rollback(t.Context())
				var pgerr *pgconn.PgError
				if !errors.As(err, &pgerr) || pgerr.Code != "42501" {
					t.Errorf("%s %s: %v", role, sql, err)
				}
			}
		}
	})
}
