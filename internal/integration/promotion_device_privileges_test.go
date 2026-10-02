//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestIntegration_PromotionRegionalDevicePrivileges(t *testing.T) {
	ctx := context.Background()
	// The roles must exist before migrations apply their conditional grants.
	rolloutExec(t, testPool, `DO $$ DECLARE r text; BEGIN
		FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
			IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN
				EXECUTE format('CREATE ROLE %I NOLOGIN',r);
			END IF;
		END LOOP;
	END $$`)
	region := promotionIsolatedDatabase(t, true)
	user, attempt := uuid.New(), uuid.New()
	event, fingerprint := "event-"+uuid.NewString(), "visitor-"+uuid.NewString()
	promotionAuthRole(t, region, "service_role", func(tx pgx.Tx) {
		var result string
		if err := tx.QueryRow(ctx, `SELECT register_promotion_signup_device($1,$2,$3,$4)`,
			user, attempt, event, fingerprint).Scan(&result); err != nil || result != "owner" {
			t.Fatalf("service registration = %q: %v", result, err)
		}
	})
	team, outcome := promotionClaimSignup(t, region, user)
	if outcome != "granted" {
		t.Fatalf("fixture signup = %q", outcome)
	}
	rolloutExec(t, region, `INSERT INTO team_billing_account(team_id) VALUES($1)`, team)

	tables := []string{
		"promotion_signup_device_evidence", "promotion_device_owner",
		"promotion_device_grant", "promotion_device_policy",
	}
	for _, table := range tables {
		var rls, noPolicies bool
		if err := region.QueryRow(ctx, `SELECT c.relrowsecurity,
			NOT EXISTS(SELECT 1 FROM pg_policy p WHERE p.polrelid=c.oid)
			FROM pg_class c WHERE c.oid=$1::regclass`, "public."+table).Scan(&rls, &noPolicies); err != nil || !rls || !noPolicies {
			t.Fatalf("%s must have default-deny RLS: enabled=%t no_policies=%t err=%v", table, rls, noPolicies, err)
		}
	}
	rpcs := []struct {
		signature string
		query     string
		args      []any
		service   bool
	}{
		{"register_promotion_signup_device(uuid,uuid,text,text)", `SELECT register_promotion_signup_device($1,$2,$3,$4)`, []any{user, attempt, event, fingerprint}, true},
		{"promotion_device_decision(uuid,text)", `SELECT promotion_device_decision($1,'stripe')`, []any{user}, true},
		{"claim_team_signup_trial_with_device(uuid,uuid)", `SELECT * FROM claim_team_signup_trial_with_device($1,$2)`, []any{team, user}, true},
		{"reserve_stripe_promotion_with_device(uuid,uuid,text,text,timestamptz,boolean)", `SELECT reserve_stripe_promotion_with_device($1,$2,$3,NULL,NULL,false)`, []any{team, user, event}, true},
		{"reserve_stripe_promotion_for_event_state(uuid,uuid,text)", `SELECT reserve_stripe_promotion_for_event_state($1,$2,$3)`, []any{team, user, event}, true},
		{"reserve_stripe_promotion_for_subscription_event_state(uuid,uuid,text,text,timestamptz,boolean)", `SELECT reserve_stripe_promotion_for_subscription_event_state($1,$2,$3,'sub_missing',NULL,false)`, []any{team, user, event}, true},
		{"release_stripe_promotion_for_event(uuid,uuid,text)", `SELECT release_stripe_promotion_for_event($1,$2,$3)`, []any{team, user, event}, true},
		{"finalize_stripe_promotion(uuid,uuid,text)", `SELECT finalize_stripe_promotion($1,$2,'')`, []any{team, user}, true},
		{"activate_team_billing(uuid,uuid,text)", `SELECT activate_team_billing($1,$2,'')`, []any{team, user}, true},
		{"activate_team_billing(uuid,text)", `SELECT activate_team_billing($1,'')`, []any{team}, true},
		{"record_stripe_promotion_device_grant(uuid,uuid)", `SELECT record_stripe_promotion_device_grant($1,$2)`, []any{team, user}, true},
		{"set_promotion_device_policy(boolean,boolean)", `SELECT set_promotion_device_policy(false,false)`, nil, false},
		{"set_promotion_device_policy(boolean)", `SELECT set_promotion_device_policy(false)`, nil, false},
		{"protect_promotion_device_fact()", "", nil, false},
	}
	for _, role := range []string{"anon", "authenticated", "service_role"} {
		t.Run(role, func(t *testing.T) {
			for _, table := range tables {
				var access bool
				if err := region.QueryRow(ctx, `SELECT has_table_privilege($1,$2,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')`,
					role, "public."+table).Scan(&access); err != nil || access {
					t.Fatalf("%s direct access to %s: %t, %v", role, table, access, err)
				}
			}
			for _, rpc := range rpcs {
				var access bool
				want := role == "service_role" && rpc.service
				if err := region.QueryRow(ctx, `SELECT has_function_privilege($1,$2,'EXECUTE')`,
					role, "public."+rpc.signature).Scan(&access); err != nil || access != want {
					t.Fatalf("%s execute %s = %t, want %t: %v", role, rpc.signature, access, want, err)
				}
			}
			promotionAuthRole(t, region, role, func(tx pgx.Tx) {
				for _, table := range tables {
					t.Run(table, func(t *testing.T) {
						name := pgx.Identifier{"public", table}.Sanitize()
						column := "fingerprint"
						if table == "promotion_device_policy" {
							column = "device_enforced"
						}
						for _, statement := range []string{
							"SELECT * FROM " + name,
							"INSERT INTO " + name + " DEFAULT VALUES",
							"UPDATE " + name + " SET " + column + "=" + column,
							"DELETE FROM " + name,
							"TRUNCATE " + name,
						} {
							t.Run(statement, func(t *testing.T) {
								localIdentityError(t, tx, "42501", statement)
							})
						}
					})
				}
				for _, rpc := range rpcs {
					if rpc.query != "" && !(role == "service_role" && rpc.service) {
						t.Run(rpc.signature, func(t *testing.T) {
							localIdentityError(t, tx, "42501", rpc.query, rpc.args...)
						})
					}
				}
			})
		})
	}
	promotionAuthRole(t, region, "service_role", func(tx pgx.Tx) {
		var decision, claim, reason, reservation string
		if err := tx.QueryRow(ctx, `SELECT promotion_device_decision($1,'stripe')`, user).Scan(&decision); err != nil || decision != "eligible" {
			t.Fatalf("service decision = %q: %v", decision, err)
		}
		if err := tx.QueryRow(ctx, `SELECT * FROM claim_team_signup_trial_with_device($1,$2)`, team, user).Scan(&claim, &reason); err != nil || claim != "granted" {
			t.Fatalf("service claim replay = %q %q: %v", claim, reason, err)
		}
		if err := tx.QueryRow(ctx, `SELECT reserve_stripe_promotion_with_device($1,$2,$3,NULL,NULL,false)`, team, user, event).Scan(&reservation); err != nil || reservation != "acquired" {
			t.Fatalf("service reservation = %q: %v", reservation, err)
		}
		localIdentityError(t, tx, "55000", `SELECT record_stripe_promotion_device_grant($1,$2)`, team, user)
	})
}
