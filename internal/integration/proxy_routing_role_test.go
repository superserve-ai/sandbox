//go:build integration

package integration

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// TestMain applies the complete migration history, including the routing role.
func TestIntegration_ProxyRoutingRoleMigration(t *testing.T) {
	ctx := context.Background()
	migration, err := os.ReadFile("../../supabase/migrations/20260917194153_sandbox_proxy_router.sql")
	if err != nil {
		t.Fatal(err)
	}
	team, _ := seedTeamAndKey(t)
	sandboxID := seedPrivatePreviewSandbox(t, team, testDefaultHostID, "example-routing")
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	exec := func(t *testing.T, sql string) {
		t.Helper()
		if _, err := tx.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	// Keep unrelated privileges intact while repairing partial or stale setup.
	exec(t, `CREATE TABLE public.example_routing_grant(id int);
 GRANT SELECT ON public.example_routing_grant TO sandbox_proxy_router;`)
	for _, state := range []string{"existing", "stale", "partial"} {
		t.Run(state, func(t *testing.T) {
			if state == "stale" {
				exec(t, `ALTER ROLE sandbox_proxy_router SET default_transaction_read_only = off;
    ALTER ROLE sandbox_proxy_router SET statement_timeout = '5s';
    ALTER POLICY proxy_routing_read ON public.sandbox TO PUBLIC USING (false);
    ALTER POLICY proxy_routing_read ON public.host TO PUBLIC USING (false);`)
			}
			if state == "partial" {
				exec(t, `DROP POLICY proxy_routing_read ON public.sandbox;
    DROP POLICY proxy_routing_read ON public.host;
    REVOKE SELECT (id, host_id, destroyed_at) ON public.sandbox FROM sandbox_proxy_router;
    REVOKE SELECT (id, vmd_addr, proxy_addr, incarnation_id, peer_generation, last_heartbeat_at) ON public.host FROM sandbox_proxy_router;`)
			}
			exec(t, string(migration))
			exec(t, string(migration))
			var valid bool
			err := tx.QueryRow(ctx, `SELECT rolcanlogin AND NOT rolinherit AND NOT rolsuper
    AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls
    AND rolconnlimit = 32 AND rolconfig @> ARRAY['default_transaction_read_only=on','statement_timeout=500ms']
    FROM pg_roles WHERE rolname = 'sandbox_proxy_router'`).Scan(&valid)
			if err != nil || !valid {
				t.Fatalf("role contract: %v, %v", valid, err)
			}
			err = tx.QueryRow(ctx, `SELECT count(*) = 2 FROM pg_policies
    WHERE schemaname = 'public' AND tablename IN ('sandbox','host')
    AND policyname = 'proxy_routing_read' AND cmd = 'SELECT'
    AND roles = ARRAY['sandbox_proxy_router']::name[] AND qual = 'true'`).Scan(&valid)
			if err != nil || !valid {
				t.Fatalf("policy contract: %v, %v", valid, err)
			}
			exec(t, "SET LOCAL ROLE sandbox_proxy_router")
			// Verify every current column, including columns outside the lookup contract.
			err = tx.QueryRow(ctx, `SELECT bool_and(
    has_column_privilege(current_user, attrelid, attname, 'SELECT') =
    CASE WHEN attrelid = 'public.sandbox'::regclass THEN attname = ANY(ARRAY['id','host_id','destroyed_at'])
    ELSE attname = ANY(ARRAY['id','vmd_addr','proxy_addr','incarnation_id','peer_generation','last_heartbeat_at']) END)
    FROM pg_attribute WHERE attrelid IN ('public.sandbox'::regclass, 'public.host'::regclass)
    AND attnum > 0 AND NOT attisdropped`).Scan(&valid)
			if err != nil || !valid {
				t.Fatalf("column permissions: %v, %v", valid, err)
			}
			var hostID string
			err = tx.QueryRow(ctx, `SELECT h.id FROM public.sandbox s JOIN public.host h ON h.id=s.host_id
    WHERE s.id=$1 AND s.destroyed_at IS NULL`, sandboxID).Scan(&hostID)
			if err != nil || hostID != testDefaultHostID {
				t.Fatalf("routing read: %q, %v", hostID, err)
			}
			exec(t, "SELECT id FROM public.example_routing_grant")
			exec(t, "SET LOCAL default_transaction_read_only = off")
			for _, query := range []string{
				"SELECT secret_env_fingerprint FROM public.sandbox",
				"UPDATE public.sandbox SET host_id='other'",
				"INSERT INTO public.host(id) VALUES('other')",
				"UPDATE public.host SET proxy_addr='192.0.2.2:5009'",
				"DELETE FROM public.host",
			} {
				exec(t, "SAVEPOINT forbidden")
				_, err := tx.Exec(ctx, query)
				var pgErr *pgconn.PgError
				if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
					t.Errorf("expected permission denial for %s: %v", query, err)
				}
				exec(t, "ROLLBACK TO SAVEPOINT forbidden")
			}
			exec(t, "RESET ROLE")
		})
	}
}
