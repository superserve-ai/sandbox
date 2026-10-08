//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/proxy"
)

func TestMachineReadinessWithRestrictedDatabaseRole(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name, revoke, table, column string
	}{
		{name: "ready"},
		{name: "missing_authority_grant", revoke: "REVOKE SELECT (revocation_generation) ON machine_credential FROM sandbox_proxy_router", table: "machine_credential", column: "revocation_generation"},
		{name: "missing_ownership_grant", revoke: "REVOKE SELECT (owner_principal_id) ON sandbox_machine_owner FROM sandbox_proxy_router", table: "sandbox_machine_owner", column: "owner_principal_id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := testPool.Config()
			config.MaxConns, config.MinConns = 1, 0
			previousAfterConnect := config.AfterConnect
			config.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
				if previousAfterConnect != nil {
					if err := previousAfterConnect(ctx, conn); err != nil {
						return err
					}
				}
				// Keep permission changes uncommitted and private to this one
				// test connection; closing it rolls back without changing any
				// other test's privileges or requiring separate credentials.
				if _, err := conn.Exec(ctx, "BEGIN"); err != nil {
					return err
				}
				if tc.revoke != "" {
					if _, err := conn.Exec(ctx, tc.revoke); err != nil {
						return err
					}
				}
				_, err := conn.Exec(ctx, "SET LOCAL ROLE sandbox_proxy_router")
				return err
			}
			pool, err := pgxpool.NewWithConfig(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			defer pool.Close()
			var role string
			if err := pool.QueryRow(ctx, "SELECT current_user").Scan(&role); err != nil || role != "sandbox_proxy_router" {
				t.Fatalf("wrong probe role %q: %v", role, err)
			}
			if tc.revoke != "" {
				var allowed bool
				if err := pool.QueryRow(ctx, "SELECT has_column_privilege(current_user,$1,$2,'SELECT')", tc.table, tc.column).Scan(&allowed); err != nil || allowed {
					t.Fatalf("missing grant fixture ineffective: allowed=%v err=%v", allowed, err)
				}
			}
			handler := proxy.NewHandler(nil, nil, zerolog.Nop()).
				WithAuth([]byte("machine-readiness-test-key-0123456")).
				WithMachineAuthority(proxy.NewCachedMachineAuthority(pool, 5*time.Second)).
				WithSandboxOwnership(proxy.NewCachedSandboxOwnership(pool))
			if ready := handler.MachineIdentityReady(ctx); ready != (tc.revoke == "") {
				t.Fatalf("database readiness=%v, want %v", ready, tc.revoke == "")
			}
		})
	}
}
