//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/superserve-ai/sandbox/internal/db"
)

func TestMachineProxyRoleCanReadAuthorityWithoutSecrets(t *testing.T) {
	ctx := context.Background()
	q := db.New(testPool)
	teamID, _ := seedTeamAndKey(t)
	principal := machineRepairPrincipal(t, q, teamID)
	credential := machineRepairIssue(t, q, principal, uuid.New(), uuid.New(), "proxy-role-fixture")
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	exec := func(sql string) {
		t.Helper()
		if _, err := tx.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	exec("SET LOCAL ROLE sandbox_proxy_router")
	var generation int64
	// This is the production cached authority lookup, executed with the same
	// restricted role used by the proxy ownership connection pool.
	err = tx.QueryRow(ctx, `SELECT c.revocation_generation FROM machine_credential c JOIN machine_principal p ON p.id=c.principal_id WHERE c.id=$1 AND c.principal_id=$2 AND c.state='active' AND c.expires_at>now() AND p.status='active' AND c.revocation_generation=p.generation`, credential.ID, principal.ID).Scan(&generation)
	if err != nil || generation != principal.Generation {
		t.Fatalf("restricted proxy authority lookup: generation=%d err=%v", generation, err)
	}
	var columnsRestricted bool
	err = tx.QueryRow(ctx, `SELECT bool_and(has_column_privilege(current_user,attrelid,attname,'SELECT') = CASE WHEN attrelid='public.machine_credential'::regclass THEN attname=ANY(ARRAY['id','principal_id','state','expires_at','revocation_generation']) ELSE attname=ANY(ARRAY['id','status','generation']) END) FROM pg_attribute WHERE attrelid IN ('public.machine_credential'::regclass,'public.machine_principal'::regclass) AND attnum>0 AND NOT attisdropped`).Scan(&columnsRestricted)
	if err != nil || !columnsRestricted {
		t.Fatalf("proxy column grant boundary: restricted=%v err=%v", columnsRestricted, err)
	}
	// Prove grants enforce the boundary even if the connection's read-only
	// default is accidentally disabled by a caller.
	exec("SET LOCAL default_transaction_read_only = off")
	for _, query := range []string{
		"SELECT secret_hash FROM machine_credential",
		"SELECT permissions FROM machine_credential",
		"SELECT team_id FROM machine_principal",
		"SELECT input_digest FROM machine_lifecycle_operation",
		"SELECT owner_principal_id FROM sandbox_machine_owner",
		"UPDATE machine_credential SET state='active'",
		"UPDATE machine_principal SET status='active'",
		"INSERT INTO machine_lifecycle_operation(principal_id,operation_id,operation_kind,expected_generation) VALUES(gen_random_uuid(),gen_random_uuid(),'disable',1)",
		"DELETE FROM machine_credential",
		"SELECT ensure_machine_principal(gen_random_uuid(),gen_random_uuid(),NULL)",
	} {
		exec("SAVEPOINT forbidden")
		_, err := tx.Exec(ctx, query)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Errorf("expected permission denial for %s: %v", query, err)
		}
		exec("ROLLBACK TO SAVEPOINT forbidden")
	}
}
