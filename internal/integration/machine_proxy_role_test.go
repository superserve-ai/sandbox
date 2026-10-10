//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/preview"
)

func TestMachineProxyRoleCanReadAuthorityWithoutSecrets(t *testing.T) {
	ctx := context.Background()
	q := db.New(testPool)
	teamID, _ := seedTeamAndKey(t)
	principal := machineRepairPrincipal(t, q, teamID)
	credential := machineRepairIssue(t, q, principal, uuid.New(), uuid.New(), "proxy-role-fixture")
	ordinaryID, machineID := uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{ordinaryID, machineID} {
		if _, err := q.CreateSandbox(ctx, db.CreateSandboxParams{ID: id, TeamID: teamID, Name: id.String(), Status: db.SandboxStatusActive, VcpuCount: 1, MemoryMib: 1, HostID: testDefaultHostID, Metadata: []byte(`{}`), PreviewAccess: preview.AccessPublic}); err != nil {
			t.Fatal(err)
		}
	}
	if err := q.CreateMachineSandboxOwner(ctx, machineID, principal.ID, teamID); err != nil {
		t.Fatal(err)
	}
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
	for _, id := range []uuid.UUID{ordinaryID, machineID} {
		var owner, ownerTeam *string
		err := tx.QueryRow(ctx, `SELECT mo.owner_principal_id::text, mo.team_id::text FROM sandbox s LEFT JOIN sandbox_machine_owner mo ON mo.sandbox_id=s.id WHERE s.id=$1 AND s.team_id=$2 AND s.destroyed_at IS NULL`, id, teamID).Scan(&owner, &ownerTeam)
		if err != nil {
			t.Fatal(err)
		}
		if id == ordinaryID && (owner != nil || ownerTeam != nil) {
			t.Fatal("ordinary sandbox acquired a machine owner")
		}
		if id == machineID && (owner == nil || ownerTeam == nil || *owner != principal.ID.String() || *ownerTeam != teamID.String()) {
			t.Fatal("machine owner association was hidden by restricted role")
		}
	}
	var columnsRestricted bool
	err = tx.QueryRow(ctx, `SELECT bool_and(has_column_privilege(current_user,attrelid,attname,'SELECT') = CASE WHEN attrelid='public.machine_credential'::regclass THEN attname=ANY(ARRAY['id','principal_id','state','expires_at','revocation_generation']) WHEN attrelid='public.machine_principal'::regclass THEN attname=ANY(ARRAY['id','status','generation']) ELSE attname=ANY(ARRAY['sandbox_id','owner_principal_id','team_id']) END) FROM pg_attribute WHERE attrelid IN ('public.machine_credential'::regclass,'public.machine_principal'::regclass,'public.sandbox_machine_owner'::regclass) AND attnum>0 AND NOT attisdropped`).Scan(&columnsRestricted)
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
		"SELECT created_at FROM sandbox_machine_owner",
		"UPDATE sandbox_machine_owner SET owner_principal_id=gen_random_uuid()",
		"DELETE FROM sandbox_machine_owner",
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
