//go:build integration

package main

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Exercise the production batch query: migration must carry an explicit
// ordinary attestation or the durable machine association, never a creator.
func TestMigrationOwnershipBatch(t *testing.T) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not configured")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `CREATE TEMP TABLE sandbox (id uuid, vcpu_count int, memory_mib int, team_id uuid, timeout_seconds int, network_config jsonb, snapshot_id uuid, host_id text, status text, destroyed_at timestamptz);
 CREATE TEMP TABLE sandbox_machine_owner (sandbox_id uuid, owner_principal_id uuid, team_id uuid);
 CREATE TEMP TABLE artifact_manifest (snapshot_id uuid, file_name text, sha256 text);
 CREATE TEMP TABLE snapshot (id uuid, generation bigint);
 INSERT INTO sandbox VALUES
 ('10000000-0000-0000-0000-000000000001',1,512,'20000000-0000-0000-0000-000000000001',60,'{}',NULL,'source','paused',NULL),
 ('10000000-0000-0000-0000-000000000002',1,512,'20000000-0000-0000-0000-000000000001',60,'{}',NULL,'source','paused',NULL),
 ('10000000-0000-0000-0000-000000000003',1,512,'20000000-0000-0000-0000-000000000001',60,'{}',NULL,'source','paused',NULL);
 INSERT INTO sandbox_machine_owner VALUES
 ('10000000-0000-0000-0000-000000000002','30000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000001'),
 ('10000000-0000-0000-0000-000000000003','30000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000002');`)
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]string{
		"10000000-0000-0000-0000-000000000001": "ordinary:attested",
		"10000000-0000-0000-0000-000000000002": "machine:30000000-0000-0000-0000-000000000001",
		"10000000-0000-0000-0000-000000000003": "machine:",
	}
	ids := make([]string, 0, len(expected))
	for id := range expected {
		ids = append(ids, id)
	}
	rows, err := tx.Query(ctx, migrationShapesSQL, ids, "source")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, team, recorded, owner string
		var vcpu, mem int32
		var timeout *int32
		var raw []byte
		var snapshot *string
		var generation int64
		if err := rows.Scan(&id, &vcpu, &mem, &team, &timeout, &raw, &recorded, &snapshot, &generation, &owner); err != nil {
			t.Fatal(err)
		}
		if want, ok := expected[id]; !ok || owner != want {
			t.Fatalf("sandbox %s owner = %q, want %q", id, owner, want)
		}
		delete(expected, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(expected) != 0 {
		t.Fatalf("missing rows: %v", expected)
	}
}
