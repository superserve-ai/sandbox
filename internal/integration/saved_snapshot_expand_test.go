//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestSavedSnapshotExpandRolloutGuards(t *testing.T) {
	ctx := context.Background()

	var unique, valid, ready, partial bool
	err := testPool.QueryRow(ctx, `
		SELECT i.indisunique,
		       i.indisvalid,
		       i.indisready,
		       i.indpred IS NOT NULL
		FROM pg_index i
		JOIN pg_class idx ON idx.oid = i.indexrelid
		JOIN pg_namespace ns ON ns.oid = idx.relnamespace
		WHERE ns.nspname = 'public'
		  AND idx.relname = 'snapshot_sandbox_unique'
		  AND i.indrelid = 'public.snapshot'::regclass
	`).Scan(&unique, &valid, &ready, &partial)
	if err != nil {
		t.Fatalf("inspect snapshot_sandbox_unique: %v", err)
	}
	if !unique || !valid || !ready || partial {
		t.Error("legacy snapshot_sandbox_unique is not a ready, valid, non-partial unique index")
	}

	constraints := []string{
		"snapshot_name_valid",
		"snapshot_idempotency_key_valid",
		"snapshot_vcpu_positive",
		"snapshot_memory_positive",
		"snapshot_disk_positive",
		"snapshot_logical_size_non_negative",
		"snapshot_exclusive_size_non_negative",
		"snapshot_artifact_metadata_object",
		"snapshot_secret_bindings_array",
		"snapshot_secret_env_keys_array",
		"snapshot_runtime_shape",
		"snapshot_saved_source_shape",
		"snapshot_ready_artifact_shape",
		"snapshot_deleted_state",
		"snapshot_template_id_fk",
		"snapshot_parent_team_fk",
		"snapshot_source_sandbox_team_fk",
		"team_max_snapshots_positive",
		"team_max_snapshots_per_sandbox_positive",
		"team_snapshot_storage_quota_non_negative",
		"team_snapshot_storage_non_negative",
		"sandbox_source_snapshot_team_fk",
		"sandbox_snapshot_operation_team_fk",
		"sandbox_snapshot_operation_pair",
		"sandbox_secret_env_keys_array",
	}
	var validated int
	if err := testPool.QueryRow(ctx, `
		SELECT count(*)
		FROM pg_constraint
		WHERE conname = ANY($1::text[])
		  AND convalidated
	`, constraints).Scan(&validated); err != nil {
		t.Fatalf("inspect validated expand constraints: %v", err)
	}
	if validated != len(constraints) {
		t.Errorf("validated expand constraints = %d, want %d", validated, len(constraints))
	}

	var globalEnabled bool
	if err := testPool.QueryRow(ctx, `
		SELECT enabled
		FROM feature_flag
		WHERE key = 'sandbox_snapshots_v1'
	`).Scan(&globalEnabled); err != nil {
		t.Fatalf("read global saved-snapshot feature flag: %v", err)
	}
	if globalEnabled {
		t.Error("global saved-snapshot feature flag is enabled during expand")
	}

	var enabledTeamOverrides int
	if err := testPool.QueryRow(ctx, `
		SELECT count(*)
		FROM team_feature_flag
		WHERE key = 'sandbox_snapshots_v1'
		  AND enabled
	`).Scan(&enabledTeamOverrides); err != nil {
		t.Fatalf("count enabled team saved-snapshot overrides: %v", err)
	}
	if enabledTeamOverrides != 0 {
		t.Errorf("enabled saved-snapshot team overrides = %d, want 0", enabledTeamOverrides)
	}

	rows, err := testPool.Query(ctx, `
		SELECT c.relname, c.relrowsecurity
		FROM pg_class c
		JOIN pg_namespace ns ON ns.oid = c.relnamespace
		WHERE ns.nspname = 'public'
		  AND c.relname = ANY (
		      ARRAY['snapshot_storage_layer', 'snapshot_storage_reference']
		  )
		ORDER BY c.relname
	`)
	if err != nil {
		t.Fatalf("inspect saved-snapshot ledger RLS: %v", err)
	}
	defer rows.Close()

	seen := 0
	for rows.Next() {
		var table string
		var enabled bool
		if err := rows.Scan(&table, &enabled); err != nil {
			t.Fatalf("scan saved-snapshot ledger RLS: %v", err)
		}
		seen++
		if !enabled {
			t.Errorf("RLS is disabled on %s", table)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate saved-snapshot ledger RLS: %v", err)
	}
	if seen != 2 {
		t.Errorf("found %d saved-snapshot ledger tables, want 2", seen)
	}
}

func TestSavedSnapshotExpandTracksLegacySecretHistory(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	router := newRouter(t)

	response := do(router, http.MethodPost, "/sandboxes", apiKey, `{"name":"legacy-secret-history"}`)
	if response.Code != http.StatusCreated {
		t.Fatalf("create sandbox: %d %s", response.Code, response.Body.String())
	}
	sandboxID := mustJSON(t, response)["id"].(string)

	var secretID uuid.UUID
	if err := testPool.QueryRow(ctx, `
		INSERT INTO secret (
		    team_id, name, auth_type, hosts, ciphertext, encrypted_dek, kek_id
		)
		VALUES ($1, $2, 'bearer', ARRAY['example.com'], '\x01', '\x02', 'test-kek')
		RETURNING id
	`, teamID, "legacy-secret-"+uuid.NewString()[:8]).Scan(&secretID); err != nil {
		t.Fatalf("create secret: %v", err)
	}

	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox_secret (sandbox_id, secret_id, env_key)
		VALUES ($1, $2, 'LEGACY_TOKEN')
	`, sandboxID, secretID); err != nil {
		t.Fatalf("legacy attach secret: %v", err)
	}
	assertSandboxSecretHistory(t, ctx, sandboxID, []string{"LEGACY_TOKEN"})

	if _, err := testPool.Exec(ctx, `
		DELETE FROM sandbox_secret
		WHERE sandbox_id = $1 AND env_key = 'LEGACY_TOKEN'
	`, sandboxID); err != nil {
		t.Fatalf("legacy detach secret: %v", err)
	}
	assertSandboxSecretHistory(t, ctx, sandboxID, []string{"LEGACY_TOKEN"})
}

func TestSavedSnapshotSecretBackfillPreservesConcurrentTriggerWrite(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	router := newRouter(t)

	response := do(router, http.MethodPost, "/sandboxes", apiKey, `{"name":"concurrent-secret-backfill"}`)
	if response.Code != http.StatusCreated {
		t.Fatalf("create sandbox: %d %s", response.Code, response.Body.String())
	}
	sandboxID := mustJSON(t, response)["id"].(string)

	insertSecret := func(name string) uuid.UUID {
		t.Helper()
		var secretID uuid.UUID
		if err := testPool.QueryRow(ctx, `
			INSERT INTO secret (
			    team_id, name, auth_type, hosts, ciphertext, encrypted_dek, kek_id
			)
			VALUES ($1, $2, 'bearer', ARRAY['example.com'], '\x01', '\x02', 'test-kek')
			RETURNING id
		`, teamID, name+"-"+uuid.NewString()[:8]).Scan(&secretID); err != nil {
			t.Fatalf("create %s secret: %v", name, err)
		}
		return secretID
	}

	initialSecretID := insertSecret("initial")
	concurrentSecretID := insertSecret("concurrent")
	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox_secret (sandbox_id, secret_id, env_key)
		VALUES ($1, $2, 'INITIAL_TOKEN')
	`, sandboxID, initialSecretID); err != nil {
		t.Fatalf("attach initial secret: %v", err)
	}
	// Model the expand window after the sandbox column exists but before the
	// active-binding backfill has populated it.
	if _, err := testPool.Exec(ctx, `
		UPDATE sandbox
		SET secret_env_keys = '[]'::jsonb
		WHERE id = $1
	`, sandboxID); err != nil {
		t.Fatalf("clear pre-backfill secret history: %v", err)
	}

	triggerTx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin concurrent trigger transaction: %v", err)
	}
	defer triggerTx.Rollback(ctx)
	if _, err := triggerTx.Exec(ctx, `
		INSERT INTO sandbox_secret (sandbox_id, secret_id, env_key)
		VALUES ($1, $2, 'CONCURRENT_TOKEN')
	`, sandboxID, concurrentSecretID); err != nil {
		t.Fatalf("attach concurrent secret: %v", err)
	}

	backfillConn, err := testPool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire backfill connection: %v", err)
	}
	defer backfillConn.Release()

	var backfillPID int32
	if err := backfillConn.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&backfillPID); err != nil {
		t.Fatalf("read backfill backend pid: %v", err)
	}

	backfillDone := make(chan error, 1)
	go func() {
		_, execErr := backfillConn.Exec(ctx, `
			UPDATE sandbox s
			SET secret_env_keys = (
			        SELECT COALESCE(
			            jsonb_agg(history.env_key ORDER BY history.env_key),
			            '[]'::jsonb
			        )
			        FROM (
			            SELECT jsonb_array_elements_text(s.secret_env_keys) AS env_key
			            UNION
			            SELECT jsonb_array_elements_text(merged.keys) AS env_key
			        ) history
			    ),
			    updated_at = now()
			FROM (
			    SELECT source.sandbox_id,
			           jsonb_agg(source.env_key ORDER BY source.env_key) AS keys
			    FROM (
			        SELECT existing.id AS sandbox_id,
			               jsonb_array_elements_text(existing.secret_env_keys) AS env_key
			        FROM sandbox existing
			        UNION
			        SELECT binding.sandbox_id, binding.env_key
			        FROM sandbox_secret binding
			    ) source
			    GROUP BY source.sandbox_id
			) merged
			WHERE s.id = merged.sandbox_id
			  AND s.secret_env_keys IS DISTINCT FROM merged.keys
		`)
		backfillDone <- execErr
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting bool
		if err := testPool.QueryRow(ctx, `
			SELECT COALESCE(
			    (SELECT wait_event_type = 'Lock'
			     FROM pg_stat_activity
			     WHERE pid = $1),
			    false
			)
		`, backfillPID).Scan(&waiting); err != nil {
			t.Fatalf("inspect blocked backfill: %v", err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("backfill did not block behind the concurrent trigger writer")
		}
		time.Sleep(10 * time.Millisecond)
	}

	if err := triggerTx.Commit(ctx); err != nil {
		t.Fatalf("commit concurrent trigger transaction: %v", err)
	}

	select {
	case err := <-backfillDone:
		if err != nil {
			t.Fatalf("run concurrent secret-history backfill: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("backfill did not finish after the concurrent trigger committed")
	}

	assertSandboxSecretHistory(
		t,
		ctx,
		sandboxID,
		[]string{"CONCURRENT_TOKEN", "INITIAL_TOKEN"},
	)
}

func assertSandboxSecretHistory(t *testing.T, ctx context.Context, sandboxID string, want []string) {
	t.Helper()

	var raw []byte
	if err := testPool.QueryRow(ctx, `
		SELECT secret_env_keys
		FROM sandbox
		WHERE id = $1
	`, sandboxID).Scan(&raw); err != nil {
		t.Fatalf("read sandbox secret history: %v", err)
	}
	var got []string
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode sandbox secret history: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("sandbox secret history = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sandbox secret history = %v, want %v", got, want)
		}
	}
}

func TestSavedSnapshotExpandLedgerRLSBlocksUnprivilegedReads(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	router := newRouter(t)

	response := do(router, http.MethodPost, "/sandboxes", apiKey, `{"name":"ledger-rls"}`)
	if response.Code != http.StatusCreated {
		t.Fatalf("create sandbox: %d %s", response.Code, response.Body.String())
	}
	sandboxID := mustJSON(t, response)["id"].(string)

	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin RLS test transaction: %v", err)
	}
	defer tx.Rollback(ctx)

	var layerID int64
	if err := tx.QueryRow(ctx, `
		INSERT INTO snapshot_storage_layer (
		    team_id, kind, owner_sandbox_id
		)
		VALUES ($1, 'sandbox_writable', $2)
		RETURNING id
	`, teamID, sandboxID).Scan(&layerID); err != nil {
		t.Fatalf("seed ledger layer: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO snapshot_storage_reference (
		    layer_id, team_id, sandbox_id
		)
		VALUES ($1, $2, $3)
	`, layerID, teamID, sandboxID); err != nil {
		t.Fatalf("seed ledger reference: %v", err)
	}

	role := "snapshot_rls_" + uuid.NewString()
	quotedRole := pgx.Identifier{role}.Sanitize()
	if _, err := tx.Exec(ctx, "CREATE ROLE "+quotedRole+" NOLOGIN"); err != nil {
		t.Fatalf("create restricted role: %v", err)
	}
	if _, err := tx.Exec(ctx, "GRANT USAGE ON SCHEMA public TO "+quotedRole); err != nil {
		t.Fatalf("grant schema usage: %v", err)
	}
	if _, err := tx.Exec(ctx,
		"GRANT SELECT ON snapshot_storage_layer, snapshot_storage_reference TO "+quotedRole,
	); err != nil {
		t.Fatalf("grant ledger select: %v", err)
	}
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+quotedRole); err != nil {
		t.Fatalf("assume restricted role: %v", err)
	}

	for _, table := range []string{
		"snapshot_storage_layer",
		"snapshot_storage_reference",
	} {
		var visible int
		query := "SELECT count(*) FROM " + pgx.Identifier{table}.Sanitize()
		if err := tx.QueryRow(ctx, query).Scan(&visible); err != nil {
			t.Fatalf("restricted select from %s: %v", table, err)
		}
		if visible != 0 {
			t.Errorf("restricted role can see %d rows in %s, want 0", visible, table)
		}
	}
}

func TestSavedSnapshotExpandDoesNotResurrectDeletedSnapshots(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	router := newRouter(t)

	response := do(router, http.MethodPost, "/sandboxes", apiKey, `{"name":"snapshot-delete-guard"}`)
	if response.Code != http.StatusCreated {
		t.Fatalf("create sandbox: %d %s", response.Code, response.Body.String())
	}
	sandboxID := mustJSON(t, response)["id"].(string)

	if _, err := testPool.Exec(ctx, `
		UPDATE team
		SET snapshot_storage_quota_bytes = 1048576
		WHERE id = $1
	`, teamID); err != nil {
		t.Fatalf("provision snapshot storage quota: %v", err)
	}

	var snapshotID uuid.UUID
	if err := testPool.QueryRow(ctx, `
		INSERT INTO snapshot (
		    sandbox_id, team_id, path, trigger, kind, status, name,
		    source_status, host_id, vcpu_count, memory_mib, disk_mib
		)
		VALUES (
		    $1, $2, '/pending', 'manual', 'saved', 'creating', 'delete-guard',
		    'active', $3, 1, 1024, 4096
		)
		RETURNING id
	`, sandboxID, teamID, testDefaultHostID).Scan(&snapshotID); err != nil {
		t.Fatalf("create saved snapshot row: %v", err)
	}

	if _, err := testPool.Exec(ctx, `
		UPDATE snapshot
		SET status = 'ready',
		    path = '/snapshots/delete-guard/vmstate.snap',
		    mem_path = '/snapshots/delete-guard/mem.snap',
		    manifest_path = '/snapshots/delete-guard/manifest.json',
		    manifest_digest = repeat('a', 64),
		    logical_size_bytes = 1024,
		    exclusive_size_bytes = 1024,
		    finalized_at = now()
		WHERE id = $1
	`, snapshotID); err != nil {
		t.Fatalf("finalize saved snapshot row: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		UPDATE snapshot
		SET status = 'deleting', deleted_at = now()
		WHERE id = $1
	`, snapshotID); err != nil {
		t.Fatalf("logically delete saved snapshot row: %v", err)
	}

	if _, err := testPool.Exec(ctx, `
		UPDATE snapshot
		SET deleted_at = NULL
		WHERE id = $1
	`, snapshotID); err == nil {
		t.Fatal("resurrecting a logically deleted saved snapshot succeeded")
	}

	var stillDeleted bool
	if err := testPool.QueryRow(ctx, `
		SELECT deleted_at IS NOT NULL
		FROM snapshot
		WHERE id = $1
	`, snapshotID).Scan(&stillDeleted); err != nil {
		t.Fatalf("read deleted snapshot state: %v", err)
	}
	if !stillDeleted {
		t.Fatal("failed resurrection attempt cleared deleted_at")
	}
}
