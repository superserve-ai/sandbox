//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestSavedSnapshotContractRolloutGuards(t *testing.T) {
	ctx := context.Background()

	expectedIndexes := []struct {
		name       string
		table      string
		unique     bool
		keys       []string
		predicate  string
		definition string
	}{
		{
			name:       "snapshot_sandbox_runtime_unique",
			table:      "snapshot",
			unique:     true,
			keys:       []string{"sandbox_id"},
			predicate:  "(kind = 'runtime_checkpoint'::snapshot_kind)",
			definition: "CREATE UNIQUE INDEX snapshot_sandbox_runtime_unique ON public.snapshot USING btree (sandbox_id) WHERE (kind = 'runtime_checkpoint'::snapshot_kind)",
		},
		{
			name:       "snapshot_team_source_idempotency_unique",
			table:      "snapshot",
			unique:     true,
			keys:       []string{"team_id", "sandbox_id", "idempotency_key"},
			predicate:  "((kind = 'saved'::snapshot_kind) AND (idempotency_key IS NOT NULL))",
			definition: "CREATE UNIQUE INDEX snapshot_team_source_idempotency_unique ON public.snapshot USING btree (team_id, sandbox_id, idempotency_key) WHERE ((kind = 'saved'::snapshot_kind) AND (idempotency_key IS NOT NULL))",
		},
		{
			name:       "idx_snapshot_team_saved_created",
			table:      "snapshot",
			keys:       []string{"team_id", "created_at", "id"},
			predicate:  "((kind = 'saved'::snapshot_kind) AND (deleted_at IS NULL))",
			definition: "CREATE INDEX idx_snapshot_team_saved_created ON public.snapshot USING btree (team_id, created_at DESC, id DESC) WHERE ((kind = 'saved'::snapshot_kind) AND (deleted_at IS NULL))",
		},
		{
			name:       "idx_snapshot_source_saved_created",
			table:      "snapshot",
			keys:       []string{"sandbox_id", "created_at", "id"},
			predicate:  "((kind = 'saved'::snapshot_kind) AND (deleted_at IS NULL))",
			definition: "CREATE INDEX idx_snapshot_source_saved_created ON public.snapshot USING btree (sandbox_id, created_at DESC, id DESC) WHERE ((kind = 'saved'::snapshot_kind) AND (deleted_at IS NULL))",
		},
		{
			name:       "idx_snapshot_parent_saved",
			table:      "snapshot",
			keys:       []string{"parent_snapshot_id"},
			predicate:  "((kind = 'saved'::snapshot_kind) AND (deleted_at IS NULL))",
			definition: "CREATE INDEX idx_snapshot_parent_saved ON public.snapshot USING btree (parent_snapshot_id) WHERE ((kind = 'saved'::snapshot_kind) AND (deleted_at IS NULL))",
		},
		{
			name:       "idx_snapshot_saved_host",
			table:      "snapshot",
			keys:       []string{"host_id", "status"},
			predicate:  "((kind = 'saved'::snapshot_kind) AND (deleted_at IS NULL))",
			definition: "CREATE INDEX idx_snapshot_saved_host ON public.snapshot USING btree (host_id, status) WHERE ((kind = 'saved'::snapshot_kind) AND (deleted_at IS NULL))",
		},
		{
			name:      "idx_snapshot_saved_reconcile",
			table:     "snapshot",
			keys:      []string{"status", "updated_at", "id"},
			predicate: "((kind = 'saved'::snapshot_kind) AND (deleted_at IS NULL) AND (status = ANY (ARRAY['creating'::snapshot_status, 'deleting'::snapshot_status])))",
			definition: "CREATE INDEX idx_snapshot_saved_reconcile ON public.snapshot USING btree (status, updated_at, id) " +
				"WHERE ((kind = 'saved'::snapshot_kind) AND (deleted_at IS NULL) AND (status = ANY (ARRAY['creating'::snapshot_status, 'deleting'::snapshot_status])))",
		},
		{
			name:       "idx_sandbox_source_snapshot_pin",
			table:      "sandbox",
			keys:       []string{"source_snapshot_id"},
			predicate:  "(source_snapshot_id IS NOT NULL)",
			definition: "CREATE INDEX idx_sandbox_source_snapshot_pin ON public.sandbox USING btree (source_snapshot_id) WHERE (source_snapshot_id IS NOT NULL)",
		},
		{
			name:       "idx_sandbox_destroyed_snapshot_pin",
			table:      "sandbox",
			keys:       []string{"destroyed_at", "id"},
			predicate:  "((source_snapshot_id IS NOT NULL) AND (destroyed_at IS NOT NULL))",
			definition: "CREATE INDEX idx_sandbox_destroyed_snapshot_pin ON public.sandbox USING btree (destroyed_at, id) WHERE ((source_snapshot_id IS NOT NULL) AND (destroyed_at IS NOT NULL))",
		},
		{
			name:       "idx_sandbox_snapshot_operation",
			table:      "sandbox",
			keys:       []string{"snapshot_operation_started_at"},
			predicate:  "((snapshot_operation_id IS NOT NULL) AND (destroyed_at IS NULL))",
			definition: "CREATE INDEX idx_sandbox_snapshot_operation ON public.sandbox USING btree (snapshot_operation_started_at) WHERE ((snapshot_operation_id IS NOT NULL) AND (destroyed_at IS NULL))",
		},
	}

	for _, expected := range expectedIndexes {
		var (
			table, accessMethod, predicate, definition string
			unique, valid, ready, live, immediate      bool
			keyCount, attributeCount                   int16
			keys                                       []string
			hasExpressions                             bool
		)
		err := testPool.QueryRow(ctx, `
			SELECT indexed_table.relname,
			       access_method.amname,
			       catalog.indisunique,
			       catalog.indisvalid,
			       catalog.indisready,
			       catalog.indislive,
			       catalog.indimmediate,
			       catalog.indnkeyatts,
			       catalog.indnatts,
			       ARRAY(
			           SELECT pg_get_indexdef(
			                      catalog.indexrelid,
			                      key_position,
			                      true
			                  )
			           FROM generate_series(
			                    1,
			                    catalog.indnkeyatts
			                ) AS key_position
			           ORDER BY key_position
			       ),
			       pg_get_expr(catalog.indpred, catalog.indrelid, false),
			       pg_get_indexdef(catalog.indexrelid),
			       catalog.indexprs IS NOT NULL
			FROM pg_index catalog
			JOIN pg_class index_object
			  ON index_object.oid = catalog.indexrelid
			JOIN pg_namespace index_namespace
			  ON index_namespace.oid = index_object.relnamespace
			JOIN pg_class indexed_table
			  ON indexed_table.oid = catalog.indrelid
			JOIN pg_namespace table_namespace
			  ON table_namespace.oid = indexed_table.relnamespace
			JOIN pg_am access_method
			  ON access_method.oid = index_object.relam
			WHERE index_namespace.nspname = 'public'
			  AND table_namespace.nspname = 'public'
			  AND index_object.relkind = 'i'
			  AND index_object.relname = $1
		`, expected.name).Scan(
			&table,
			&accessMethod,
			&unique,
			&valid,
			&ready,
			&live,
			&immediate,
			&keyCount,
			&attributeCount,
			&keys,
			&predicate,
			&definition,
			&hasExpressions,
		)
		if err != nil {
			t.Fatalf("inspect %s: %v", expected.name, err)
		}
		if table != expected.table ||
			accessMethod != "btree" ||
			unique != expected.unique ||
			!valid ||
			!ready ||
			!live ||
			!immediate ||
			int(keyCount) != len(expected.keys) ||
			attributeCount != keyCount ||
			!slices.Equal(keys, expected.keys) ||
			predicate != expected.predicate ||
			definition != expected.definition ||
			hasExpressions {
			t.Errorf(
				"%s catalog contract mismatch: table=%q access=%q unique=%v valid=%v ready=%v live=%v immediate=%v keys=%v predicate=%q definition=%q expressions=%v",
				expected.name,
				table,
				accessMethod,
				unique,
				valid,
				ready,
				live,
				immediate,
				keys,
				predicate,
				definition,
				hasExpressions,
			)
		}
	}

	var legacyIndexExists bool
	if err := testPool.QueryRow(ctx, `
		SELECT to_regclass('public.snapshot_sandbox_unique') IS NOT NULL
	`).Scan(&legacyIndexExists); err != nil {
		t.Fatalf("inspect legacy snapshot_sandbox_unique: %v", err)
	}
	if legacyIndexExists {
		t.Error("legacy snapshot_sandbox_unique still exists after contract")
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
