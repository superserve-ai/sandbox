//go:build integration

package integration

import (
	"context"
	"regexp"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// Historical fixtures may describe pins that preceded reference protection.
// Restrict trigger bypass to this transaction and recapture only its returned
// owners. Normal lifecycle writes must still reject identity replacement.
func seedLegacyStoragePins(t *testing.T, ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	t.Helper()
	if !regexp.MustCompile(`^\s*UPDATE sandbox\s+SET\b`).MatchString(query) {
		t.Fatal("legacy fixture requires an explicit sandbox update")
	}
	tx, err := testPool.Begin(ctx)
	if err != nil {
		return pgconn.CommandTag{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SET LOCAL session_replication_role=replica`); err != nil {
		return pgconn.CommandTag{}, err
	}
	rows, err := tx.Query(ctx, query+" RETURNING id", args...)
	if err != nil {
		return pgconn.CommandTag{}, err
	}
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return pgconn.CommandTag{}, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return pgconn.CommandTag{}, err
	}
	tag := rows.CommandTag()
	if _, err = tx.Exec(ctx, `UPDATE sandbox SET legacy_storage_refs=legacy_storage_reference(template_id,base_path,delta_path,NULL) WHERE id=ANY($1::uuid[])`, ids); err != nil {
		return tag, err
	}
	return tag, tx.Commit(ctx)
}

func seedLegacyStoragePinsExec(t *testing.T, query string, args ...any) {
	t.Helper()
	if _, err := seedLegacyStoragePins(t, t.Context(), query, args...); err != nil {
		t.Fatal(err)
	}
}
