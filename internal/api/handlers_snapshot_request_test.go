package api

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/superserve-ai/sandbox/internal/db"
)

func TestCreateSnapshotRequestRejectsExplicitNull(t *testing.T) {
	for _, body := range []string{`null`, `{"name":null}`} {
		var req createSnapshotRequest
		if err := json.Unmarshal([]byte(body), &req); err == nil {
			t.Errorf("json.Unmarshal(%s) succeeded, want explicit null rejection", body)
		}
	}
}

func TestCreateSnapshotRequestAllowsOmittedOrStringName(t *testing.T) {
	for _, tc := range []struct {
		body string
		name *string
	}{
		{body: `{}`},
		{body: `{"name":"before-change"}`, name: stringPointer("before-change")},
	} {
		var req createSnapshotRequest
		if err := json.Unmarshal([]byte(tc.body), &req); err != nil {
			t.Fatalf("json.Unmarshal(%s): %v", tc.body, err)
		}
		switch {
		case tc.name == nil && req.Name != nil:
			t.Errorf("json.Unmarshal(%s) name = %q, want nil", tc.body, *req.Name)
		case tc.name != nil && (req.Name == nil || *req.Name != *tc.name):
			t.Errorf("json.Unmarshal(%s) name = %v, want %q", tc.body, req.Name, *tc.name)
		}
	}
}

func stringPointer(value string) *string { return &value }

func TestSavedSnapshotWorstCaseExclusiveBytes(t *testing.T) {
	const mib = int64(1 << 20)
	if got, want := savedSnapshotWorstCaseExclusiveBytes(2048, 8192), int64(10240)*mib+savedSnapshotMetadataReserve; got != want {
		t.Fatalf("worst-case bytes = %d, want %d", got, want)
	}
	if got := savedSnapshotWorstCaseExclusiveBytes(-1, 1); got != math.MaxInt64 {
		t.Fatalf("invalid shape estimate = %d, want MaxInt64", got)
	}
}

func TestBeginSavedSnapshotDirectPathFencesBeforeHostLocks(t *testing.T) {
	var query string
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			query = sql
			return notFoundRow()
		},
	}
	h := &Handlers{DB: db.New(mock)}
	_, err := h.beginSavedSnapshot(context.Background(), db.BeginSavedSnapshotParams{
		SnapshotID: uuid.New(),
		Trigger:    "api",
		TeamID:     uuid.New(),
		SandboxID:  uuid.New(),
	})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("direct BeginSavedSnapshot error = %v, want pgx.ErrNoRows", err)
	}

	globalFenceAt := strings.Index(query, "WITH global_migration_fence AS MATERIALIZED")
	teamFenceAt := strings.Index(query, "team_migration_fence AS MATERIALIZED")
	hostAt := strings.Index(query, "host_admitted AS MATERIALIZED")
	if globalFenceAt < 0 || teamFenceAt < 0 || hostAt < 0 ||
		globalFenceAt >= teamFenceAt || teamFenceAt >= hostAt {
		t.Fatalf("migration fences must be global -> team -> host in generated SQL:\n%s", query)
	}
	for _, required := range []string{
		"pg_try_advisory_xact_lock_shared",
		"'superserve:migrate-team:'",
		"'superserve:migrate-team:saved-snapshot-global'",
		"FROM global_migration_fence global_fence",
		"CROSS JOIN team_migration_fence fence",
		"AND fence.acquired",
	} {
		if !strings.Contains(query, required) {
			t.Errorf("generated BeginSavedSnapshot SQL is missing %q", required)
		}
	}
}
