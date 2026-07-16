package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type savedSnapshotStateQuerier struct {
	state savedSnapshotMigrationState
	err   error
	query string
	arg   any
}

func (q *savedSnapshotStateQuerier) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	q.query = sql
	if len(args) == 1 {
		q.arg = args[0]
	}
	return savedSnapshotStateRow{state: q.state, err: q.err}
}

type savedSnapshotStateRow struct {
	state savedSnapshotMigrationState
	err   error
}

func (r savedSnapshotStateRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	values := []int64{
		r.state.snapshotRows,
		r.state.forkedSandboxes,
		r.state.captureOperations,
		r.state.templateDependents,
		r.state.storageBytes,
	}
	for i, value := range values {
		*(dest[i].(*int64)) = value
	}
	return nil
}

func TestRejectSavedSnapshotMigration(t *testing.T) {
	teamID := uuid.New()
	tests := []struct {
		name    string
		phase   string
		state   savedSnapshotMigrationState
		wantErr []string
	}{
		{name: "empty state passes", phase: phasePlan},
		{
			name:  "plan rejects deleted snapshot history",
			phase: phasePlan,
			state: savedSnapshotMigrationState{snapshotRows: 1},
			wantErr: []string{
				"refusing plan",
				"saved snapshot rows=1 (including deleted history)",
			},
		},
		{
			name:  "copy rejects fork lineage and storage accounting",
			phase: phaseCopy,
			state: savedSnapshotMigrationState{forkedSandboxes: 2, storageBytes: 4096},
			wantErr: []string{
				"refusing copy",
				"sandboxes forked from saved snapshots=2",
				"snapshot storage bytes=4096",
			},
		},
		{
			name:  "purge rejects captures and template dependencies",
			phase: phasePurge,
			state: savedSnapshotMigrationState{captureOperations: 1, templateDependents: 3},
			wantErr: []string{
				"refusing purge",
				"snapshot capture operations=1",
				"other teams' saved snapshots pinning this team's templates=3",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := &savedSnapshotStateQuerier{state: tt.state}
			err := rejectSavedSnapshotMigration(context.Background(), q, teamID, tt.phase)
			if len(tt.wantErr) == 0 {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Fatal("expected saved-snapshot state to block migration")
				}
				for _, want := range tt.wantErr {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error %q does not contain %q", err, want)
					}
				}
			}

			if q.arg != teamID {
				t.Errorf("query team argument = %v, want %v", q.arg, teamID)
			}
			// There must be no deleted_at predicate: soft-deleted rows still
			// carry FKs and must keep blocking this V1 tool.
			if strings.Contains(q.query, "deleted_at") {
				t.Errorf("snapshot guard unexpectedly excludes deleted history: %s", q.query)
			}
			for _, column := range []string{"source_snapshot_id", "snapshot_operation_id", "snapshot_storage_bytes"} {
				if !strings.Contains(q.query, column) {
					t.Errorf("snapshot guard query does not inspect %s", column)
				}
			}
		})
	}
}

func TestRejectSavedSnapshotMigrationQueryError(t *testing.T) {
	want := errors.New("database unavailable")
	q := &savedSnapshotStateQuerier{err: want}
	err := rejectSavedSnapshotMigration(context.Background(), q, uuid.New(), phaseCopy)
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want wrapped %v", err, want)
	}
}
