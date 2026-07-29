package api

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/superserve-ai/sandbox/internal/db"
)

func TestRecordSandboxWritableLayerUsagePersistsMeasuredGeneration(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	var gotArgs []any
	dbtx := &mockDBTX{execFn: func(ctx context.Context, _ string, args ...any) (pgconn.CommandTag, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("shadow accounting DB write has no bounded deadline")
		}
		gotArgs = append([]any(nil), args...)
		return pgconn.NewCommandTag("UPDATE 1"), nil
	}}
	vmd := &stubSavedSnapshotVMD{
		stubVMD: &stubVMD{},
		measureSavedFn: func(ctx context.Context, instanceID string) (int64, int64, error) {
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("writable-layer measurement has no bounded deadline")
			}
			if instanceID != sandboxID.String() {
				t.Fatalf("measured sandbox = %s, want %s", instanceID, sandboxID)
			}
			return 8192, 4096, nil
		},
	}
	h := &Handlers{DB: db.New(dbtx)}

	h.recordSandboxWritableLayerUsage(context.Background(), vmd, sandboxID, teamID)

	if len(gotArgs) != 4 {
		t.Fatalf("storage update args = %v, want 4", gotArgs)
	}
	if gotArgs[0] != teamID {
		t.Fatalf("storage team arg = %#v, want %s", gotArgs[0], teamID)
	}
	if gotArgs[1] != sandboxID {
		t.Fatalf("storage sandbox arg = %#v, want %s", gotArgs[1], sandboxID)
	}
	if gotArgs[2] != int64(8192) || gotArgs[3] != int64(4096) {
		t.Fatalf("storage size args = %v, want logical=8192 exclusive=4096", gotArgs[2:])
	}
}

func TestRecordSandboxWritableLayerUsageRejectsNegativeMeasurement(t *testing.T) {
	dbtx := &mockDBTX{execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
		t.Fatal("negative measurement reached the storage ledger")
		return pgconn.CommandTag{}, nil
	}}
	vmd := &stubSavedSnapshotVMD{
		stubVMD: &stubVMD{},
		measureSavedFn: func(context.Context, string) (int64, int64, error) {
			return 1, -1, nil
		},
	}
	h := &Handlers{DB: db.New(dbtx)}

	h.recordSandboxWritableLayerUsage(context.Background(), vmd, uuid.New(), uuid.New())
}
