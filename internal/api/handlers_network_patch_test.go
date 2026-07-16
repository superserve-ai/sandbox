package api

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/db"
)

type networkCall struct {
	allowed []string
	denied  []string
	domains []string
}

func TestApplyCapturedNetworkPatch_RollsBackLivePolicyWhenPersistenceFails(t *testing.T) {
	sandboxID, teamID := uuid.New(), uuid.New()
	sandbox := db.Sandbox{
		ID:            sandboxID,
		TeamID:        teamID,
		Status:        db.SandboxStatusActive,
		NetworkConfig: []byte(`{"egress":{"allowed_cidrs":["192.0.2.0/24"],"denied_cidrs":["192.0.2.128/25"],"allowed_domains":["old.example"]}}`),
	}
	dbErr := errors.New("database write failed")
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return sandboxRow(sandbox) },
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, dbErr
		},
	}
	var calls []networkCall
	vmd := &stubVMD{updateNetworkFn: func(_ context.Context, _ string, allowed, denied, domains []string) error {
		calls = append(calls, networkCall{
			allowed: append([]string(nil), allowed...),
			denied:  append([]string(nil), denied...),
			domains: append([]string(nil), domains...),
		})
		return nil
	}}
	h := &Handlers{DB: db.New(mock), VMD: vmd}

	_, err := h.applyCapturedNetworkPatch(
		context.Background(), vmd, sandboxID, teamID,
		[]string{"10.0.0.0/8"}, nil, []string{"new.example"},
		[]byte(`{"egress":{"allowed_cidrs":["10.0.0.0/8"],"allowed_domains":["new.example"]}}`),
	)
	if !errors.Is(err, dbErr) {
		t.Fatalf("error = %v, want wrapped DB failure", err)
	}
	want := []networkCall{
		{allowed: []string{"10.0.0.0/8"}, domains: []string{"new.example"}},
		{allowed: []string{"192.0.2.0/24"}, denied: []string{"192.0.2.128/25"}, domains: []string{"old.example"}},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("VMD network calls = %#v, want apply then rollback %#v", calls, want)
	}
}

func TestApplyCapturedNetworkPatch_RejectsCaptureClaimAfterLock(t *testing.T) {
	sandboxID, teamID := uuid.New(), uuid.New()
	sandbox := db.Sandbox{
		ID:                  sandboxID,
		TeamID:              teamID,
		Status:              db.SandboxStatusActive,
		SnapshotOperationID: pgtype.UUID{Bytes: uuid.New(), Valid: true},
	}
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return sandboxRow(sandbox) },
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			t.Fatal("network config must not be persisted during capture")
			return pgconn.CommandTag{}, nil
		},
	}
	var vmdCalled bool
	vmd := &stubVMD{updateNetworkFn: func(context.Context, string, []string, []string, []string) error {
		vmdCalled = true
		return nil
	}}
	h := &Handlers{DB: db.New(mock), VMD: vmd}

	_, err := h.applyCapturedNetworkPatch(context.Background(), vmd, sandboxID, teamID, nil, nil, nil, []byte(`{"egress":{}}`))
	if !errors.Is(err, errSandboxSnapshotInFlight) {
		t.Fatalf("error = %v, want snapshot-operation conflict", err)
	}
	if vmdCalled {
		t.Fatal("live network policy changed during snapshot capture")
	}
}
