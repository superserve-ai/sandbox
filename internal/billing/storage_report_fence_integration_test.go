//go:build integration

package billing

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func storageFenceTestConnection(t *testing.T) *pgx.Conn {
	t.Helper()
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL is required for storage receipt fence integration tests")
	}
	conn, err := pgx.Connect(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

func TestIntegration_StorageReceiptFenceScopesAndReleasesLocks(t *testing.T) {
	ctx := t.Context()
	conn := storageFenceTestConnection(t)
	blocker := storageFenceTestConnection(t)
	probe := storageFenceTestConnection(t)
	teamID, unrelatedTeamID := uuid.New(), uuid.New()
	prefix := uuid.NewString()
	firstHost, busyHost, unrelatedHost := prefix+"-a", prefix+"-b", prefix+"-c"
	if _, err := conn.Exec(ctx, `CREATE TEMP TABLE sandbox(team_id uuid, host_id text);
		CREATE INDEX ON sandbox(team_id,host_id)`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `INSERT INTO sandbox VALUES ($1,$3),($1,$4),($1,$4),($2,$5)`,
		teamID, unrelatedTeamID, firstHost, busyHost, unrelatedHost); err != nil {
		t.Fatal(err)
	}
	blocked, err := blocker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Rollback(context.Background())
	if _, err := blocked.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text,0))`, busyHost); err != nil {
		t.Fatal(err)
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	fenceCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err := FenceStorageReportReceipts(fenceCtx, tx, teamID); !errors.Is(err, ErrStorageReportsIncomplete) {
		t.Fatalf("fence with busy receipt = %v, want incomplete without waiting", err)
	}
	var available bool
	if err := probe.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1::text,0))`, firstHost).Scan(&available); err != nil {
		t.Fatal(err)
	}
	if available {
		t.Fatal("partial fence was released before caller rollback")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := probe.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1::text,0))`, firstHost).Scan(&available); err != nil {
		t.Fatal(err)
	}
	if !available {
		t.Fatal("rollback retained a partial receipt fence")
	}
	tx, err = conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if err := FenceStorageReportReceipts(ctx, tx, unrelatedTeamID); err != nil {
		t.Fatalf("unrelated team's fence = %v", err)
	}
	if err := blocked.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := FenceStorageReportReceipts(ctx, tx, teamID); err != nil {
		t.Fatalf("retry after receipt commits = %v", err)
	}
	if err := probe.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1::text,0))`, busyHost).Scan(&available); err != nil {
		t.Fatal(err)
	}
	if available {
		t.Fatal("successful fence did not exclude new receipts until commit")
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := probe.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1::text,0))`, busyHost).Scan(&available); err != nil {
		t.Fatal(err)
	}
	if !available {
		t.Fatal("commit retained the receipt fence")
	}
}

func TestIntegration_StorageSettlementUsesTransactionBoundary(t *testing.T) {
	ctx := t.Context()
	conn := storageFenceTestConnection(t)
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	var boundary time.Time
	if err := tx.QueryRow(ctx, `SELECT transaction_timestamp()+interval '50 milliseconds'`).Scan(&boundary); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_sleep(0.06)`); err != nil {
		t.Fatal(err)
	}
	if err := CheckStorageSettlementBoundary(ctx, tx, boundary); !errors.Is(err, ErrStorageSettlementBoundaryOpen) {
		t.Fatalf("transaction started before boundary = %v, want open even after wall clock passes it", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	tx, err = conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if err := CheckStorageSettlementBoundary(ctx, tx, boundary); err != nil {
		t.Fatalf("fresh transaction after boundary = %v", err)
	}
}
