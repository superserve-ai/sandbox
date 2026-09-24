package billing

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const StorageReportSettlementTimeout = 30 * time.Second

var ErrStorageSettlementBoundaryOpen = errors.New("billing period is still open in the settlement transaction")

// FenceStorageReportReceipts must run before aggregation in a READ COMMITTED
// transaction. Ingestion holds the same host locks from before receipt-time
// allocation through commit, including legacy staging and promotion. A fresh
// statement after this fence sees every earlier receipt; keep the locks until
// the usage snapshot is committed or frozen. No remote calls belong in that
// transaction.
func FenceStorageReportReceipts(ctx context.Context, tx pgx.Tx, teamID uuid.UUID) error {
	rows, err := tx.Query(ctx, `
		SELECT DISTINCT host_id
		FROM sandbox
		WHERE team_id=$1 AND host_id IS NOT NULL
		ORDER BY host_id`, teamID)
	if err != nil {
		return fmt.Errorf("list storage receipt hosts: %w", err)
	}
	hostIDs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return fmt.Errorf("read storage receipt hosts: %w", err)
	}
	for _, hostID := range hostIDs {
		var acquired bool
		if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1::text, 0))`, hostID).Scan(&acquired); err != nil {
			return fmt.Errorf("fence storage receipts: %w", err)
		}
		if !acquired {
			// Roll back the caller's transaction to release any earlier locks.
			// Waiting here would couple settlement to a stalled ingestion or
			// invert another settlement's billing-row/host lock order.
			return ErrStorageReportsIncomplete
		}
	}
	return nil
}

// CheckStorageSettlementBoundary uses the same transaction clock as usage
// aggregation. Later receipts must fall outside an irreversibly closed window.
func CheckStorageSettlementBoundary(ctx context.Context, tx pgx.Tx, boundary time.Time) error {
	var closed bool
	if err := tx.QueryRow(ctx, `SELECT $1::timestamptz <= transaction_timestamp()`, boundary).Scan(&closed); err != nil {
		return fmt.Errorf("check storage settlement boundary: %w", err)
	}
	if !closed {
		return ErrStorageSettlementBoundaryOpen
	}
	return nil
}
