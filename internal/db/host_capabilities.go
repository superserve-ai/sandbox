package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// LockedHostHasCapabilities serializes with heartbeat writers before taking
// the capability snapshot. Existing transactions must be READ COMMITTED and
// retain the host lock until their caller commits or rolls back. Pool/connection
// callers get a short READ COMMITTED transaction that ends before return.
func (q *Queries) LockedHostHasCapabilities(ctx context.Context, arg HostHasCapabilitiesParams) (bool, error) {
	if _, ok := q.db.(pgx.Tx); ok {
		return q.lockedHostHasCapabilities(ctx, arg)
	}
	beginner, ok := q.db.(interface {
		BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
	})
	if !ok {
		return false, fmt.Errorf("locked host capability validation requires a transaction or transaction-capable connection")
	}
	tx, err := beginner.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return false, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	capable, err := q.WithTx(tx).lockedHostHasCapabilities(ctx, arg)
	if err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return capable, nil
}

// LockedResumePostBootCheck is ResumePostBootCheck evaluated after
// LockHostForCapabilities in one short READ COMMITTED transaction, so the
// capability snapshot follows any heartbeat update already in flight.
func (q *Queries) LockedResumePostBootCheck(ctx context.Context, arg ResumePostBootCheckParams) (ResumePostBootCheckRow, error) {
	beginner, ok := q.db.(interface {
		BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
	})
	if !ok {
		return ResumePostBootCheckRow{}, fmt.Errorf("locked resume check requires a transaction-capable connection")
	}
	tx, err := beginner.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return ResumePostBootCheckRow{}, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	locked := q.WithTx(tx)
	if _, err := locked.LockHostForCapabilities(ctx, arg.HostID); err != nil {
		return ResumePostBootCheckRow{}, err
	}
	row, err := locked.ResumePostBootCheck(ctx, arg)
	if err != nil {
		return ResumePostBootCheckRow{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ResumePostBootCheckRow{}, err
	}
	return row, nil
}

func (q *Queries) lockedHostHasCapabilities(ctx context.Context, arg HostHasCapabilitiesParams) (bool, error) {
	locked, err := q.LockHostForCapabilities(ctx, arg.HostID)
	if err != nil {
		return false, err
	}
	if locked == 0 {
		return false, nil
	}
	return q.HostHasCapabilities(ctx, arg)
}
