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
