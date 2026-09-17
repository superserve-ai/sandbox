package db

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type capabilityTestTx struct {
	pgx.Tx
	steps   []string
	fail    string
	capable bool
}

func (tx *capabilityTestTx) step(s string) error {
	tx.steps = append(tx.steps, s)
	if tx.fail == s {
		return errors.New(s)
	}
	return nil
}
func (tx *capabilityTestTx) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	if !strings.Contains(sql, "FOR SHARE") {
		return pgconn.CommandTag{}, errors.New("missing share lock")
	}
	return pgconn.NewCommandTag("SELECT 1"), tx.step("lock")
}
func (tx *capabilityTestTx) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	if strings.Contains(sql, "FOR SHARE") {
		return capabilityTestRow{err: errors.New("evaluation locks within its snapshot")}
	}
	return capabilityTestRow{capable: tx.capable, err: tx.step("read")}
}
func (tx *capabilityTestTx) Commit(context.Context) error   { return tx.step("commit") }
func (tx *capabilityTestTx) Rollback(context.Context) error { return tx.step("rollback") }

type capabilityTestRow struct {
	capable bool
	err     error
}

func (r capabilityTestRow) Scan(dest ...any) error { *dest[0].(*bool) = r.capable; return r.err }

type capabilityTestPool struct {
	DBTX
	tx *capabilityTestTx
}

func (p capabilityTestPool) BeginTx(_ context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
	if opts.IsoLevel != pgx.ReadCommitted {
		return nil, errors.New("wrong isolation")
	}
	return p.tx, p.tx.step("begin")
}

func TestLockedHostCapabilitiesTransactionLifetime(t *testing.T) {
	for _, tc := range []struct {
		name, fail string
		capable    bool
		steps      []string
	}{
		{"success", "", true, []string{"begin", "lock", "read", "commit", "rollback"}},
		{"withdrawn", "", false, []string{"begin", "lock", "read", "commit", "rollback"}},
		{"begin error", "begin", false, []string{"begin"}},
		{"lock error", "lock", false, []string{"begin", "lock", "rollback"}},
		{"read error", "read", false, []string{"begin", "lock", "read", "rollback"}},
		{"commit error", "commit", false, []string{"begin", "lock", "read", "commit", "rollback"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := &capabilityTestTx{fail: tc.fail, capable: tc.capable}
			ok, err := New(capabilityTestPool{tx: tx}).LockedHostHasCapabilities(context.Background(), HostHasCapabilitiesParams{HostID: "example-host"})
			if (err != nil) != (tc.fail != "") || ok != tc.capable {
				t.Fatalf("got %v, %v", ok, err)
			}
			if !reflect.DeepEqual(tx.steps, tc.steps) {
				t.Fatalf("steps=%v, want %v", tx.steps, tc.steps)
			}
		})
	}
}
func TestLockedHostCapabilitiesReusesMutationTransaction(t *testing.T) {
	tx := &capabilityTestTx{capable: true}
	ok, err := New(tx).LockedHostHasCapabilities(context.Background(), HostHasCapabilitiesParams{HostID: "example-host"})
	if err != nil || !ok {
		t.Fatalf("got %v, %v", ok, err)
	}
	if !reflect.DeepEqual(tx.steps, []string{"lock", "read"}) {
		t.Fatalf("transaction ownership changed: %v", tx.steps)
	}
}
func TestLockedHostCapabilitiesRejectsAutocommitOnlyDB(t *testing.T) {
	_, err := New(struct{ DBTX }{}).LockedHostHasCapabilities(context.Background(), HostHasCapabilitiesParams{})
	if err == nil {
		t.Fatal("autocommit-only DB accepted")
	}
}
