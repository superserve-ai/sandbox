//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/db"
)

func maintainLog(ctx context.Context, table string) error {
	return testQueries.MaintainLogPartitions(ctx, db.MaintainLogPartitionsParams{Parent: table, KeepDays: 7})
}

// Log tables are partitioned by day: maintenance creates the window and the
// days ahead, drops the days past it, and a row outside the window has
// nowhere to land.
func TestIntegration_LogRetentionMaintainsDayPartitions(t *testing.T) {
	ctx := context.Background()
	if _, err := testPool.Exec(ctx, `CREATE TABLE IF NOT EXISTS net_flow_20200101 PARTITION OF net_flow FOR VALUES FROM ('2020-01-01 00:00:00+00') TO ('2020-01-02 00:00:00+00')`); err != nil {
		t.Fatalf("stale partition: %v", err)
	}
	if err := maintainLog(ctx, "net_flow"); err != nil {
		t.Fatalf("maintain: %v", err)
	}
	var stale bool
	if err := testPool.QueryRow(ctx, `SELECT to_regclass('net_flow_20200101') IS NOT NULL`).Scan(&stale); err != nil || stale {
		t.Fatalf("stale partition still present = %v, err = %v", stale, err)
	}
	var days int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM pg_inherits WHERE inhparent = 'net_flow'::regclass`).Scan(&days); err != nil || days < 14 {
		t.Fatalf("net_flow partitions = %d, err = %v; want the 7-day window and 7 ahead", days, err)
	}
	if _, err := testPool.Exec(ctx, `INSERT INTO net_flow (ts, team_id, sandbox_id, protocol, dst_ip, dst_port, verdict) VALUES (now() - interval '7 days', $1, $2, 'tls', '192.0.2.1', 443, 'allowed')`, uuid.New(), uuid.New()); err == nil {
		t.Fatal("a row from the eighth day back found a partition")
	}
	if _, err := testPool.Exec(ctx, `INSERT INTO net_flow (team_id, sandbox_id, protocol, dst_ip, dst_port, verdict) VALUES ($1, $2, 'tls', '192.0.2.1', 443, 'allowed')`, uuid.New(), uuid.New()); err != nil {
		t.Fatalf("insert today: %v", err)
	}
	if _, err := testPool.Exec(ctx, `INSERT INTO net_flow (ts, team_id, sandbox_id, protocol, dst_ip, dst_port, verdict) VALUES (now() - interval '9 days', $1, $2, 'tls', '192.0.2.1', 443, 'allowed')`, uuid.New(), uuid.New()); err == nil {
		t.Fatal("a row past the window found a partition")
	}
}

// A pass with nothing to do takes no lock a reader could hold up, and a pass
// that must create a day gives up inside the writers' deadline instead of
// queueing behind the reader while holding the other table's locks.
func TestIntegration_LogRetentionDoesNotStallWritersBehindReaders(t *testing.T) {
	ctx := context.Background()
	for _, table := range []string{"net_flow", "proxy_audit"} {
		if err := maintainLog(ctx, table); err != nil {
			t.Fatalf("maintain %s: %v", table, err)
		}
	}
	reader, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer reader.Rollback(ctx)
	if _, err := reader.Exec(ctx, `SELECT count(*) FROM proxy_audit`); err != nil {
		t.Fatalf("reader: %v", err)
	}

	bounded := func(table string) error {
		done := make(chan error, 1)
		go func() { done <- maintainLog(ctx, table) }()
		select {
		case err := <-done:
			return err
		case <-time.After(4 * time.Second):
			t.Fatalf("maintain %s queued behind the reader", table)
			return nil
		}
	}
	if err := bounded("proxy_audit"); err != nil {
		t.Fatalf("no-op maintain with a reader open: %v", err)
	}
	if err := bounded("net_flow"); err != nil {
		t.Fatalf("maintain net_flow with a proxy_audit reader open: %v", err)
	}
	ictx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := testPool.Exec(ictx, `INSERT INTO net_flow (team_id, sandbox_id, protocol, dst_ip, dst_port, verdict) VALUES ($1, $2, 'tls', '192.0.2.1', 443, 'allowed')`, uuid.New(), uuid.New()); err != nil {
		t.Fatalf("insert during maintenance: %v", err)
	}

	if err := reader.Rollback(ctx); err != nil {
		t.Fatalf("reader rollback: %v", err)
	}

	// A day that must be created needs the parent lock a reader holds:
	// the pass fails within lock_timeout rather than waiting it out.
	ahead := time.Now().UTC().AddDate(0, 0, 7).Format("20060102")
	if _, err := testPool.Exec(ctx, `DROP TABLE proxy_audit_`+ahead); err != nil {
		t.Fatalf("drop day ahead: %v", err)
	}
	reader, err = testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer reader.Rollback(ctx)
	if _, err := reader.Exec(ctx, `SELECT count(*) FROM proxy_audit`); err != nil {
		t.Fatalf("reader: %v", err)
	}
	if err := bounded("proxy_audit"); err == nil {
		t.Fatal("creating a day behind an open reader did not give up")
	}
	if err := reader.Rollback(ctx); err != nil {
		t.Fatalf("reader rollback: %v", err)
	}
	if err := maintainLog(ctx, "proxy_audit"); err != nil {
		t.Fatalf("maintain after the reader left: %v", err)
	}
	var recreated bool
	if err := testPool.QueryRow(ctx, `SELECT to_regclass('proxy_audit_`+ahead+`') IS NOT NULL`).Scan(&recreated); err != nil || !recreated {
		t.Fatalf("day ahead recreated = %v, err = %v", recreated, err)
	}
}
