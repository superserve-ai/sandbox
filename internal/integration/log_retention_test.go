//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// Log tables are partitioned by day: maintenance creates the window and the
// days ahead, drops the days past it, and a row outside the window has
// nowhere to land.
func TestIntegration_LogRetentionMaintainsDayPartitions(t *testing.T) {
	ctx := context.Background()
	if _, err := testPool.Exec(ctx, `CREATE TABLE IF NOT EXISTS net_flow_20200101 PARTITION OF net_flow FOR VALUES FROM ('2020-01-01 00:00:00+00') TO ('2020-01-02 00:00:00+00')`); err != nil {
		t.Fatalf("stale partition: %v", err)
	}
	if err := testQueries.MaintainLogPartitions(ctx); err != nil {
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
