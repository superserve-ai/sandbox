//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/preview"
)

func waitForHostBlocker(t *testing.T, ctx context.Context, waiter, blocker uint32) {
	t.Helper()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked bool
		if err := testPool.QueryRow(ctx, `SELECT $2::int = ANY(pg_blocking_pids($1::int))`, waiter, blocker).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("host lock wait not observed:", ctx.Err())
		case <-ticker.C:
		}
	}
}

func TestIntegration_HostCapabilitiesHeartbeatOverlap(t *testing.T) {
	for _, advertised := range []struct {
		name         string
		capabilities []string
		legacy       bool
		want         bool
	}{
		{"stable", []string{preview.HostCapabilityPorts, "other_capability"}, false, true},
		{"legacy-stable-negative-control", []string{preview.HostCapabilityPorts, "other_capability"}, true, false},
		{"removed", []string{"other_capability"}, false, false},
		{"empty", nil, false, false},
	} {
		t.Run(advertised.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			host := seedActivePreviewHost(t, preview.HostCapabilityPorts, "other_capability")
			arg := db.HostHasCapabilitiesParams{HostID: host, AllowedStatuses: []string{"active", "draining"}, RequiredCapabilities: []string{preview.HostCapabilityPorts}}
			if ok, err := testQueries.LockedHostHasCapabilities(ctx, arg); err != nil || !ok {
				t.Fatalf("initial=%v: %v", ok, err)
			}
			writer, err := testPool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Rollback(context.Background())
			if _, err = writer.Exec(ctx, `UPDATE host SET last_heartbeat_at=last_heartbeat_at+interval '1 second' WHERE id=$1`, host); err != nil {
				t.Fatal(err)
			}
			if err = db.New(writer).SyncHostCapabilities(ctx, db.SyncHostCapabilitiesParams{HostID: host, Capabilities: advertised.capabilities}); err != nil {
				t.Fatal(err)
			}
			reader, err := testPool.Acquire(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Release()
			type result struct {
				ok  bool
				err error
			}
			done := make(chan result, 1)
			start := time.Now()
			go func() {
				var ok bool
				var err error
				if advertised.legacy {
					err = reader.QueryRow(ctx, legacyHostCapabilityRead, arg.RequiredCapabilities, arg.HostID, arg.AllowedStatuses, arg.HeartbeatAfter).Scan(&ok)
				} else {
					ok, err = db.New(reader).LockedHostHasCapabilities(ctx, arg)
				}
				done <- result{ok, err}
			}()
			waitForHostBlocker(t, ctx, reader.Conn().PgConn().PID(), writer.Conn().PgConn().PID())
			if err = writer.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case r := <-done:
				if r.err != nil || r.ok != advertised.want {
					t.Fatalf("overlap=%v: %v, want %v", r.ok, r.err, advertised.want)
				}
			case <-ctx.Done():
				t.Fatal("reader failed to complete:", ctx.Err())
			}
			t.Logf("coordinated lock wait plus standalone validation: %s", time.Since(start))
			if ok, err := testQueries.LockedHostHasCapabilities(ctx, arg); err != nil || ok != (advertised.want || advertised.legacy) {
				t.Fatalf("subsequent=%v: %v", ok, err)
			}
		})
	}
}

func TestIntegration_HostCapabilitiesWithdrawalAfterValidation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	host := seedActivePreviewHost(t, preview.HostCapabilityPorts)
	arg := db.HostHasCapabilitiesParams{HostID: host, AllowedStatuses: []string{"active"}, RequiredCapabilities: []string{preview.HostCapabilityPorts}}
	reader, err := testPool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Rollback(context.Background())
	lockedAt := time.Now()
	if ok, err := db.New(reader).LockedHostHasCapabilities(ctx, arg); err != nil || !ok {
		t.Fatalf("protected=%v: %v", ok, err)
	}
	writer, err := testPool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := writer.Exec(ctx, `UPDATE host SET last_heartbeat_at=last_heartbeat_at+interval '1 second' WHERE id=$1`, host)
		if err == nil {
			err = db.New(writer).SyncHostCapabilities(ctx, db.SyncHostCapabilitiesParams{HostID: host})
		}
		if err == nil {
			err = writer.Commit(ctx)
		}
		done <- err
	}()
	waitForHostBlocker(t, ctx, writer.Conn().PgConn().PID(), reader.Conn().PgConn().PID())
	if ok, err := db.New(reader).LockedHostHasCapabilities(ctx, arg); err != nil || !ok {
		t.Fatalf("withdrawal must wait: %v: %v", ok, err)
	}
	if err = reader.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	t.Logf("protected transaction duration including coordinated writer wait: %s", time.Since(lockedAt))
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("withdrawal failed to complete:", ctx.Err())
	}
	if ok, err := testQueries.LockedHostHasCapabilities(ctx, arg); err != nil || ok {
		t.Fatalf("withdrawal=%v: %v", ok, err)
	}
}

// The former reader is a negative control: the coordinated stable-set refresh
// must expose its mixed snapshot while the production wrapper succeeds.
const legacyHostCapabilityRead = `-- name: HostHasCapabilities :one
WITH target_host AS MATERIALIZED (
  SELECT id, last_heartbeat_at
  FROM host
  WHERE id = $2
    AND status = ANY($3::text[])
    AND last_heartbeat_at IS NOT NULL
    AND ($4::timestamptz IS NULL
         OR last_heartbeat_at > $4)
  FOR SHARE
)
SELECT EXISTS (
  SELECT 1
  FROM target_host h
  WHERE NOT EXISTS (
    SELECT 1
    FROM unnest($1::text[]) AS required(capability)
    WHERE NOT EXISTS (
      SELECT 1
      FROM host_capability hc
      WHERE hc.host_id = h.id
        AND hc.capability = required.capability
        AND hc.heartbeat_at = h.last_heartbeat_at
    )
  )
)
`

func TestIntegration_HostCapabilityValidationTiming(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	host := seedActivePreviewHost(t, preview.HostCapabilityPorts)
	arg := db.HostHasCapabilitiesParams{HostID: host, AllowedStatuses: []string{"active"}, RequiredCapabilities: []string{preview.HostCapabilityPorts}}
	const samples = 20
	for _, mode := range []string{"legacy", "standalone", "mutation"} {
		started := time.Now()
		var held time.Duration
		for i := 0; i < samples; i++ {
			var ok bool
			var err error
			switch mode {
			case "legacy":
				err = testPool.QueryRow(ctx, legacyHostCapabilityRead, arg.RequiredCapabilities, arg.HostID, arg.AllowedStatuses, arg.HeartbeatAfter).Scan(&ok)
			case "standalone":
				ok, err = testQueries.LockedHostHasCapabilities(ctx, arg)
			case "mutation":
				var tx pgx.Tx
				tx, err = testPool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
				if err != nil {
					t.Fatal(err)
				}
				lockStart := time.Now()
				ok, err = db.New(tx).LockedHostHasCapabilities(ctx, arg)
				if err != nil {
					_ = tx.Rollback(ctx)
					t.Fatal(err)
				}
				err = tx.Commit(ctx)
				held += time.Since(lockStart)
			}
			if err != nil || !ok {
				t.Fatalf("%s: %v, %v", mode, ok, err)
			}
		}
		t.Logf("%s: %d samples, mean validation=%s, mean mutation lock acquisition through commit=%s", mode, samples, time.Since(started)/samples, held/samples)
	}
}
