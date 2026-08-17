package telemetry

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

// BackupCoverageQuery reports, per host that currently has paused
// sandboxes, how many of those sandboxes lack any verified backup
// generation, and how old the oldest such pause is.
//
// It deliberately drives FROM sandbox rather than from active host rows
// (the host-capacity sampler's shape): a paused sandbox pinned to a
// missing, draining, or stale host row is exactly the disaster-recovery
// exposure this metric exists to surface, so those rows must still land
// in a group instead of being dropped by an INNER JOIN or a host-status
// predicate. The host_id label is the sandbox's own pinned host_id, so
// sandboxes whose host row is gone still attribute to the specific
// missing host rather than collapsing into one placeholder series; only
// region, which lives on the host row, falls back to 'unknown'.
//
// A host whose paused population is fully covered still returns a row
// with uncovered=0, so the alert series converges to an explicit zero
// instead of going silent and leaving the alert to time out. A host
// that loses its last paused sandbox entirely simply drops out of the
// result set; the observable gauges publish only the latest snapshot,
// so its series stops being exported and retires instead of freezing at
// a stale value.
//
// Uncovered means no backup_generation row at all: the table stores one
// row per verified generation in the bucket, so bare existence is the
// coverage predicate. This is deliberately total-loss exposure (no
// restore point of any age exists), the signal the backfill effort
// converges on; whether the CURRENT pause has shipped yet is a
// freshness question owned by the vmd-side backlog-age alert on
// backup_oldest_pending_age_seconds, not by this gauge, and folding it
// in here would keep the coverage alert firing through routine upload
// lag. The age is anchored on the snapshot row behind
// sandbox.snapshot_id (the authoritative current pause, maintained by
// FinalizePause), not sandbox.updated_at, which churns on metadata
// edits. A NULL snapshot_id still counts as uncovered but contributes
// no age, and clock skew (a future created_at) clamps to zero.
//
// Exported so the DB-backed integration suite can run the SQL against
// the real migrations.
const BackupCoverageQuery = `
SELECT
	region,
	host_id,
	COUNT(*) FILTER (WHERE uncovered)::bigint AS uncovered_paused,
	COALESCE(GREATEST(EXTRACT(EPOCH FROM (now() - MIN(paused_at) FILTER (WHERE uncovered))), 0), 0)::double precision AS oldest_uncovered_age_seconds
FROM (
	SELECT
		COALESCE(h.region, 'unknown') AS region,
		COALESCE(s.host_id, 'unknown') AS host_id,
		NOT EXISTS (
			SELECT 1 FROM backup_generation bg WHERE bg.sandbox_id = s.id
		) AS uncovered,
		snap.created_at AS paused_at
	FROM sandbox s
	LEFT JOIN host h ON h.id = s.host_id
	LEFT JOIN snapshot snap ON snap.id = s.snapshot_id
	WHERE s.status = 'paused'
	  AND s.destroyed_at IS NULL
) paused
GROUP BY region, host_id
ORDER BY host_id
`

const backupCoverageQueryTimeout = 5 * time.Second

// backupCoverageTickTimeout bounds one tick's claim-and-sample work: the
// query timeout, clamped to a third of the lease. The clamp is the
// fencing story for publication: a successful claim grants the full
// lease, every database operation between that claim and the in-memory
// publish is bounded by this context, and a third of the lease leaves
// two-thirds of margin, so a leader stalled by a slow database cannot
// publish a snapshot on a lease that has already lapsed and been handed
// to another replica. What no context can bound is a stall in the Go
// runtime itself between the last context check and the publish; that
// residual overlap costs at most one export cycle and self-silences on
// the next tick, when the stale leader's claim fails and it publishes
// an empty snapshot.
func backupCoverageTickTimeout(leaseFor time.Duration) time.Duration {
	timeout := backupCoverageQueryTimeout
	if third := leaseFor / 3; third < timeout {
		timeout = third
	}
	return timeout
}

// The lease row that elects one coverage sampler per cell. The control
// plane runs many replicas, and this query scans the cell's whole
// paused population; without election every replica would multiply that
// load and publish competing copies of every gauge series. A session
// advisory lock cannot elect here: the control plane reaches Postgres
// through transaction pooling, where the backend that took the lock and
// the backend running the next statement need not match. The TTL lease
// row (the billing rollup scheduler's pattern) works through any
// pooler: the claim succeeds when the lease is expired or already held
// by the claimant, so the leader renews in place each tick and a dead
// leader is replaced as soon as its lease lapses.
const backupCoverageLeaseName = "backup_coverage"

// The deadline is computed on the database clock (now() + the lease
// duration), never the replica's: expiry is also judged by now(), and a
// replica clock behind by one lease duration could otherwise steal a
// live lease, while one ahead would stall failover.
const claimBackupCoverageLeaseQuery = `
INSERT INTO telemetry_sampler_lease (name, locked_by, locked_until)
VALUES ($1, $2, now() + make_interval(secs => $3))
ON CONFLICT (name) DO UPDATE
SET locked_by = EXCLUDED.locked_by,
    locked_until = EXCLUDED.locked_until,
    updated_at = now()
WHERE telemetry_sampler_lease.locked_until <= now()
   OR telemetry_sampler_lease.locked_by = EXCLUDED.locked_by
RETURNING true`

// ClaimBackupCoverageLease attempts one atomic claim or renewal of the
// sampler lease and reports whether the caller now holds it. The whole
// decision is one INSERT ... ON CONFLICT DO UPDATE statement whose
// WHERE admits only an expired lease or the current holder, and the
// verdict is taken solely from whether the statement returned a row, so
// two contenders can never both conclude they won. Exported so the
// DB-backed integration suite can prove that mutual exclusion against
// the real schema.
func ClaimBackupCoverageLease(ctx context.Context, pool *pgxpool.Pool, holder string, leaseFor time.Duration) (bool, error) {
	var claimed bool
	err := pool.QueryRow(ctx, claimBackupCoverageLeaseQuery, backupCoverageLeaseName, holder, leaseFor.Seconds()).Scan(&claimed)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return claimed, err
}

// samplerHolderID names this sampler instance in the lease row. The pid
// disambiguates replicas that share a hostname, and the random suffix
// disambiguates samplers within one process (tests run several).
func samplerHolderID() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown-host"
	}
	return fmt.Sprintf("%s-%d-%08x", host, os.Getpid(), rand.Uint32())
}

// StartBackupCoverageSampler publishes per-host backup coverage of the
// paused sandbox population from a single lease-elected replica per
// cell. Like the host-capacity sampler it derives the signal from
// trusted control-plane state, and it stays host-scoped so cardinality
// is bounded by the fleet, not the sandbox count.
//
// Each tick every replica contends for the lease. The winner samples
// and publishes a full snapshot; everyone else publishes an empty one,
// which makes the observable gauges export nothing from that replica.
// That asymmetry is the failover story: a replica that loses (or gives
// up) the lease goes silent within a tick instead of exporting its last
// pre-handover values alongside the new leader's live ones. Leadership
// moving therefore costs at most one export cycle of overlap, and a
// crashed leader is replaced when its lease lapses, about three
// intervals later.
func StartBackupCoverageSampler(ctx context.Context, pool *pgxpool.Pool, recorder Recorder, interval time.Duration) {
	if pool == nil || recorder == nil {
		return
	}
	// A replica whose recorder exports nothing (OTel init failed, so
	// main fell back to the noop recorder) must not contend for the
	// lease: it could win and renew indefinitely while publishing
	// nothing, black-holing the cell's coverage series and locking out
	// replicas that could actually export.
	if isNoopRecorder(recorder) {
		return
	}
	if interval <= 0 {
		interval = 15 * time.Second
	}
	// Renewed every interval; three intervals of margin tolerates a slow
	// tick without dropping leadership, while bounding the sampling gap
	// after a leader crash. The bound also covers request-throttled
	// runtimes (Cloud Run with idle CPU throttling): a leader on a
	// replica that has gone request-idle may tick slowly or stall, but
	// it then fails to renew, the lease lapses, and a replica that is
	// still getting CPU takes over, so a throttled leader costs at most
	// a few export intervals of coverage gap rather than a silent
	// series.
	leaseFor := 3 * interval
	holder := samplerHolderID()

	go func() {
		// The goroutine owns whatever this replica last published;
		// withdraw it on the way out so a graceful shutdown's final
		// export flush does not ship a leader's values after a
		// follower has already taken over.
		defer recorder.RecordBackupCoverage(context.Background(), nil)

		// Deploys start a cell's replicas near-simultaneously; a little
		// jitter keeps them from racing the first claim in the same
		// instant. The winner still samples within about a second of
		// startup.
		select {
		case <-ctx.Done():
			return
		case <-time.After(rand.N(time.Second)):
		}

		// Consecutive failed sample passes while the lease keeps
		// renewing. The lease claim is far cheaper than the coverage
		// scan, so a database sick enough to fail only the scan would
		// otherwise leave the last snapshot exporting (and an incident
		// cleared) indefinitely; after a few failures the snapshot is
		// withdrawn until a pass succeeds again.
		failures := 0
		const maxStaleSamples = 3

		tick := func() {
			tickCtx, cancel := context.WithTimeout(ctx, backupCoverageTickTimeout(leaseFor))
			defer cancel()

			claimed, err := ClaimBackupCoverageLease(tickCtx, pool, holder, leaseFor)
			if err != nil {
				log.Warn().Err(err).Msg("backup coverage telemetry lease claim failed")
				// Claims and samples ride the same database: if claims
				// fail, this replica cannot know it still leads, and it
				// could not produce fresh data anyway. Publish nothing.
				recorder.RecordBackupCoverage(tickCtx, nil)
				return
			}
			if !claimed {
				recorder.RecordBackupCoverage(tickCtx, nil)
				return
			}
			if sampleBackupCoverage(tickCtx, pool, recorder) {
				failures = 0
				return
			}
			failures++
			if failures >= maxStaleSamples {
				recorder.RecordBackupCoverage(tickCtx, nil)
			}
		}

		tick()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				tick()
			}
		}
	}()
}

// sampleBackupCoverage runs one query pass and publishes the result as
// a full snapshot, reporting whether it published. On a failed or
// partial read it publishes nothing and keeps the recorder's previous
// snapshot: the lease was just renewed, so leadership is stable, and a
// snapshot stale by a tick beats flapping the series on a transient
// error. The caller bounds how long that grace lasts.
func sampleBackupCoverage(ctx context.Context, pool *pgxpool.Pool, recorder Recorder) bool {
	rows, err := pool.Query(ctx, BackupCoverageQuery)
	if err != nil {
		log.Warn().Err(err).Msg("backup coverage telemetry query failed")
		return false
	}
	defer rows.Close()

	complete := true
	var snapshot []BackupCoverage
	for rows.Next() {
		var c BackupCoverage
		if err := rows.Scan(&c.Region, &c.HostID, &c.UncoveredPaused, &c.OldestUncoveredAgeSeconds); err != nil {
			log.Warn().Err(err).Msg("backup coverage telemetry row scan failed")
			complete = false
			continue
		}
		snapshot = append(snapshot, c)
	}
	if err := rows.Err(); err != nil {
		log.Warn().Err(err).Msg("backup coverage telemetry rows failed")
		complete = false
	}
	// Publish only complete reads: a partial snapshot would retire the
	// series it never reached, silently clearing a live alert.
	if !complete {
		return false
	}
	recorder.RecordBackupCoverage(ctx, snapshot)
	return true
}
