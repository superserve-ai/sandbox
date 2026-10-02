package main

// The discrepancy subcommand classifies every paused, non-destroyed
// sandbox lacking a verified backup generation in the audited bucket
// into exactly one class (no_snapshot_row, stale_zero_byte,
// sweep_missed) and emits a JSON ledger plus a human summary. Read-only
// by construction: it runs SELECTs against the control-plane DB,
// optionally lists the backup bucket, and writes nothing but the local
// report file.
//
// Like the rest of this tool it talks raw SQL over pgx rather than the
// control plane's query layer: DR tooling must keep working when the
// control plane is down, so its only inputs are a DB URL and the name
// of the bucket being audited. The default run needs no GCS
// credentials; -probe-bucket adds an optional bucket confirmation pass
// over the classified rows.

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"cloud.google.com/go/storage"
	"github.com/jackc/pgx/v5"

	"github.com/superserve-ai/sandbox/internal/backup"
)

// discrepancyQuery enumerates the uncovered paused fleet. Two shapes
// carry its semantics:
//
//   - The join target is the HEAD snapshot row, the one
//     sandbox.snapshot_id points at (pause finalize maintains it). Not a
//     lateral newest-by-created_at over snapshot history: a sandbox whose
//     head pointer is NULL must classify as no_snapshot_row even when
//     historical rows exist, because the head is what restore would
//     consume. The FK is ON DELETE SET NULL and the reaper deletes
//     snapshot rows of destroyed sandboxes, so NULL heads are real.
//   - Coverage is plain existence of a backup_generation row for the
//     sandbox in the audited bucket. Per-bucket because that is how the
//     uploader and sweep track coverage (vmd's Covered callback scopes
//     journal.Covered to its bucket, and backup_generation stores the
//     bucket for exactly this reason): after a bucket rotation, rows
//     pointing at the old bucket are not coverage in the new one, and
//     an unqualified EXISTS would undercount the gap. Existence, with no
//     latest-generation join or recency ranking, because the report
//     enumerates the never-covered backlog the backfill sweep owes:
//     sandboxes with no verified generation in the bucket at all. A
//     sandbox whose newest pause lost its upload while an older
//     generation exists is a coverage-recency question for per-pause
//     monitoring, and answering it takes per-generation manifest
//     correlation that is outside this ledger's scope.
const discrepancyQuery = `
SELECT sb.id::text,
       COALESCE(sb.host_id, ''),
       s.id IS NOT NULL AS has_snapshot,
       COALESCE(s.size_bytes, 0),
       s.created_at
FROM sandbox sb
LEFT JOIN snapshot s ON s.id = sb.snapshot_id
WHERE sb.status = 'paused'
  AND sb.destroyed_at IS NULL
  AND NOT EXISTS (SELECT 1 FROM backup_generation bg WHERE bg.sandbox_id = sb.id AND bg.bucket = $2)
  AND ($1 = '' OR sb.host_id = $1)
ORDER BY sb.id`

func runDiscrepancy(args []string) int {
	fs := flag.NewFlagSet("discrepancy", flag.ExitOnError)
	dbURL := fs.String("db-url", os.Getenv("DATABASE_URL"), "control-plane DB URL (default $DATABASE_URL)")
	bucket := fs.String("bucket", "", "backup bucket whose coverage is audited (required: coverage is recorded per bucket)")
	host := fs.String("host", "", "restrict the report to one host id")
	staleDays := fs.Int("stale-days", 30, "zero-byte snapshot records older than this classify as stale_zero_byte")
	out := fs.String("out", "", "report path (default ./discrepancy-report-<timestamp>.json)")
	probeBucket := fs.Bool("probe-bucket", false, "confirm classified rows against the bucket over GCS (requires credentials; default is DB-only)")
	_ = fs.Parse(args)
	if *dbURL == "" {
		fmt.Fprintln(os.Stderr, "discrepancy: -db-url (or DATABASE_URL) is required")
		return 2
	}
	if *bucket == "" {
		fmt.Fprintln(os.Stderr, "discrepancy: -bucket is required; coverage is recorded per bucket, so the report must name which cell's backup bucket it audits")
		return 2
	}
	// The upper bound keeps the horizon inside representable time (and
	// any real fleet's age); an operator typo like a pasted timestamp
	// should fail loudly, not classify everything as stale.
	if *staleDays < 0 || *staleDays > 36500 {
		fmt.Fprintln(os.Stderr, "discrepancy: -stale-days must be between 0 and 36500")
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	conn, err := pgx.Connect(ctx, *dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "discrepancy: connect: %v\n", err)
		return 1
	}
	defer conn.Close(ctx)

	// A mistyped or foreign-cell host id must not read as a clean zero:
	// verify the host row exists so "unknown host" and "no uncovered
	// rows" stay distinguishable. Unlike host restore this is a report,
	// not an inventory a recovery depends on, so an active host gets the
	// churn warning rather than a refusal.
	if *host != "" {
		var hostStatus string
		err := conn.QueryRow(ctx, `SELECT status FROM host WHERE id = $1`, *host).Scan(&hostStatus)
		if err == pgx.ErrNoRows {
			fmt.Fprintf(os.Stderr, "discrepancy: host %q is not in this cell's host table; check the id and the cell\n", *host)
			return 1
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "discrepancy: verify host: %v\n", err)
			return 1
		}
		if hostStatus == "active" {
			fmt.Fprintf(os.Stderr, "warning: host %q is active and taking placements; %s\n", *host, backup.DiscrepancyLiveWarning)
		}
	}

	dbRows, err := conn.Query(ctx, discrepancyQuery, *host, *bucket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "discrepancy: query: %v\n", err)
		return 1
	}
	defer dbRows.Close()
	var rows []backup.DiscrepancyRow
	for dbRows.Next() {
		var row backup.DiscrepancyRow
		var created *time.Time
		if err := dbRows.Scan(&row.SandboxID, &row.HostID, &row.HasSnapshot, &row.SnapshotSize, &created); err != nil {
			fmt.Fprintf(os.Stderr, "discrepancy: scan: %v\n", err)
			return 1
		}
		if created != nil {
			row.SnapshotCreated = *created
		}
		rows = append(rows, row)
	}
	if err := dbRows.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "discrepancy: query: %v\n", err)
		return 1
	}
	// The DB work ends with enumeration; release the control-plane
	// connection now rather than holding it across the optional GCS
	// probe, which walks the fleet serially and can run long. The
	// deferred Close stays as the safety net on early returns above
	// (Close on a closed pgx conn is a no-op).
	conn.Close(ctx)

	report := backup.BuildDiscrepancyReport(rows, time.Now().UTC(), *staleDays, *bucket, *host)

	exit := 0
	if *probeBucket {
		report.Probed = true
		if err := probeDiscrepancyBucket(ctx, *bucket, report); err != nil {
			// The DB-only classification is complete and worth keeping,
			// so fall through to the ledger write; but a requested probe
			// that did not finish must not read as a confirmed run, so
			// the failure lands in the ledger and the exit code.
			report.ProbeError = err.Error()
			fmt.Fprintf(os.Stderr, "warning: bucket probe incomplete: %v\n", err)
			exit = 1
		}
	}

	fmt.Printf("discrepancy report: %d paused sandboxes lack a verified backup generation in %s\n", report.Total, *bucket)
	fmt.Printf("  %-16s %d\n", backup.DiscrepancyStaleZeroByte, report.StaleZeroByte)
	fmt.Printf("  %-16s %d\n", backup.DiscrepancyNoSnapshotRow, report.NoSnapshotRow)
	fmt.Printf("  %-16s %d\n", backup.DiscrepancySweepMissed, report.SweepMissed)
	fmt.Fprintf(os.Stderr, "warning: %s\n", report.Warning)

	ledger, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "discrepancy: marshal report: %v\n", err)
		return 1
	}
	path := *out
	if path == "" {
		path = fmt.Sprintf("discrepancy-report-%s.json", report.GeneratedAt.Format("20060102T150405Z"))
	}
	// O_EXCL: a ledger must never silently truncate an existing report
	// (two runs sharing a second-resolution default name, or an -out
	// pointing at a prior ledger), and overwriting in place would keep
	// the old file's permissions instead of 0600.
	f, werr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if werr == nil {
		_, werr = f.Write(ledger)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			// A truncated ledger must not survive (it would parse as a
			// smaller fleet), and leaving it would also block an O_EXCL
			// retry at the same path.
			os.Remove(path)
		}
	}
	if werr != nil {
		// The classification still reaches the operator via stderr, but
		// the run failed its contract: automation pointing -out at a
		// collection path must not read a missing artifact as success.
		fmt.Fprintf(os.Stderr, "ledger write failed (%v); printing instead:\n%s\n", werr, ledger)
		return 1
	}
	fmt.Printf("ledger: %s\n", path)
	return exit
}

// probeDiscrepancyBucket lists each classified sandbox's prefix in the
// backup bucket and records how many completed generations exist there.
// A nonzero count on an uncovered row means durable bytes exist that
// the DB does not record, which points the investigation at report
// ingestion rather than the upload path; whether those generations
// capture the current pause is a manifest question the restore tooling
// answers, not this report.
func probeDiscrepancyBucket(ctx context.Context, bucket string, report *backup.DiscrepancyReport) error {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("storage client: %w", err)
	}
	defer client.Close()
	reader := backup.NewGCSReader(client, bucket)
	covered, failed := 0, 0
	for i := range report.Records {
		if ctx.Err() != nil {
			// Unprobed rows keep a nil bucket_generations, which the
			// ledger distinguishes from a probed zero.
			return fmt.Errorf("canceled after %d of %d rows", i, len(report.Records))
		}
		gens, err := backup.ListGenerations(ctx, reader, report.Records[i].SandboxID)
		if err != nil {
			// A per-row listing failure must not zero the row (nil means
			// "not probed", never "absent"); record it and keep going so
			// the pass stays a full ledger.
			report.Records[i].ProbeError = err.Error()
			failed++
			continue
		}
		n := len(gens)
		report.Records[i].BucketGenerations = &n
		if n > 0 {
			covered++
		}
	}
	fmt.Printf("bucket probe: %d of %d classified rows have completed generations in %s (durable bytes exist that the DB does not record; whether they capture the current pause needs the manifest)\n",
		covered, len(report.Records), bucket)
	if failed > 0 {
		return fmt.Errorf("%d of %d listings failed; their rows carry probe_error in the ledger", failed, len(report.Records))
	}
	return nil
}
