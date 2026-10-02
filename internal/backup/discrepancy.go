package backup

import (
	"fmt"
	"time"
)

// Discrepancy classification: every paused, non-destroyed sandbox lacking
// a verified backup generation in the audited bucket falls into exactly
// one class, so a backup coverage gap reads as a small set of named
// causes instead of one opaque count. Coverage is per bucket, mirroring
// how the uploader and sweep track it (Journal.Covered takes the bucket
// as its scope): after a bucket rotation, rows pointing at the old
// bucket are not coverage in the new one. The policy lives here with
// no DB dependency; cmd/backup-restore/discrepancy.go owns the
// enumeration query and feeds rows in.
//
// The classes come from how a pause can end up uncovered:
//
//   - no_snapshot_row: the sandbox's head snapshot pointer
//     (sandbox.snapshot_id) is NULL, so the control plane records no
//     current pause artifact at all. The pointer is maintained by pause
//     finalize and is ON DELETE SET NULL, so a NULL head on a paused
//     sandbox is drift, not a transient.
//   - stale_zero_byte: the head snapshot row exists but records zero
//     bytes and predates the staleness horizon. size_bytes starts at
//     zero and gains a value from a pause-time manifest total or a
//     verified backup report, so an old row still at zero means neither
//     ever arrived for that pause.
//   - sweep_missed: everything else — a recent or sized head snapshot
//     with no verified generation. The backfill sweep has not converged
//     on it yet, or is not running on its host; the per-row host id is
//     what tells those two apart.
type DiscrepancyClass string

const (
	DiscrepancyNoSnapshotRow DiscrepancyClass = "no_snapshot_row"
	DiscrepancyStaleZeroByte DiscrepancyClass = "stale_zero_byte"
	DiscrepancySweepMissed   DiscrepancyClass = "sweep_missed"
)

// DiscrepancyLiveWarning travels in every report: enumeration is one
// point-in-time query, so while placement and the sweep are live, rows
// pause, resume, and gain coverage between runs and counts churn. For a
// fleet-wide report that churn is noise to be aware of, not a reason to
// refuse to run; only a frozen host yields stable numbers.
const DiscrepancyLiveWarning = "counts are a point-in-time snapshot; while placement and the backfill sweep are live they will churn between runs, and per-host zeros are provisional unless the host is frozen"

// DiscrepancyRow is one uncovered paused sandbox as enumerated from the
// control plane: the sandbox joined to its HEAD snapshot row (the one
// sandbox.snapshot_id points at), never a newest-by-created_at guess over
// snapshot history. A sandbox whose head is NULL classifies as
// no_snapshot_row even if historical snapshot rows exist, because the
// head is what pause finalize maintains and what restore would consume.
type DiscrepancyRow struct {
	SandboxID string
	HostID    string
	// HasSnapshot reports whether the head pointer resolved to a snapshot
	// row. False means sandbox.snapshot_id is NULL (the FK is ON DELETE
	// SET NULL, so a deleted row nulls the pointer rather than dangling).
	HasSnapshot     bool
	SnapshotSize    int64
	SnapshotCreated time.Time // zero when HasSnapshot is false
}

// DiscrepancyRecord is one classified row of the report ledger.
type DiscrepancyRecord struct {
	SandboxID string           `json:"sandbox_id"`
	HostID    string           `json:"host_id"`
	Class     DiscrepancyClass `json:"class"`
	Reason    string           `json:"reason"`
	// Head snapshot facts, present only when a head row exists.
	SnapshotCreated   *time.Time `json:"snapshot_created,omitempty"`
	SnapshotAgeDays   *int64     `json:"snapshot_age_days,omitempty"`
	SnapshotSizeBytes *int64     `json:"snapshot_size_bytes,omitempty"`
	// Optional GCS confirmation pass (-probe-bucket): how many completed
	// generations the bucket actually holds for this sandbox. Nonzero
	// means durable bytes exist that the DB does not record; whether
	// they capture the current pause takes a manifest comparison, which
	// is restore tooling's job, not this report's. Nil when the probe
	// did not run or failed for this row.
	BucketGenerations *int   `json:"bucket_generations,omitempty"`
	ProbeError        string `json:"probe_error,omitempty"`
}

// DiscrepancyReport aggregates a run: per-class counts first so the
// verdict reads before the detail, then every classified row.
type DiscrepancyReport struct {
	GeneratedAt time.Time `json:"generated_at"`
	// Bucket is the backup bucket whose coverage this report audits;
	// the enumeration's coverage predicate is scoped to it, so rows
	// pointing at a rotated-out bucket never count as coverage.
	Bucket        string `json:"bucket"`
	HostFilter    string `json:"host_filter,omitempty"`
	StaleDays     int    `json:"stale_days"`
	Warning       string `json:"warning"`
	Total         int    `json:"total"`
	NoSnapshotRow int    `json:"no_snapshot_row"`
	StaleZeroByte int    `json:"stale_zero_byte"`
	SweepMissed   int    `json:"sweep_missed"`
	// Probed reports whether the optional GCS confirmation pass ran;
	// ProbeError records why it did not complete, so a ledger with an
	// unconfirmed probe never reads as a confirmed one.
	Probed     bool                `json:"probed,omitempty"`
	ProbeError string              `json:"probe_error,omitempty"`
	Records    []DiscrepancyRecord `json:"records"`
}

// ClassifyDiscrepancy assigns exactly one class to an uncovered row. The
// staleness boundary is strict: a zero-byte snapshot created exactly
// staleDays ago is not yet stale and classifies as sweep_missed.
func ClassifyDiscrepancy(row DiscrepancyRow, now time.Time, staleDays int) DiscrepancyRecord {
	rec := DiscrepancyRecord{SandboxID: row.SandboxID, HostID: row.HostID}
	if !row.HasSnapshot {
		rec.Class = DiscrepancyNoSnapshotRow
		rec.Reason = "paused with a NULL head snapshot pointer: the control plane records no current pause artifact"
		return rec
	}
	created := row.SnapshotCreated
	size := row.SnapshotSize
	ageDays := int64(now.Sub(created).Hours() / 24)
	rec.SnapshotCreated = &created
	rec.SnapshotAgeDays = &ageDays
	rec.SnapshotSizeBytes = &size
	// AddDate rather than a Duration multiply: day counts near
	// time.Duration's ~106751-day ceiling would overflow the multiply
	// and invert the cutoff into the future. In UTC a calendar day is
	// exactly 24h, so the horizon is staleDays whole days.
	cutoff := now.AddDate(0, 0, -staleDays)
	if size == 0 && created.Before(cutoff) {
		rec.Class = DiscrepancyStaleZeroByte
		rec.Reason = fmt.Sprintf("zero-byte head snapshot older than %d days: no pause manifest total or backup report ever recorded a size", staleDays)
	} else {
		rec.Class = DiscrepancySweepMissed
		rec.Reason = "head snapshot recorded but no verified generation: sweep not yet converged, or not running on this host"
	}
	return rec
}

// BuildDiscrepancyReport classifies every row and aggregates counts.
// Rows arrive pre-filtered (paused, not destroyed, no backup_generation
// row for the audited bucket); this function only classifies and counts.
func BuildDiscrepancyReport(rows []DiscrepancyRow, now time.Time, staleDays int, bucket, hostFilter string) *DiscrepancyReport {
	report := &DiscrepancyReport{
		GeneratedAt: now,
		Bucket:      bucket,
		HostFilter:  hostFilter,
		StaleDays:   staleDays,
		Warning:     DiscrepancyLiveWarning,
		Total:       len(rows),
		Records:     make([]DiscrepancyRecord, 0, len(rows)),
	}
	for _, row := range rows {
		rec := ClassifyDiscrepancy(row, now, staleDays)
		switch rec.Class {
		case DiscrepancyNoSnapshotRow:
			report.NoSnapshotRow++
		case DiscrepancyStaleZeroByte:
			report.StaleZeroByte++
		case DiscrepancySweepMissed:
			report.SweepMissed++
		}
		report.Records = append(report.Records, rec)
	}
	return report
}
