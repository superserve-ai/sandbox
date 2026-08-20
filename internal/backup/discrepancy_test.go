package backup

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Fixed clock: classification depends only on now-relative ages, so the
// tests pin now and derive creation times from it.
var discNow = time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)

func discRow(hasSnapshot bool, size int64, age time.Duration) DiscrepancyRow {
	row := DiscrepancyRow{SandboxID: "sb-1", HostID: "usw2", HasSnapshot: hasSnapshot}
	if hasSnapshot {
		row.SnapshotSize = size
		row.SnapshotCreated = discNow.Add(-age)
	}
	return row
}

func TestClassifyDiscrepancy(t *testing.T) {
	const day = 24 * time.Hour
	cases := []struct {
		name string
		row  DiscrepancyRow
		want DiscrepancyClass
	}{
		// A NULL head classifies as no_snapshot_row regardless of any
		// historical snapshot rows: the enumeration query joins ONLY the
		// head pointer (sandbox.snapshot_id), so history never reaches
		// classification. Both realities present as HasSnapshot=false.
		{"null head, no history", discRow(false, 0, 0), DiscrepancyNoSnapshotRow},
		{"null head, history exists but is not the head", discRow(false, 0, 0), DiscrepancyNoSnapshotRow},
		{"zero-byte old", discRow(true, 0, 31*day), DiscrepancyStaleZeroByte},
		{"zero-byte recent", discRow(true, 0, 5*day), DiscrepancySweepMissed},
		{"nonzero old", discRow(true, 4096, 45*day), DiscrepancySweepMissed},
		{"nonzero recent", discRow(true, 4096, time.Hour), DiscrepancySweepMissed},
		// Strict boundary: created exactly staleDays ago is not yet
		// stale.
		{"zero-byte exactly at stale-days", discRow(true, 0, 30*day), DiscrepancySweepMissed},
		{"zero-byte one second past stale-days", discRow(true, 0, 30*day+time.Second), DiscrepancyStaleZeroByte},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := ClassifyDiscrepancy(tc.row, discNow, 30)
			if rec.Class != tc.want {
				t.Fatalf("class = %q, want %q", rec.Class, tc.want)
			}
			if rec.Reason == "" {
				t.Fatal("reason must never be empty")
			}
			if rec.SandboxID != tc.row.SandboxID || rec.HostID != tc.row.HostID {
				t.Fatalf("identity not carried: %+v", rec)
			}
			if tc.row.HasSnapshot {
				if rec.SnapshotCreated == nil || rec.SnapshotSizeBytes == nil || rec.SnapshotAgeDays == nil {
					t.Fatalf("snapshot facts missing on a row with a head: %+v", rec)
				}
				if *rec.SnapshotSizeBytes != tc.row.SnapshotSize {
					t.Fatalf("size = %d, want %d", *rec.SnapshotSizeBytes, tc.row.SnapshotSize)
				}
			} else if rec.SnapshotCreated != nil || rec.SnapshotSizeBytes != nil || rec.SnapshotAgeDays != nil {
				t.Fatalf("snapshot facts must be absent without a head: %+v", rec)
			}
		})
	}
}

// A horizon at the flag's upper bound must stay a past cutoff: a naive
// duration multiply overflows near 106751 days and flips the cutoff
// into the future, classifying everything as stale.
func TestClassifyDiscrepancyLargeStaleDays(t *testing.T) {
	rec := ClassifyDiscrepancy(discRow(true, 0, 40*24*time.Hour), discNow, 36500)
	if rec.Class != DiscrepancySweepMissed {
		t.Fatalf("class = %q, want %q", rec.Class, DiscrepancySweepMissed)
	}
}

func TestClassifyDiscrepancyAgeDays(t *testing.T) {
	rec := ClassifyDiscrepancy(discRow(true, 0, 31*24*time.Hour+time.Hour), discNow, 30)
	if *rec.SnapshotAgeDays != 31 {
		t.Fatalf("age days = %d, want 31", *rec.SnapshotAgeDays)
	}
}

func TestBuildDiscrepancyReportCounts(t *testing.T) {
	const day = 24 * time.Hour
	rows := []DiscrepancyRow{
		discRow(false, 0, 0),
		discRow(true, 0, 40*day),
		discRow(true, 0, 50*day),
		discRow(true, 0, day),
		discRow(true, 1<<20, 90*day),
	}
	report := BuildDiscrepancyReport(rows, discNow, 30, "cell-backups", "usw2")
	if report.Total != 5 || len(report.Records) != 5 {
		t.Fatalf("total = %d, records = %d, want 5", report.Total, len(report.Records))
	}
	if report.NoSnapshotRow != 1 || report.StaleZeroByte != 2 || report.SweepMissed != 2 {
		t.Fatalf("counts = %d/%d/%d, want 1/2/2", report.NoSnapshotRow, report.StaleZeroByte, report.SweepMissed)
	}
	if report.NoSnapshotRow+report.StaleZeroByte+report.SweepMissed != report.Total {
		t.Fatal("every row must land in exactly one class")
	}
	if report.Bucket != "cell-backups" || report.HostFilter != "usw2" || report.StaleDays != 30 {
		t.Fatalf("parameters not recorded: %+v", report)
	}
	if report.Warning != DiscrepancyLiveWarning {
		t.Fatal("the live-churn warning must travel in the ledger")
	}
	// Covered, destroyed, and non-paused sandboxes never reach this
	// function: the enumeration query excludes them (status='paused',
	// destroyed_at IS NULL, NOT EXISTS over backup_generation scoped to
	// the audited bucket, so a row for a different bucket does NOT count
	// as coverage), which the cmd-level SQL invariant test pins.
}

func TestBuildDiscrepancyReportEmpty(t *testing.T) {
	report := BuildDiscrepancyReport(nil, discNow, 30, "cell-backups", "")
	if report.Total != 0 || len(report.Records) != 0 {
		t.Fatalf("empty input must yield an empty report: %+v", report)
	}
	// Records must marshal as [] rather than null so ledger consumers
	// can iterate without a nil check.
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"records":null`) {
		t.Fatalf("records must marshal as an empty array: %s", data)
	}
}

// TestDiscrepancyReportJSONShape pins the ledger's wire shape: field
// names and per-class keys are parsed by operators and downstream
// tooling, so renaming any of them is a breaking change.
func TestDiscrepancyReportJSONShape(t *testing.T) {
	const day = 24 * time.Hour
	rows := []DiscrepancyRow{
		discRow(false, 0, 0),
		discRow(true, 0, 40*day),
	}
	report := BuildDiscrepancyReport(rows, discNow, 30, "cell-backups", "usw2")
	got, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want := `{
  "generated_at": "2026-08-16T12:00:00Z",
  "bucket": "cell-backups",
  "host_filter": "usw2",
  "stale_days": 30,
  "warning": ` + string(mustJSON(t, DiscrepancyLiveWarning)) + `,
  "total": 2,
  "no_snapshot_row": 1,
  "stale_zero_byte": 1,
  "sweep_missed": 0,
  "records": [
    {
      "sandbox_id": "sb-1",
      "host_id": "usw2",
      "class": "no_snapshot_row",
      "reason": "paused with a NULL head snapshot pointer: the control plane records no current pause artifact"
    },
    {
      "sandbox_id": "sb-1",
      "host_id": "usw2",
      "class": "stale_zero_byte",
      "reason": "zero-byte head snapshot older than 30 days: no pause manifest total or backup report ever recorded a size",
      "snapshot_created": "2026-07-07T12:00:00Z",
      "snapshot_age_days": 40,
      "snapshot_size_bytes": 0
    }
  ]
}`
	if string(got) != want {
		t.Fatalf("ledger shape drifted:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
