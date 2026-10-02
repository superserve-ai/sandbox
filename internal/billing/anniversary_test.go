package billing

import (
	"testing"
	"time"
)

func TestAnniversaryPeriod(t *testing.T) {
	anchor := time.Date(2026, 8, 21, 17, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		at        time.Time
		wantStart time.Time
		wantEnd   time.Time
		wantOK    bool
	}{
		{
			name:   "before commercial start is not billable",
			at:     anchor.Add(-time.Nanosecond),
			wantOK: false,
		},
		{
			name:      "commercial start",
			at:        anchor,
			wantStart: anchor,
			wantEnd:   time.Date(2026, 9, 21, 17, 0, 0, 0, time.UTC),
			wantOK:    true,
		},
		{
			name:      "inside first period",
			at:        time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
			wantStart: anchor,
			wantEnd:   time.Date(2026, 9, 21, 17, 0, 0, 0, time.UTC),
			wantOK:    true,
		},
		{
			name:      "exact anniversary advances period",
			at:        time.Date(2026, 9, 21, 17, 0, 0, 0, time.UTC),
			wantStart: time.Date(2026, 9, 21, 17, 0, 0, 0, time.UTC),
			wantEnd:   time.Date(2026, 10, 21, 17, 0, 0, 0, time.UTC),
			wantOK:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotStart, gotEnd, gotOK := AnniversaryPeriod(anchor, tc.at)
			if gotOK != tc.wantOK {
				t.Fatalf("ok = %v, want %v", gotOK, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if !gotStart.Equal(tc.wantStart) {
				t.Fatalf("start = %s, want %s", gotStart, tc.wantStart)
			}
			if !gotEnd.Equal(tc.wantEnd) {
				t.Fatalf("end = %s, want %s", gotEnd, tc.wantEnd)
			}
		})
	}
}

func TestAnniversaryPeriodMonthEndAnchor(t *testing.T) {
	anchor := time.Date(2026, 1, 31, 12, 0, 0, 0, time.UTC)

	febStart, febEnd, ok := AnniversaryPeriod(anchor, time.Date(2026, 2, 15, 0, 0, 0, 0, time.UTC))
	if !ok {
		t.Fatal("expected February to be billable")
	}
	if !febStart.Equal(anchor) {
		t.Fatalf("February start = %s, want %s", febStart, anchor)
	}
	wantFebEnd := time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC)
	if !febEnd.Equal(wantFebEnd) {
		t.Fatalf("February end = %s, want %s", febEnd, wantFebEnd)
	}

	marStart, marEnd, ok := AnniversaryPeriod(anchor, time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC))
	if !ok {
		t.Fatal("expected March to be billable")
	}
	if !marStart.Equal(wantFebEnd) {
		t.Fatalf("March start = %s, want %s", marStart, wantFebEnd)
	}
	wantMarEnd := time.Date(2026, 3, 31, 12, 0, 0, 0, time.UTC)
	if !marEnd.Equal(wantMarEnd) {
		t.Fatalf("March end = %s, want %s", marEnd, wantMarEnd)
	}

	aprilStart, aprilEnd, ok := AnniversaryPeriod(anchor, time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC))
	if !ok {
		t.Fatal("expected April to be billable")
	}
	if !aprilStart.Equal(wantMarEnd) {
		t.Fatalf("April start = %s, want %s", aprilStart, wantMarEnd)
	}
	wantAprilEnd := time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
	if !aprilEnd.Equal(wantAprilEnd) {
		t.Fatalf("April end = %s, want %s", aprilEnd, wantAprilEnd)
	}
}

func TestAnniversaryPeriodNormalizesToUTC(t *testing.T) {
	location := time.FixedZone("CDT", -5*60*60)
	anchor := time.Date(2026, 8, 21, 12, 0, 0, 123, location)
	at := time.Date(2026, 9, 21, 12, 0, 0, 123, location)

	start, end, ok := AnniversaryPeriod(anchor, at)
	if !ok {
		t.Fatal("expected anniversary boundary to be billable")
	}
	wantStart := time.Date(2026, 9, 21, 17, 0, 0, 123, time.UTC)
	wantEnd := time.Date(2026, 10, 21, 17, 0, 0, 123, time.UTC)
	if !start.Equal(wantStart) {
		t.Fatalf("start = %s, want %s", start, wantStart)
	}
	if !end.Equal(wantEnd) {
		t.Fatalf("end = %s, want %s", end, wantEnd)
	}
	if start.Location() != time.UTC || end.Location() != time.UTC {
		t.Fatalf("period locations = %v/%v, want UTC/UTC", start.Location(), end.Location())
	}
}
