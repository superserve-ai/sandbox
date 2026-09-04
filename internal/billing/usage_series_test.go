package billing

import (
	"testing"
	"time"
)

func TestUsageSeriesBucketsDST(t *testing.T) {
	loc, _ := time.LoadLocation("America/Chicago")
	s := time.Date(2024, 3, 10, 0, 0, 0, 0, loc)
	e := time.Date(2024, 3, 11, 0, 0, 0, 0, loc)
	b, err := UsageSeriesBuckets(s, e, "hour", loc)
	if err != nil || len(b) != 23 {
		t.Fatalf("got %d buckets err=%v", len(b), err)
	}
	s = time.Date(2024, 11, 3, 0, 0, 0, 0, loc)
	e = time.Date(2024, 11, 4, 0, 0, 0, 0, loc)
	b, err = UsageSeriesBuckets(s, e, "hour", loc)
	if err != nil || len(b) != 25 {
		t.Fatalf("fall back got %d", len(b))
	}
}
func TestUsageSeriesBucketsWeek(t *testing.T) {
	loc := time.UTC
	s := time.Date(2024, 1, 3, 0, 0, 0, 0, loc)
	e := s.AddDate(0, 0, 10)
	b, _ := UsageSeriesBuckets(s, e, "week", loc)
	if len(b) != 2 || b[0].Start.Weekday() != time.Wednesday {
		t.Fatalf("unexpected %#v", b)
	}
}

func TestUsageSeriesBucketsFractionalDST(t *testing.T) {
	loc, err := time.LoadLocation("Australia/Lord_Howe")
	if err != nil {
		t.Fatal(err)
	}
	s := time.Date(2024, 10, 6, 0, 0, 0, 0, loc)
	e := time.Date(2024, 10, 7, 0, 0, 0, 0, loc)
	b, err := UsageSeriesBuckets(s, e, "hour", loc)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []int{0, 1, 2, 3, 4} {
		got := b[i].Start.In(loc).Hour()
		if got != want {
			t.Fatalf("bucket %d starts at local hour %d, want %d", i, got, want)
		}
	}
}

func TestUsageSeriesBucketsFractionalFallBack(t *testing.T) {
	loc, err := time.LoadLocation("Australia/Lord_Howe")
	if err != nil {
		t.Fatal(err)
	}
	// The 30-minute fall-back occurs between 01:00 DST and 01:30 standard
	// time. Both wall-clock intervals must remain represented.
	s := time.Date(2024, 4, 7, 0, 0, 0, 0, loc)
	e := time.Date(2024, 4, 7, 3, 0, 0, 0, loc)
	b, err := UsageSeriesBuckets(s, e, "hour", loc)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 4 {
		t.Fatalf("got %d buckets, want 4", len(b))
	}
	if got := b[1].End.Sub(b[1].Start); got != time.Hour {
		t.Fatalf("repeated-hour bucket duration %s, want 1h", got)
	}
	if b[2].Start.Equal(b[1].Start) || b[2].Start.In(loc).Format("15:04") != "01:30" {
		t.Fatalf("next bucket starts at %s, want distinct 01:30", b[2].Start.In(loc))
	}
}
