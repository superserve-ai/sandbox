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
