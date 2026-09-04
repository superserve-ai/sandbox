package billing

import (
	"fmt"
	"time"
)

type UsageBucket struct{ Start, End time.Time }

// advanceCalendar returns the next calendar boundary, accounting for civil
// dates that do not exist in a timezone (for example, a skipped day).
func advanceCalendar(cur time.Time, granularity string) time.Time {
	var next time.Time
	switch granularity {
	case "day":
		next = cur.AddDate(0, 0, 1)
	case "week":
		next = cur.AddDate(0, 0, 7)
	case "month":
		next = cur.AddDate(0, 1, 0)
	}
	if next.After(cur) {
		return next
	}
	// AddDate can normalize a skipped civil date back to cur. Scan subsequent
	// local dates until a valid boundary is found.
	cl := cur.In(cur.Location())
	for days := 1; days <= 370; days++ {
		candidate := time.Date(cl.Year(), cl.Month(), cl.Day()+days, 0, 0, 0, 0, cur.Location())
		if candidate.After(cur) {
			return candidate
		}
	}
	// A timezone should not have more than a year of skipped dates; retain a
	// progress guarantee even if one is encountered.
	return cur.Add(24 * time.Hour)
}

// UsageSeriesBuckets returns clipped, half-open calendar buckets in loc.
func UsageSeriesBuckets(start, end time.Time, granularity string, loc *time.Location) ([]UsageBucket, error) {
	if !start.Before(end) {
		return nil, fmt.Errorf("end must be after start")
	}
	if loc == nil {
		return nil, fmt.Errorf("timezone is required")
	}
	if granularity != "hour" && granularity != "day" && granularity != "week" && granularity != "month" {
		return nil, fmt.Errorf("unsupported granularity")
	}
	var cur time.Time
	local := start.In(loc)
	if granularity == "hour" {
		cur = time.Date(local.Year(), local.Month(), local.Day(), local.Hour(), 0, 0, 0, loc)
	} else if granularity == "day" {
		cur = time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, loc)
	} else if granularity == "week" {
		cur = time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, loc)
		for cur.Weekday() != time.Monday {
			cur = cur.AddDate(0, 0, -1)
		}
	} else {
		cur = time.Date(local.Year(), local.Month(), 1, 0, 0, 0, 0, loc)
	}
	// Include the containing calendar bucket, then continue until the range ends.
	out := make([]UsageBucket, 0, 32)
	for cur.Before(end) {
		var next time.Time
		switch granularity {
		case "hour":
			// Prefer the next local wall-clock hour, but retain the repeated
			// hour on fall-back by using elapsed time across a backward offset
			// transition (including fractional transitions such as Lord Howe).
			elapsed := cur.Add(time.Hour)
			cl := cur.In(loc)
			el := elapsed.In(loc)
			_, curOffset := cl.Zone()
			_, elapsedOffset := el.Zone()
			if elapsedOffset < curOffset {
				next = elapsed
			} else {
				next = time.Date(cl.Year(), cl.Month(), cl.Day(), cl.Hour()+1, 0, 0, 0, loc)
				// A skipped wall hour can normalize back to the current instant
				// (e.g. spring-forward); always make progress in that case.
				if !next.After(cur) {
					next = elapsed
				}
			}
		case "day":
			next = advanceCalendar(cur, granularity)
		case "week":
			next = advanceCalendar(cur, granularity)
		case "month":
			next = advanceCalendar(cur, granularity)
		}
		bs, be := cur, next
		if bs.Before(start) {
			bs = start
		}
		if be.After(end) {
			be = end
		}
		if bs.Before(be) {
			out = append(out, UsageBucket{bs, be})
		}
		if len(out) > 400 {
			return nil, fmt.Errorf("usage series exceeds 400 buckets")
		}
		cur = next
	}
	return out, nil
}
