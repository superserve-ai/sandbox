package billing

import (
	"fmt"
	"time"
)

type UsageBucket struct{ Start, End time.Time }

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
			next = cur.AddDate(0, 0, 1)
		case "week":
			next = cur.AddDate(0, 0, 7)
		case "month":
			next = cur.AddDate(0, 1, 0)
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
