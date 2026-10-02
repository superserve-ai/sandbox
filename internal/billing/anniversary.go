package billing

import "time"

// AnniversaryPeriod returns the monthly commercial billing period containing
// at. The anchor is the authoritative commercial start. For anchors on a day
// that does not exist in a target month, the boundary is clamped to that
// month's final day (for example Jan 31 -> Feb 28/29).
//
// The first period begins exactly at anchor. Times before anchor are not part
// of paid billing and return ok=false.
func AnniversaryPeriod(anchor, at time.Time) (start, end time.Time, ok bool) {
	anchor = anchor.UTC()
	at = at.UTC()
	if at.Before(anchor) {
		return time.Time{}, time.Time{}, false
	}

	months := (at.Year()-anchor.Year())*12 + int(at.Month()-anchor.Month())
	start = anniversaryBoundary(anchor, months)
	if start.After(at) {
		months--
		start = anniversaryBoundary(anchor, months)
	}
	end = anniversaryBoundary(anchor, months+1)
	return start, end, true
}

func anniversaryBoundary(anchor time.Time, monthOffset int) time.Time {
	first := time.Date(anchor.Year(), anchor.Month(), 1, anchor.Hour(), anchor.Minute(), anchor.Second(), anchor.Nanosecond(), time.UTC).AddDate(0, monthOffset, 0)
	lastDay := time.Date(first.Year(), first.Month()+1, 0, 0, 0, 0, 0, time.UTC).Day()
	day := anchor.Day()
	if day > lastDay {
		day = lastDay
	}
	return time.Date(first.Year(), first.Month(), day, anchor.Hour(), anchor.Minute(), anchor.Second(), anchor.Nanosecond(), time.UTC)
}
