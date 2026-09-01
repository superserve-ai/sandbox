package main

import (
	"log"
	"sync"
	"time"
)

// A guest restored with its monotonic clock frozen wakes believing it is still
// the moment its snapshot was taken: kvm-clock is what normally drags the wall
// clock forward on restore, and freezing it for readiness leaves CLOCK_REALTIME
// stale by the snapshot's age. The host exposes its own realtime to the guest
// through the paravirtual PTP device, so boxd reads that on every health check
// and corrects the guest clock before reporting ready — the supervisor waits on
// /health, so a corrected clock is part of what "ready" means.

// wallClockTolerance is how far the guest may drift before boxd steps the clock.
// Wide enough that a guest whose clock is already right — a fresh boot, or a
// legacy restore where kvm-clock advanced it — is never touched; a frozen
// restore is off by minutes to weeks, so it is always caught.
const wallClockTolerance = time.Second

// wallClockSource is the host's view of realtime, and the means to adopt it.
type wallClockSource interface {
	// hostTime returns realtime as the host sees it, or an error when no
	// trusted source is usable in this guest.
	hostTime() (time.Time, error)
	// set replaces the guest's CLOCK_REALTIME.
	set(time.Time) error
}

// wallClockStatus is what /health reports about the clock, so an operator (or
// the template builder deciding whether to mark an image) can see which path
// this guest is on rather than infer it from latency.
type wallClockStatus struct {
	// Source is "ptp" when the host's time was readable, "unavailable" otherwise.
	Source string `json:"source"`
	// CorrectedMs is the size of the step applied on this check, zero if none.
	CorrectedMs int64  `json:"corrected_ms,omitempty"`
	Error       string `json:"error,omitempty"`
}

type wallClock struct {
	src wallClockSource
	now func() time.Time

	mu           sync.Mutex
	warnedNoSrc  bool
	correctedCnt int
}

func newWallClock(src wallClockSource) *wallClock {
	return &wallClock{src: src, now: time.Now}
}

// sync brings CLOCK_REALTIME within tolerance of the host and reports what it
// did. ready is false only when host time was readable but the guest could not
// be brought into tolerance: that guest would serve on a stale clock, so it
// must not be reported ready.
//
// An unreadable source is surfaced but not fatal. A guest is only ever marked
// as correcting its clock after this source was proven at build time, so a
// source that fails at runtime is an anomaly to log, not grounds to strand the
// sandbox: it degrades to today's behaviour, which is wrong only if the clock
// was actually frozen, and the marker is what decides that.
func (c *wallClock) sync() (status wallClockStatus, ready bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	host, err := c.src.hostTime()
	if err != nil {
		if !c.warnedNoSrc {
			c.warnedNoSrc = true
			log.Printf("wall clock: host time unavailable, clock left as-is: %v", err)
		}
		return wallClockStatus{Source: "unavailable", Error: err.Error()}, true
	}
	status.Source = "ptp"

	delta := host.Sub(c.now())
	if delta.Abs() <= wallClockTolerance {
		return status, true
	}

	if err := c.src.set(host); err != nil {
		status.Error = "set: " + err.Error()
		log.Printf("wall clock: %v off host, correction failed: %v", delta, err)
		return status, false
	}
	// Re-read both sides: the step itself took time, and a set that silently
	// did nothing must read as not-ready rather than as corrected.
	host2, err := c.src.hostTime()
	if err != nil {
		status.Error = "verify: " + err.Error()
		return status, false
	}
	if host2.Sub(c.now()).Abs() > wallClockTolerance {
		status.Error = "still outside tolerance after correction"
		log.Printf("wall clock: %v off host, still outside tolerance after correction", delta)
		return status, false
	}

	status.CorrectedMs = delta.Milliseconds()
	c.correctedCnt++
	log.Printf("wall clock: corrected by %v from host time", delta)
	return status, true
}
