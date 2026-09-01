package main

import (
	"log"
	"sync"
	"time"
)

// A guest restored with its monotonic clock frozen wakes with a stale wall
// clock. The host's realtime is readable through the paravirtual PTP device,
// so boxd corrects the guest clock from it before reporting ready.

// wallClockTolerance: a guest that is already right is never touched; a frozen
// restore is off by minutes to weeks and always caught.
const wallClockTolerance = time.Second

// wallClockSource is the host's realtime, and the means to adopt it.
type wallClockSource interface {
	hostTime() (time.Time, error)
	set(time.Time) error
}

// wallClockStatus is what /health reports about the clock.
type wallClockStatus struct {
	Source      string `json:"source"` // "ptp" or "unavailable"
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

// sync brings CLOCK_REALTIME within tolerance of the host. ready is false only
// when host time was readable but the guest could not be corrected: that guest
// must not serve on a stale clock. An unreadable source degrades to today's
// behaviour — the marker is only ever written for a guest that proved the
// source at build time.
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
	// Re-read: a set that silently did nothing must read as not-ready.
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
