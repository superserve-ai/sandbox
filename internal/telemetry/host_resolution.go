package telemetry

import "time"

// HostResolution is one EXECUTED registry resolution of a host id to a VMD
// client: a row read (plus dial when the address moved). Recorded once per
// singleflight execution — never per waiting caller — so counts describe
// resolutions, not request bursts. Isolated from the aggregate lifecycle
// metrics because a blocking resolution is a distinct, bounded (~2s
// worst-case) component of create/resume tail latency that would otherwise
// be unattributable.
type HostResolution struct {
	// Kind: "cold" (no cached client at flight start) or "due"
	// (re-verification of an existing entry).
	Kind     string
	Result   string
	Duration time.Duration
}
