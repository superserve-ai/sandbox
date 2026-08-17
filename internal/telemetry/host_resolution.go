package telemetry

import "time"

// HostResolution is one registry resolution of a host id to a VMD client:
// a row read (plus dial when the address moved) that lifecycle dispatch
// either blocks on or that runs as a background refresh-ahead. Isolated
// from the aggregate lifecycle metrics because a blocking resolution is a
// distinct, bounded (~2s worst-case) component of create/resume tail
// latency that would otherwise be unattributable.
type HostResolution struct {
	// Kind: "cold" (no cached client) or "due" (verification due).
	Kind string
	// Mode: "blocking" (a request waited on it) or "background"
	// (refresh-ahead).
	Mode     string
	Result   string
	Duration time.Duration
}
