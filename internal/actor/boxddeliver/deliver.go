// Package boxddeliver is the production vmdwaker.Deliverer: it delivers an
// Actor's turn into the in-guest harness by exec'ing the harness turn command in
// the sandbox (via boxd) and streaming its output back into the turn's Relay.
// The actual exec/stream transport is an injected ExecStreamer seam (proxy or a
// vmd-mediated boxd exec in production; a mock in tests), so the delivery logic
// is unit-tested without a running sandbox.
package boxddeliver

import (
	"context"

	"github.com/superserve-ai/sandbox/internal/actor"
	"github.com/superserve-ai/sandbox/internal/actor/vmdwaker"
)

// ExecStreamer runs a command inside a sandbox, feeds it stdin, and streams its
// stdout back chunk-by-chunk. The production impl is the sandbox exec path
// (proxy /exec/stream against boxd, or a vmd-mediated exec); ExecStreamer keeps
// boxddeliver decoupled from that wiring so it stays unit-testable.
type ExecStreamer interface {
	ExecStream(ctx context.Context, sandboxID string, argv []string, stdin []byte, onOut func(chunk []byte)) error
}

// Deliverer delivers a turn by exec'ing the harness command with the event as
// stdin and streaming stdout into the turn's output sink. This is the "exec per
// turn" delivery mode (the simplest harness transport); stdin/http transports
// for long-lived harnesses layer on the same ExecStreamer.
type Deliverer struct {
	exec     ExecStreamer
	turnArgv []string
}

// New builds a Deliverer that runs turnArgv in the sandbox for each event.
func New(exec ExecStreamer, turnArgv []string) *Deliverer {
	return &Deliverer{exec: exec, turnArgv: turnArgv}
}

var _ vmdwaker.Deliverer = (*Deliverer)(nil)

// Deliver execs the harness turn command in the Actor's sandbox, passing the
// event payload on stdin and streaming stdout into ev.Out (with monotonic
// sequence numbers so the Relay can dedup replays). Returns when the turn's
// process exits.
func (d *Deliverer) Deliver(ctx context.Context, sandboxID string, ev actor.Event) error {
	var seq int64
	return d.exec.ExecStream(ctx, sandboxID, d.turnArgv, ev.Payload, func(chunk []byte) {
		if ev.Out != nil {
			seq++
			ev.Out.Append(seq, chunk)
		}
	})
}
