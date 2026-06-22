// Command agent-e2e drives the durable-Actor agent loop end to end against a
// REAL boxd in a REAL (networked) Firecracker microVM — the isolated full-stack
// e2e for POST /v1/agents/send minus the vmd gRPC hop.
//
// It wires the PRODUCTION runtime — actor.Registry (single-writer lease) +
// actor.Router (wake-on-reference, serial inbox) + the real vmdwaker.Waker +
// the real boxddeliver.Deliverer over an HTTP exec/stream to boxd — and only
// stubs the SandboxBooter, because the VM is already booted (by the host
// harness script) and reachable over a dedicated TAP. For each turn it sends an
// event through Router.Route and drains the turn's Relay, asserting the in-guest
// harness saw the event (via $ACTOR_EVENT) and streamed its reply back through
// the inbox → Relay path.
//
// Run (on the KVM host, after a networked boxd VM is up):
//
//	agent-e2e -boxd-url http://172.31.99.2:49983/exec/stream -turns 3
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/superserve-ai/sandbox/internal/actor"
	"github.com/superserve-ai/sandbox/internal/actor/boxddeliver"
	"github.com/superserve-ai/sandbox/internal/actor/vmdwaker"
)

func main() {
	boxdURL := flag.String("boxd-url", "", "boxd /exec/stream URL of the running sandbox VM (required)")
	turns := flag.Int("turns", 3, "number of agent turns to drive")
	agentName := flag.String("agent", "agent-1", "durable Actor name")
	flag.Parse()
	if *boxdURL == "" {
		fail("-boxd-url is required")
	}

	fmt.Printf("Driving %d agent turns through Registry+Lease+Router → vmdwaker → boxddeliver → real boxd:\n", *turns)
	results, err := driveTurns(*boxdURL, *agentName, *turns, harnessTurnArgv)
	if err != nil {
		fail(err.Error())
	}
	for _, r := range results {
		want := "REPLY[" + r.payload + "]"
		if !strings.Contains(r.reply, want) {
			fail(fmt.Sprintf("turn %q: harness reply %q does not contain %q", r.payload, r.reply, want))
		}
		fmt.Printf("  sent %q → harness streamed %q  (%s) ✓\n", r.payload, r.reply, r.elapsed.Round(time.Millisecond))
	}
	fmt.Printf("\nPASS — %d turns delivered to the in-guest harness and streamed back through the Actor loop.\n", *turns)
}

// harnessTurnArgv is the in-guest "turn": read the event from $ACTOR_EVENT (how
// boxddeliver delivers it) and stream a reply on stdout.
var harnessTurnArgv = []string{"sh", "-c", `printf 'REPLY[%s]' "$ACTOR_EVENT"`}

// turnResult is one driven turn's outcome.
type turnResult struct {
	payload string
	reply   string
	elapsed time.Duration
}

// driveTurns wires the PRODUCTION agent-loop runtime — actor.Registry (lease) +
// actor.Router (wake-on-reference, serial inbox + Relay) + the real
// vmdwaker.Waker + the real boxddeliver.Deliverer over HTTPExecStreamer at
// boxdURL — and routes `turns` events through it, returning each turn's streamed
// reply. Only the SandboxBooter is stubbed (the sandbox is pre-booted). Shared by
// main (real boxd) and the test (httptest fake boxd).
func driveTurns(boxdURL, agentName string, turns int, turnArgv []string) ([]turnResult, error) {
	streamer := boxddeliver.NewHTTPExecStreamer(
		&http.Client{Timeout: 30 * time.Second},
		func(string) string { return boxdURL },
		func(string) (string, error) { return "", nil },
	)
	deliverer := boxddeliver.New(streamer, turnArgv)
	waker := vmdwaker.New(prebootedBooter{}, deliverer, func(actor.Actor) (vmdwaker.Target, error) {
		return vmdwaker.Target{}, nil
	})
	reg := actor.NewRegistry(actor.NewMemStore(), nil)
	router := actor.NewRouter(reg, waker, "agent-e2e", 16)
	ctx := context.Background()

	var results []turnResult
	for i := 1; i <= turns; i++ {
		payload := fmt.Sprintf("event-%d", i)
		relay := actor.NewRelay()
		ev := actor.Event{ID: fmt.Sprintf("ev-%d", i), Type: "msg", Payload: []byte(payload), Out: relay}
		start := time.Now()
		if err := router.Route(ctx, "team-e2e", agentName, actor.Actor{}, ev); err != nil {
			return results, fmt.Errorf("turn %d (%q): Route: %w", i, payload, err)
		}
		results = append(results, turnResult{payload: payload, reply: drain(ctx, relay), elapsed: time.Since(start)})
	}
	return results, nil
}

// drain reads the turn's Relay to completion, returning the concatenated reply.
func drain(ctx context.Context, relay *actor.Relay) string {
	var b strings.Builder
	cur := int64(0)
	for {
		chunk, ok, err := relay.ReadFrom(ctx, cur)
		if err != nil || !ok {
			return b.String()
		}
		b.Write(chunk.Data)
		cur = chunk.Seq
	}
}

// prebootedBooter is a SandboxBooter for an already-running VM: "boot" is a
// no-op that reports the sandbox live. The VM is started + networked by the host
// harness; here we only exercise the runtime + delivery path.
type prebootedBooter struct{}

func (prebootedBooter) RestoreSnapshot(_ context.Context, id, _, _, _, _, _, _ string, _ map[string]string) (string, uint32, uint32, error) {
	return id, 1, 256, nil
}
func (prebootedBooter) BareResumeInstance(_ context.Context, id string) (string, uint32, uint32, error) {
	return id, 1, 256, nil
}
func (prebootedBooter) DestroyInstance(_ context.Context, _ string, _ bool) error { return nil }

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "agent-e2e:", msg)
	os.Exit(1)
}
