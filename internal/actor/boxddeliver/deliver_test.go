package boxddeliver

import (
	"context"
	"strings"
	"testing"

	"github.com/superserve-ai/sandbox/internal/actor"
)

// echoExec streams the stdin back as output (in two chunks), as a stand-in for a
// harness turn that echoes its input.
type echoExec struct {
	gotSandbox string
	gotArgv    []string
	gotStdin   []byte
}

func (e *echoExec) ExecStream(_ context.Context, sandboxID string, argv []string, stdin []byte, onOut func([]byte)) error {
	e.gotSandbox = sandboxID
	e.gotArgv = argv
	e.gotStdin = stdin
	onOut([]byte("out:"))
	onOut(stdin)
	return nil
}

func TestDeliverStreamsHarnessOutput(t *testing.T) {
	ex := &echoExec{}
	d := New(ex, []string{"claude", "-p"})
	relay := actor.NewRelay()
	ev := actor.Event{ID: "e1", Payload: []byte("hello"), Out: relay}

	if err := d.Deliver(context.Background(), "sbx-1", ev); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	relay.Close()

	// Exec was invoked against the right sandbox with the harness command + event.
	if ex.gotSandbox != "sbx-1" {
		t.Errorf("sandbox = %q", ex.gotSandbox)
	}
	if strings.Join(ex.gotArgv, " ") != "claude -p" {
		t.Errorf("argv = %v", ex.gotArgv)
	}
	if string(ex.gotStdin) != "hello" {
		t.Errorf("stdin = %q", ex.gotStdin)
	}

	// Output streamed into the relay in order.
	ctx := context.Background()
	var out []string
	cur := int64(0)
	for {
		c, ok, err := relay.ReadFrom(ctx, cur)
		if err != nil || !ok {
			break
		}
		out = append(out, string(c.Data))
		cur = c.Seq
	}
	if strings.Join(out, "") != "out:hello" {
		t.Fatalf("streamed output = %q, want %q", strings.Join(out, ""), "out:hello")
	}
}

// TestDeliverNoSink: fire-and-forget events (no Out) still exec without error.
func TestDeliverNoSink(t *testing.T) {
	d := New(&echoExec{}, []string{"run"})
	if err := d.Deliver(context.Background(), "sbx", actor.Event{ID: "e", Payload: []byte("x")}); err != nil {
		t.Fatalf("deliver without sink should succeed: %v", err)
	}
}
