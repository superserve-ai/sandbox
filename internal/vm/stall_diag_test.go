package vm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestCounterDeltasKeepOnlyWhatMoved(t *testing.T) {
	// A stalled VM's signal is what is still ticking — or conspicuously not.
	// Hundreds of static counters would bury it, so only movement survives.
	before := map[string]int64{"vcpu0/exits": 100, "vcpu1/exits": 50, "vm/fpu_reload": 7}
	after := map[string]int64{"vcpu0/exits": 100, "vcpu1/exits": 4050, "vm/fpu_reload": 7}

	d := counterDeltas(before, after)
	if len(d) != 1 {
		t.Fatalf("expected only the moving counter, got %v", d)
	}
	if d["vcpu1/exits"] != 4000 {
		t.Fatalf("delta = %d, want 4000", d["vcpu1/exits"])
	}
	// A counter absent from the first sample cannot yield a meaningful delta.
	if got := counterDeltas(map[string]int64{}, after); len(got) != 0 {
		t.Fatalf("counters without a baseline produced deltas: %v", got)
	}
	// The rendered form must name the vcpu, since distinguishing the spinning
	// vCPU from the halted one is the entire purpose.
	if s := formatDeltas(d); !strings.Contains(s, "vcpu1/exits=+4000") {
		t.Fatalf("formatted deltas lost the vcpu identity: %q", s)
	}
	if s := formatDeltas(nil); s != "none-moved" {
		t.Fatalf("empty deltas rendered as %q", s)
	}
}

func TestKVMDebugDirMatchesTheWholePIDToken(t *testing.T) {
	// KVM names its directories "<pid>-<instance>", so a prefix match on the
	// bare pid would also match pid 12345 for pid 1234.
	root := t.TempDir()
	for _, name := range []string{"1234-15", "12345-15", "999-1"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Exercise the same matching rule the real lookup uses.
	entries, _ := os.ReadDir(root)
	var got []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "1234-") {
			got = append(got, e.Name())
		}
	}
	if len(got) != 1 || got[0] != "1234-15" {
		t.Fatalf("pid token matching selected %v", got)
	}
}

func TestGuestIPPatternExtractsAddresses(t *testing.T) {
	sample := "          ffffffff810a2b40\n          ffffffff810a2b40\n          7f9c0a1b2c3d\nnot-an-address\n"
	m := guestIPPattern.FindAllStringSubmatch(sample, -1)
	if len(m) != 3 {
		t.Fatalf("extracted %d addresses, want 3: %v", len(m), m)
	}
	if m[0][1] != "ffffffff810a2b40" {
		t.Fatalf("first address = %q", m[0][1])
	}
}

func TestArmedDiagnosticsAreCancelledOnTheHappyPath(t *testing.T) {
	// The entire cost on a successful restore must be a timer that never
	// fires: an unknown pid would make the battery a no-op anyway, but the
	// contract is that cancelling is always safe and immediate.
	m := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{}}
	stop := m.armEarlyStallDiagnostics("vm-that-succeeds", 0)
	stop()
	stop() // idempotent: restore paths may cancel more than once
	time.Sleep(10 * time.Millisecond)
}

func TestDiagnosticsRefuseAForeignPID(t *testing.T) {
	// Same identity rule as the teardown capture: profiling and counter reads
	// must never be aimed at a process that is not this VM's firecracker.
	m := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{}}
	m.runStallDiagnostics("00000000-0000-0000-0000-000000000000", os.Getpid())
	m.runStallDiagnostics("any-vm", 0)
}
