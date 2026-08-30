package network

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// Compile-time interface compliance for both backends.
var (
	_ slotNetOps = shellSlotOps{}
	_ slotNetOps = (*netlinkSlotOps)(nil)
)

// fakeSlotOps records every backend call and fails the one named in failOn.
type fakeSlotOps struct {
	calls  []string
	failOn string
}

func (f *fakeSlotOps) op(name string) error {
	f.calls = append(f.calls, name)
	if name == f.failOn {
		return errors.New(name + " failed")
	}
	return nil
}

func (f *fakeSlotOps) AddNamespace(context.Context, string) error { return f.op("AddNamespace") }
func (f *fakeSlotOps) DelNamespace(context.Context, string) error { return f.op("DelNamespace") }
func (f *fakeSlotOps) BuildSlotVeth(_ context.Context, _, _, _, _ string) error {
	return f.op("BuildSlotVeth")
}
func (f *fakeSlotOps) MoveVethToHost(context.Context, string, string) error {
	return f.op("MoveVethToHost")
}
func (f *fakeSlotOps) ConfigureHostVeth(context.Context, string, string) error {
	return f.op("ConfigureHostVeth")
}
func (f *fakeSlotOps) RebuildTap(context.Context, string) error { return f.op("RebuildTap") }
func (f *fakeSlotOps) EnableLoopback(context.Context, string) error {
	return f.op("EnableLoopback")
}
func (f *fakeSlotOps) AddDefaultRoute(context.Context, string, string) error {
	return f.op("AddDefaultRoute")
}
func (f *fakeSlotOps) ReplaceDefaultRoute(context.Context, string, string) error {
	return f.op("ReplaceDefaultRoute")
}
func (f *fakeSlotOps) AddHostRoute(context.Context, string, string, string) error {
	return f.op("AddHostRoute")
}
func (f *fakeSlotOps) ReplaceHostRoute(context.Context, string, string, string) error {
	return f.op("ReplaceHostRoute")
}
func (f *fakeSlotOps) DelHostRoute(context.Context, string, string, string) error {
	return f.op("DelHostRoute")
}
func (f *fakeSlotOps) DelHostLink(context.Context, string) error { return f.op("DelHostLink") }

func testManager(ops slotNetOps) *Manager {
	return &Manager{
		log:       zerolog.Nop(),
		setupSem:  make(chan struct{}, 1),
		devices:   make(map[string]*VMNetInfo),
		slotOwner: make(map[int]string),
		ops:       ops,
	}
}

// TestSetupSlotFailureCleanup pins the two cleanup regimes: while the veth is
// still inside the namespace, failure cleanup is namespace deletion alone;
// once it has moved to the host, cleanup must also delete the host link.
func TestSetupSlotFailureCleanup(t *testing.T) {
	cases := []struct {
		failOn      string
		wantHostDel bool
	}{
		{"BuildSlotVeth", false},
		{"MoveVethToHost", false},
		{"ConfigureHostVeth", true},
		{"RebuildTap", true},
		{"AddDefaultRoute", true},
	}
	for _, tc := range cases {
		t.Run(tc.failOn, func(t *testing.T) {
			fake := &fakeSlotOps{failOn: tc.failOn}
			m := testManager(fake)
			_, _, err := m.setupSlot(context.Background(), 77)
			if err == nil || !strings.Contains(err.Error(), tc.failOn+" failed") {
				t.Fatalf("setupSlot error = %v, want failure from %s", err, tc.failOn)
			}
			gotHostDel := slices.Contains(fake.calls, "DelHostLink")
			if gotHostDel != tc.wantHostDel {
				t.Fatalf("DelHostLink called = %v, want %v (calls: %v)", gotHostDel, tc.wantHostDel, fake.calls)
			}
			if !slices.Contains(fake.calls, "DelNamespace") {
				t.Fatalf("DelNamespace not called (calls: %v)", fake.calls)
			}
			// EnableLoopback is best-effort; a failure there must not fail
			// the build, so it never appears as a failOn case above.
		})
	}
}

// TestSetupSlotCallOrder pins the build sequence the backends rely on: the
// namespace exists before anything enters it, and the veth leaves it only
// after the vpeer side is fully configured.
func TestSetupSlotCallOrder(t *testing.T) {
	fake := &fakeSlotOps{failOn: "AddDefaultRoute"} // stop before the firewall step
	m := testManager(fake)
	_, _, _ = m.setupSlot(context.Background(), 78)
	want := []string{
		"AddNamespace", "BuildSlotVeth", "MoveVethToHost",
		"ConfigureHostVeth", "RebuildTap", "EnableLoopback", "AddDefaultRoute",
	}
	got := fake.calls[:len(fake.calls)-2] // trim the cleanup calls
	if !slices.Equal(got, want) {
		t.Fatalf("call order = %v, want %v", got, want)
	}
}

func TestBackendSelection(t *testing.T) {
	m := &Manager{}
	WithNetlinkSlotOps()(m)
	if !m.useNetlinkOps {
		t.Fatal("WithNetlinkSlotOps did not select the netlink backend")
	}
}

func TestSocketTimeoutBounds(t *testing.T) {
	if d := socketTimeout(context.Background()); d != 10*time.Second {
		t.Fatalf("no-deadline timeout = %v, want 10s", d)
	}
	shortCtx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if d := socketTimeout(shortCtx); d != time.Second {
		t.Fatalf("near-spent deadline timeout = %v, want the 1s floor", d)
	}
	midCtx, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	if d := socketTimeout(midCtx); d > 5*time.Second || d < 4*time.Second {
		t.Fatalf("mid deadline timeout = %v, want ~5s", d)
	}
}

func TestFakeCoversInterface(t *testing.T) {
	// Guards the fake against silently drifting from the interface.
	var ops slotNetOps = &fakeSlotOps{}
	if err := ops.AddNamespace(context.Background(), "x"); err != nil {
		t.Fatal(err)
	}
}

// Namespace create/delete must stay on iproute2: it initializes /run/netns as
// a shared mount under flock, and unlinks the name even when the unmount
// fails. Creation is also the one slot operation that cannot use
// inNamespace's restore-or-terminate discipline — the namespace does not
// exist until the call that enters it — so a hand-rolled version's failure
// paths are the only ones that can return a thread to the scheduler still
// inside a sandbox namespace. Structural check only: it pins the delegation,
// not the absence of a shadowing method.
func TestNetlinkBackendDelegatesNamespaceLifecycle(t *testing.T) {
	f, ok := reflect.TypeOf(netlinkSlotOps{}).FieldByName("shellSlotOps")
	if !ok || !f.Anonymous {
		t.Fatal("netlinkSlotOps must embed shellSlotOps so AddNamespace/DelNamespace stay on iproute2")
	}
}

func init() {
	// Fail fast in tests if the fixed MTU constant ever becomes unparseable,
	// since the netlink backend derives its int MTU from it.
	if _, err := fmt.Sscanf(ifaceMTU, "%d", new(int)); err != nil {
		panic("ifaceMTU is not numeric: " + ifaceMTU)
	}
}
