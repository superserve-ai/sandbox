package handoff

import (
	"context"
	"strings"
	"sync"
	"testing"
)

type fakeGateway struct{ rec func(string) }

func (f *fakeGateway) QuiesceGRPC(on bool) {
	f.rec("gw: quiesce-grpc " + map[bool]string{true: "on", false: "off"}[on])
}
func (f *fakeGateway) QuiesceResolver(on bool) {
	f.rec("gw: quiesce-resolver " + map[bool]string{true: "on", false: "off"}[on])
}
func (f *fakeGateway) SetActive(gen Generation) { f.rec("gw: set-active " + gen.ID) }

// A full Deploy through the controller and the systemd adapter (with fake
// exec + control backends) must issue the right systemctl and control commands
// in the right order.
func TestSystemdActionsDeploySequence(t *testing.T) {
	var mu sync.Mutex
	var log []string
	rec := func(s string) { mu.Lock(); log = append(log, s); mu.Unlock() }

	a := &SystemdActions{
		Gateway:         &fakeGateway{rec: rec},
		Unit:            func(id string) string { return "superserve-vmd@" + id },
		GenControl:      func(id string) string { return "/run/vmd/gen-" + id + "-ctl.sock" },
		ActivateTimeout: 0,
		StabilizeWait:   0,
		run: func(_ context.Context, name string, args ...string) error {
			rec("run: " + name + " " + strings.Join(args, " "))
			return nil
		},
		send: func(_ context.Context, sock, cmd string) (string, error) {
			// Normalize the drain budget (a timing-dependent number) for a stable
			// recorded sequence.
			if strings.HasPrefix(cmd, "drain") {
				rec("send[" + sock + "]: drain")
				return "OK drained", nil
			}
			rec("send[" + sock + "]: " + cmd)
			switch {
			case strings.HasPrefix(cmd, "activate"):
				return "OK active", nil
			case strings.HasPrefix(cmd, "status"):
				return "OK phase=active", nil
			default:
				return "OK", nil
			}
		},
	}

	c := New(a, Generation{ID: "a", GRPCSocket: "/run/vmd/gen-a-grpc.sock", ResolverSocket: "/run/vmd/gen-a-resolver.sock"})
	next := Generation{ID: "b", GRPCSocket: "/run/vmd/gen-b-grpc.sock", ResolverSocket: "/run/vmd/gen-b-resolver.sock"}
	if err := c.Deploy(context.Background(), Generation{ID: "a"}, next); err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if c.Current().ID != "b" {
		t.Fatalf("current = %s, want b", c.Current().ID)
	}

	want := []string{
		"run: systemctl start superserve-vmd@b",
		"send[/run/vmd/gen-b-ctl.sock]: status",
		"gw: quiesce-grpc on",
		"send[/run/vmd/gen-a-ctl.sock]: drain",
		"run: systemctl stop superserve-vmd@a",
		"gw: quiesce-resolver on",
		"send[/run/vmd/gen-b-ctl.sock]: activate",
		"gw: set-active b",
		"gw: quiesce-resolver off",
		"gw: quiesce-grpc off",
		"send[/run/vmd/gen-b-ctl.sock]: status",
	}
	mu.Lock()
	defer mu.Unlock()
	if len(log) != len(want) {
		t.Fatalf("commands = %v\nwant %v", log, want)
	}
	for i := range want {
		if log[i] != want[i] {
			t.Fatalf("command[%d] = %q, want %q", i, log[i], want[i])
		}
	}
}
