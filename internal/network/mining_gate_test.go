package network

import (
	"context"
	"net"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/superserve-ai/sandbox/internal/abuse"
	"github.com/superserve-ai/sandbox/internal/blocklist"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

type kernelTestTeams struct {
	trusted atomic.Bool
	mode    atomic.Int32
	id      uuid.UUID
}

func (s *kernelTestTeams) TeamPolicy(id uuid.UUID) abuse.TeamPolicy {
	mode := abuse.ModeEnforce
	if s.mode.Load() == 1 {
		mode = abuse.ModeOff
	}
	if s.mode.Load() == 2 {
		mode = abuse.ModeObserve
	}
	return abuse.TeamPolicy{TeamID: id, Known: true, Mode: mode, Trusted: s.trusted.Load()}
}

// Run only in an explicitly disposable Linux network namespace/container.
// This exercises real NFQUEUE attribution and established TCP/UDP traffic,
// including the raw/forward paths missed by the web proxy.
func TestMiningKernelContainmentTCPUDP(t *testing.T) {
	for _, protocol := range []string{"udp", "tcp"} {
		t.Run(protocol, func(t *testing.T) { testMiningKernelContainment(t, protocol) })
	}
}
func testMiningKernelContainment(t *testing.T, triggerProtocol string) {
	if os.Getenv("RUN_MINING_NETNS_TESTS") != "1" {
		t.Skip("requires disposable Linux namespace with CAP_NET_ADMIN and CAP_SYS_ADMIN")
	}
	root, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	runtime.LockOSThread()
	guest, err := netns.New()
	if err == nil {
		err = netns.Set(root)
	}
	runtime.UnlockOSThread()
	if err != nil {
		t.Fatal(err)
	}
	defer guest.Close()
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "veth-2"}, PeerName: "mining-peer"}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatal(err)
	}
	defer netlink.LinkDel(veth)
	host, err := netlink.LinkByName("veth-2")
	if err != nil {
		t.Fatal(err)
	}
	peer, err := netlink.LinkByName("mining-peer")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetNsFd(peer, int(guest)); err != nil {
		t.Fatal(err)
	}
	addAddr := func(link netlink.Link, s string) {
		a, e := netlink.ParseAddr(s)
		if e != nil {
			t.Fatal(e)
		}
		if e = netlink.AddrAdd(link, a); e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { _ = netlink.AddrDel(link, a) })
	}
	addAddr(host, "10.11.0.1/24")
	if err := netlink.LinkSetUp(host); err != nil {
		t.Fatal(err)
	}
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	addAddr(lo, "203.0.113.9/32")
	addAddr(lo, "203.0.113.10/32")
	configure := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := netns.Set(guest); err != nil {
			configure <- err
			return
		}
		defer netns.Set(root)
		link, err := netlink.LinkByName("mining-peer")
		if err == nil {
			addr, _ := netlink.ParseAddr("10.11.0.2/24")
			err = netlink.AddrAdd(link, addr)
			if err == nil {
				forged, _ := netlink.ParseAddr("10.11.0.3/32")
				err = netlink.AddrAdd(link, forged)
			}
		}
		if err == nil {
			err = netlink.LinkSetUp(link)
		}
		if err == nil {
			err = netlink.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Gw: net.ParseIP("10.11.0.1")})
		}
		configure <- err
	}()
	if err := <-configure; err != nil {
		t.Fatal(err)
	}
	dialFrom := func(network, address, source string) (net.Conn, error) {
		type result struct {
			c net.Conn
			e error
		}
		ch := make(chan result, 1)
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			if err := netns.Set(guest); err != nil {
				ch <- result{e: err}
				return
			}
			defer netns.Set(root)
			dialer := net.Dialer{Timeout: 300 * time.Millisecond}
			if source != "" {
				dialer.LocalAddr = &net.UDPAddr{IP: net.ParseIP(source)}
			}
			c, e := dialer.Dial(network, address)
			ch <- result{c, e}
		}()
		r := <-ch
		return r.c, r.e
	}
	dial := func(network, address string) (net.Conn, error) { return dialFrom(network, address, "") }
	gate, err := NewMiningPacketGate(zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	p := NewEgressProxy(0, 0, 0, 10, zerolog.Nop())
	sandbox, team := uuid.New(), uuid.New()
	victim := uuid.New()
	p.RegisterSandbox("10.11.0.3", victim.String())
	p.RegisterSandbox("10.11.0.2", sandbox.String())
	teams := &kernelTestTeams{id: team}
	source := NewHostMiningSource(nil, teams, p, "host-test", "boot-test")
	assignments := miningAssignments{sandbox: {TeamPolicy: abuse.TeamPolicy{TeamID: team}, SandboxID: sandbox, HostID: "host-test", HostIP: "10.11.0.2", Assignment: "assignment-one"}}
	assignments[victim] = abuse.SandboxPolicy{TeamPolicy: abuse.TeamPolicy{TeamID: team}, SandboxID: victim, HostID: "host-test", HostIP: "10.11.0.3", Assignment: "assignment-victim"}
	source.cur.Store(&assignments)
	source.curBindings = make(map[uuid.UUID]*EgressRules)
	for id, assignment := range assignments {
		_, source.curBindings[id] = p.miningRegistration(assignment.HostIP)
	}
	if err := gate.SyncAssignments(source); err != nil {
		t.Fatal(err)
	}
	if err := gate.UpdateCIDRs([]string{"203.0.113.9/32"}); err != nil {
		t.Fatal(err)
	}
	policy := blocklist.New(&blocklist.Config{CustomCIDRs: []string{"203.0.113.9/32"}}, zerolog.Nop())
	submit := &miningTestSubmit{}
	controller := NewMiningContainment(source, gate, submit, zerolog.Nop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- gate.Run(ctx, policy, controller) }()
	listener, err := net.Listen("tcp", "203.0.113.10:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	tcp, err := dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if _, err := tcp.Write([]byte("a")); err != nil {
		t.Fatal(err)
	}
	server.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := server.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp", "203.0.113.10:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	mirror, err := dial("udp", udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer mirror.Close()
	if _, err := mirror.Write([]byte("a")); err != nil {
		t.Fatal(err)
	}
	udp.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := udp.ReadFrom(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	blockedDestination, err := net.ListenPacket("udp", "203.0.113.9:45454")
	if err != nil {
		t.Fatal(err)
	}
	defer blockedDestination.Close()
	for _, mode := range []int32{1, 2, 0} {
		teams.mode.Store(mode)
		teams.trusted.Store(mode == 0)
		attempt, err := dial("udp", "203.0.113.9:45454")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = attempt.Write([]byte("policy-check")); err != nil {
			t.Fatal(err)
		}
		attempt.Close()
		blockedDestination.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if _, _, err := blockedDestination.ReadFrom(make([]byte, 20)); err == nil {
			t.Fatal("independent mining destination deny bypassed")
		}
		if controller.Blocked(sandbox, "10.11.0.2") {
			t.Fatal("trusted/off/observe traffic triggered containment")
		}
	}
	teams.trusted.Store(false)
	teams.mode.Store(0)
	spoof, err := dialFrom("udp", "203.0.113.9:45454", "10.11.0.3")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := spoof.Write([]byte("forged")); err != nil {
		t.Fatal(err)
	}
	spoof.Close()
	time.Sleep(100 * time.Millisecond)
	if controller.Blocked(victim, "10.11.0.3") || controller.Blocked(sandbox, "10.11.0.2") {
		t.Fatal("spoofed source triggered quarantine")
	}
	mining, err := dial(triggerProtocol, "203.0.113.9:45454")
	if triggerProtocol == "udp" {
		if err != nil {
			t.Fatal(err)
		}
		defer mining.Close()
		if _, err := mining.Write([]byte("hit")); err != nil {
			t.Fatal(err)
		}
	} else if err == nil {
		mining.Close()
		t.Fatal("direct mining TCP connection was allowed")
	}

	deadline := time.Now().Add(2 * time.Second)
	for !controller.Blocked(sandbox, "10.11.0.2") && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !controller.Blocked(sandbox, "10.11.0.2") {
		select {
		case err := <-done:
			t.Fatalf("observer stopped: %v", err)
		default:
			t.Fatal("direct mining hit did not contain")
		}
	}
	if _, err := mirror.Write([]byte("b")); err != nil {
		t.Fatal(err)
	}
	udp.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if _, _, err := udp.ReadFrom(make([]byte, 1)); err == nil {
		t.Fatal("existing UDP flow bypassed containment")
	}
	if _, err := tcp.Write([]byte("b")); err != nil {
		t.Fatal(err)
	}
	server.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if _, err := server.Read(make([]byte, 1)); err == nil {
		t.Fatal("existing TCP flow bypassed containment")
	}
	if conn, err := dial("tcp", listener.Addr().String()); err == nil {
		conn.Close()
		t.Fatal("new TCP mirror bypassed containment")
	}
	// The set is intentionally still present. A replacement occupant must pass
	// even before background cleanup, proving stale-IP safety in the kernel.
	replacement := uuid.New()
	p.RegisterSandbox("10.11.0.2", replacement.String())
	if _, err := mirror.Write([]byte("c")); err != nil {
		t.Fatal(err)
	}
	udp.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := udp.ReadFrom(make([]byte, 1)); err != nil {
		t.Fatalf("IP reuse falsely blocked new occupant: %v", err)
	}
	p.RegisterSandbox("10.11.0.2", sandbox.String())
	if !controller.Blocked(sandbox, "10.11.0.2") {
		t.Fatal("containment missing before queue failure test")
	}
	_ = gate.queue.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("observer did not exit")
	}
	if _, err := mirror.Write([]byte("d")); err != nil {
		t.Fatal(err)
	}
	udp.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := udp.ReadFrom(make([]byte, 1)); err != nil {
		t.Fatalf("dead queue listener did not fail open: %v", err)
	}
	cancel()
}
