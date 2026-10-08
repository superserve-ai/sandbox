package network

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
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
		t.Run(protocol, func(t *testing.T) { testMiningKernelContainment(t, protocol, 2) })
	}
}
func TestMiningKernelAllocatorBounds(t *testing.T) {
	for _, slot := range []int{1, MaxSlots} {
		t.Run(fmt.Sprintf("slot-%d", slot), func(t *testing.T) { testMiningKernelContainment(t, "udp", slot) })
	}
}
func testMiningKernelContainment(t *testing.T, triggerProtocol string, slot int) {
	sourceIP, forgedIP := hostIPForSlot(slot), hostIPForSlot(slot+1)
	gateway := net.ParseIP(sourceIP).To4()
	gateway[3] = 254
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
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: vethNameForSlot(slot)}, PeerName: "mining-peer"}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatal(err)
	}
	defer netlink.LinkDel(veth)
	host, err := netlink.LinkByName(vethNameForSlot(slot))
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
	addAddr(host, gateway.String()+"/24")
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
			addr, _ := netlink.ParseAddr(sourceIP + "/24")
			err = netlink.AddrAdd(link, addr)
			if err == nil {
				forged, _ := netlink.ParseAddr(forgedIP + "/32")
				err = netlink.AddrAdd(link, forged)
			}
		}
		if err == nil {
			err = netlink.LinkSetUp(link)
		}
		if err == nil {
			err = netlink.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Gw: net.ParseIP(gateway.String())})
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
				if network == "tcp" {
					addr, err := net.ResolveTCPAddr("tcp", source)
					if err != nil {
						ch <- result{e: err}
						return
					}
					dialer.LocalAddr = addr
				} else {
					dialer.LocalAddr = &net.UDPAddr{IP: net.ParseIP(source)}
				}
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
	p.RegisterSandbox(forgedIP, victim.String())
	p.RegisterSandbox(sourceIP, sandbox.String())
	teams := &kernelTestTeams{id: team}
	source := NewHostMiningSource(nil, teams, p, "host-test", "boot-test")
	assignments := miningAssignments{sandbox: {TeamPolicy: abuse.TeamPolicy{TeamID: team}, SandboxID: sandbox, HostID: "host-test", HostIP: sourceIP, Assignment: "assignment-one"}}
	assignments[victim] = abuse.SandboxPolicy{TeamPolicy: abuse.TeamPolicy{TeamID: team}, SandboxID: victim, HostID: "host-test", HostIP: forgedIP, Assignment: "assignment-victim"}
	source.cur.Store(&assignments)
	source.curBindings = make(map[uuid.UUID]*EgressRules)
	for id, assignment := range assignments {
		_, source.curBindings[id] = p.miningRegistration(assignment.HostIP)
	}
	if err := gate.SyncAssignments(source); err != nil {
		t.Fatal(err)
	}
	// A policy update must not open a raw-packet attribution gap before refresh.
	p.SetRules(sourceIP, &EgressRules{SandboxID: sandbox.String(), AllowedDomains: []string{"example.com"}})
	if err := gate.UpdateCIDRs([]string{"203.0.113.9/32"}); err != nil {
		t.Fatal(err)
	}
	policy := blocklist.New(&blocklist.Config{CustomCIDRs: []string{"203.0.113.9/32"}}, zerolog.Nop())
	storageBlocked := make(chan struct{})
	storageEntered := make(chan struct{}, 1)
	var releaseStorage sync.Once
	unblockStorage := func() { releaseStorage.Do(func() { close(storageBlocked) }) }
	defer unblockStorage()
	submit := miningSubmitFunc(func(abuse.MiningIncident) error { storageEntered <- struct{}{}; <-storageBlocked; return nil })
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
	// A guest can choose the control service's source port. Prove the
	// negative containment probe is usable before the policy takes effect.
	portProbe, err := dialFrom("tcp", listener.Addr().String(), net.JoinHostPort(sourceIP, "49983"))
	if err != nil {
		t.Fatal(err)
	}
	portPeer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	portProbe.(*net.TCPConn).SetLinger(0)
	portProbe.Close()
	portPeer.Close()
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
		if controller.Blocked(sandbox, sourceIP) {
			t.Fatal("trusted/off/observe traffic triggered containment")
		}
	}
	teams.trusted.Store(false)
	teams.mode.Store(0)
	spoof, err := dialFrom("udp", "203.0.113.9:45454", forgedIP)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := spoof.Write([]byte("forged")); err != nil {
		t.Fatal(err)
	}
	spoof.Close()
	time.Sleep(100 * time.Millisecond)
	if controller.Blocked(victim, forgedIP) || controller.Blocked(sandbox, sourceIP) {
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
	for !controller.Blocked(sandbox, sourceIP) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !controller.Blocked(sandbox, sourceIP) {
		select {
		case err := <-done:
			t.Fatalf("observer stopped: %v", err)
		default:
			t.Fatal("direct mining hit did not contain")
		}
	}
	select {
	case <-storageEntered:
	case <-time.After(time.Second):
		t.Fatal("incident worker did not start")
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
	if conn, err := dialFrom("tcp", listener.Addr().String(), net.JoinHostPort(sourceIP, "49983")); err == nil {
		conn.Close()
		t.Fatal("guest-initiated connection using control source port bypassed containment")
	} else {
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("control-port probe failed without testing containment: %v", err)
		}
	}
	// The host must still be able to open boxd RPCs after containment so the
	// ordinary freeze/snapshot path can pause the guest safely.
	type listenResult struct {
		listener net.Listener
		err      error
	}
	controlReady := make(chan listenResult, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := netns.Set(guest); err != nil {
			controlReady <- listenResult{err: err}
			return
		}
		defer netns.Set(root)
		listener, err := net.Listen("tcp", net.JoinHostPort(sourceIP, "49983"))
		controlReady <- listenResult{listener, err}
	}()
	control := <-controlReady
	if control.err != nil {
		t.Fatal(control.err)
	}
	defer control.listener.Close()
	hostControl, err := net.DialTimeout("tcp", control.listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("containment blocked host control connection: %v", err)
	}
	defer hostControl.Close()
	guestControl, err := control.listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer guestControl.Close()
	hostControl.SetDeadline(time.Now().Add(time.Second))
	guestControl.SetDeadline(time.Now().Add(time.Second))
	if _, err := hostControl.Write([]byte("freeze")); err != nil {
		t.Fatal(err)
	}
	if _, err := guestControl.Read(make([]byte, 6)); err != nil {
		t.Fatal(err)
	}
	if _, err := guestControl.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	if _, err := hostControl.Read(make([]byte, 2)); err != nil {
		t.Fatalf("containment blocked host control reply: %v", err)
	}
	// The set is intentionally still present. A replacement occupant must pass
	// even before background cleanup and while Submit remains blocked. This
	// proves that slow storage does not stall unrelated queued packet verdicts.
	replacement := uuid.New()
	p.RegisterSandbox(sourceIP, replacement.String())
	if _, err := mirror.Write([]byte("c")); err != nil {
		t.Fatal(err)
	}
	udp.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := udp.ReadFrom(make([]byte, 1)); err != nil {
		t.Fatalf("IP reuse falsely blocked new occupant: %v", err)
	}
	p.RegisterSandbox(sourceIP, sandbox.String())
	if controller.Blocked(sandbox, sourceIP) {
		t.Fatal("re-registration revived stale containment before refresh")
	}
	_, source.curBindings[sandbox] = p.miningRegistration(sourceIP)
	if err := gate.SyncAssignments(source); err != nil {
		t.Fatal(err)
	}
	if !controller.Blocked(sandbox, sourceIP) {
		t.Fatal("containment missing before observer shutdown test")
	}
	// Cancellation stops packet decisions, but Run must remain joined to its
	// blocked persistence worker. Its queue must already be unregistered so
	// bypass works before either the write or Run can finish.
	cancel()
	deadline = time.Now().Add(2 * time.Second)
	for {
		if _, err := mirror.Write([]byte("d")); err != nil {
			t.Fatal(err)
		}
		udp.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if _, _, err := udp.ReadFrom(make([]byte, 1)); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("observer shutdown waited for storage before enabling queue bypass")
		}
	}
	select {
	case <-done:
		t.Fatal("observer abandoned its blocked persistence worker")
	default:
	}
	unblockStorage()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("observer cancellation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("observer did not exit after storage completed")
	}
	if controller.Blocked(sandbox, sourceIP) {
		t.Fatal("late storage completion restored cancelled containment")
	}
}
