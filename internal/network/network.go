package network

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// ---------------------------------------------------------------------------
// Fixed IPs — same for every VM, namespace isolation prevents collision
// ---------------------------------------------------------------------------

const (
	// VMInternalIP is the IP every VM uses inside its namespace.
	VMInternalIP = "169.254.0.21"
	// VMGatewayIP is the TAP device IP inside the namespace (gateway for the VM).
	VMGatewayIP = "169.254.0.22"
	// TAPName is the TAP device name inside each namespace.
	TAPName = "tap0"

	tapCIDR = VMGatewayIP + "/30"
	tapMAC  = "02:FC:00:00:00:05"

	// ifaceMTU is the MTU for all virtual interfaces (tap, veth).
	// GCP VPC default MTU is 1460. All interfaces in the packet path must
	// match to avoid silent packet drops during TLS handshakes. See:
	// https://cloud.google.com/vpc/docs/mtu
	ifaceMTU = "1460"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type Config struct {
	HostInterface string
	SubnetCIDR    string
	GatewayIP     string
	EnableNAT     bool
}

// VMNetInfo holds the network resources for a single VM.
type VMNetInfo struct {
	Namespace  string // Network namespace name.
	TAPDevice  string // TAP device inside namespace (always "tap0").
	VMIP       string // VM's internal IP (always VMInternalIP).
	GatewayIP  string // Gateway inside namespace (always VMGatewayIP).
	HostIP     string // Host-side IP to reach this VM.
	MACAddress string
}

// ---------------------------------------------------------------------------
// Manager
// ---------------------------------------------------------------------------

// MaxSlots is the maximum number of concurrent VMs. Limited by the IP scheme:
// hostIP uses 10.11.0.0/16 (one IP per VM), veth pairs use 10.12.0.0/16 (two IPs per VM).
// This supports up to ~32K concurrent VMs per node — hardware (RAM/CPU) is the real limit.
const MaxSlots = 32000

type Manager struct {
	hostInterface string
	log           zerolog.Logger

	mu        sync.Mutex
	devices   map[string]*VMNetInfo
	freeSlots []int // recycled slot indices
	nextSlot  int   // next new slot (used when freeSlots is empty)
}

func NewManager(hostInterface string, log zerolog.Logger) *Manager {
	return &Manager{
		hostInterface: hostInterface,
		log:           log.With().Str("component", "network").Logger(),
		devices:       make(map[string]*VMNetInfo),
		nextSlot:      1,
	}
}

// SetupVM creates an isolated network namespace for a VM.
//
// Network topology:
//
//	Host:      veth-<idx> (10.12.x.y/31)  ←→  eth0 (10.12.x.y/31) :Namespace
//	Host:      route hostIP/32 via vpeerIP
//	Namespace: tap0 (169.254.0.22/30)  ←→  VM eth0 (169.254.0.21)
//	Namespace: SNAT 169.254.0.21 → hostIP (outbound)
//	Namespace: DNAT hostIP → 169.254.0.21 (inbound)
//
// IP addressing uses /16 subnets to support thousands of concurrent VMs:
//   - hostIP:  10.11.<idx/256>.<idx%256>  (one per VM)
//   - vpeerIP: 10.12.<(idx*2)/256>.<(idx*2)%256>  (namespace side of veth)
//   - vethIP:  10.12.<(idx*2+1)/256>.<(idx*2+1)%256>  (host side of veth)
//
// The host reaches the VM at hostIP:<port>. NAT inside the namespace
// translates to 169.254.0.21:<port>. No guest IP reconfig needed.
func (m *Manager) SetupVM(ctx context.Context, vmID string, cfg *Config) (*VMNetInfo, error) {
	m.mu.Lock()
	var idx int
	if len(m.freeSlots) > 0 {
		idx = m.freeSlots[len(m.freeSlots)-1]
		m.freeSlots = m.freeSlots[:len(m.freeSlots)-1]
	} else {
		if m.nextSlot > MaxSlots {
			m.mu.Unlock()
			return nil, fmt.Errorf("no available network slots (max %d concurrent VMs)", MaxSlots)
		}
		idx = m.nextSlot
		m.nextSlot++
	}
	m.mu.Unlock()

	log := m.log.With().Str("vm_id", vmID).Int("slot", idx).Logger()

	// Calculate IPs for this slot using /16 subnets.
	hostIP := fmt.Sprintf("10.11.%d.%d", idx/256, idx%256)
	vpeerIP := fmt.Sprintf("10.12.%d.%d", (idx*2)/256, (idx*2)%256)
	vethIP := fmt.Sprintf("10.12.%d.%d", (idx*2+1)/256, (idx*2+1)%256)
	nsName := fmt.Sprintf("ns-%d", idx)
	vethName := fmt.Sprintf("veth-%d", idx)
	vpeerName := "eth0"
	hostCIDR := fmt.Sprintf("%s/32", hostIP)

	hostIface := m.hostInterface
	if cfg != nil && cfg.HostInterface != "" {
		hostIface = cfg.HostInterface
	}

	// 1. Create network namespace.
	if err := run(ctx, "ip", "netns", "add", nsName); err != nil {
		return nil, fmt.Errorf("create namespace: %w", err)
	}

	// 2. Create veth pair inside the namespace.
	if err := nsRun(ctx, nsName, "ip", "link", "add", vethName, "type", "veth", "peer", "name", vpeerName); err != nil {
		m.removeNS(nsName)
		return nil, fmt.Errorf("create veth pair: %w", err)
	}

	// 3. Configure vpeer (stays in namespace).
	if err := nsRun(ctx, nsName, "ip", "link", "set", vpeerName, "up"); err != nil {
		m.removeNS(nsName)
		return nil, fmt.Errorf("bring up vpeer: %w", err)
	}
	if err := nsRun(ctx, nsName, "ip", "link", "set", vpeerName, "mtu", ifaceMTU); err != nil {
		m.removeNS(nsName)
		return nil, fmt.Errorf("set vpeer MTU: %w", err)
	}
	if err := nsRun(ctx, nsName, "ip", "addr", "add", vpeerIP+"/31", "dev", vpeerName); err != nil {
		m.removeNS(nsName)
		return nil, fmt.Errorf("assign vpeer IP: %w", err)
	}

	// 4. Move veth to host namespace.
	if err := nsRun(ctx, nsName, "ip", "link", "set", vethName, "netns", "1"); err != nil {
		m.removeNS(nsName)
		return nil, fmt.Errorf("move veth to host: %w", err)
	}

	// 5. Configure veth on host side.
	if err := run(ctx, "ip", "link", "set", vethName, "up"); err != nil {
		m.removeNS(nsName)
		return nil, fmt.Errorf("bring up veth: %w", err)
	}
	if err := run(ctx, "ip", "link", "set", vethName, "mtu", ifaceMTU); err != nil {
		m.removeNS(nsName)
		return nil, fmt.Errorf("set veth MTU: %w", err)
	}
	if err := run(ctx, "ip", "addr", "add", vethIP+"/31", "dev", vethName); err != nil {
		m.removeNS(nsName)
		return nil, fmt.Errorf("assign veth IP: %w", err)
	}

	// 6. Create TAP device inside namespace.
	if err := nsRun(ctx, nsName, "ip", "tuntap", "add", "dev", TAPName, "mode", "tap"); err != nil {
		m.cleanupFull(nsName, vethName)
		return nil, fmt.Errorf("create TAP: %w", err)
	}
	if err := nsRun(ctx, nsName, "ip", "link", "set", TAPName, "up"); err != nil {
		m.cleanupFull(nsName, vethName)
		return nil, fmt.Errorf("bring up TAP: %w", err)
	}
	if err := nsRun(ctx, nsName, "ip", "link", "set", TAPName, "mtu", ifaceMTU); err != nil {
		m.cleanupFull(nsName, vethName)
		return nil, fmt.Errorf("set TAP MTU: %w", err)
	}
	if err := nsRun(ctx, nsName, "ip", "addr", "add", tapCIDR, "dev", TAPName); err != nil {
		m.cleanupFull(nsName, vethName)
		return nil, fmt.Errorf("assign TAP IP: %w", err)
	}

	// 7. Bring up loopback in namespace.
	_ = nsRun(ctx, nsName, "ip", "link", "set", "lo", "up")

	// 8. Default route in namespace → via veth IP (on host side).
	if err := nsRun(ctx, nsName, "ip", "route", "add", "default", "via", vethIP); err != nil {
		m.cleanupFull(nsName, vethName)
		return nil, fmt.Errorf("add default route in ns: %w", err)
	}

	// 9. NAT inside namespace: SNAT outbound, DNAT inbound.
	if err := nsRun(ctx, nsName, "iptables", "--wait", "10", "-t", "nat", "-A", "POSTROUTING",
		"-o", vpeerName, "-s", VMInternalIP, "-j", "SNAT", "--to", hostIP); err != nil {
		m.cleanupFull(nsName, vethName)
		return nil, fmt.Errorf("SNAT rule: %w", err)
	}
	if err := nsRun(ctx, nsName, "iptables", "--wait", "10", "-t", "nat", "-A", "PREROUTING",
		"-i", vpeerName, "-d", hostIP, "-j", "DNAT", "--to", VMInternalIP); err != nil {
		m.cleanupFull(nsName, vethName)
		return nil, fmt.Errorf("DNAT rule: %w", err)
	}

	// 10. Host routing: traffic to hostIP goes via vpeer through the veth.
	if err := run(ctx, "ip", "route", "add", hostCIDR, "via", vpeerIP, "dev", vethName); err != nil {
		log.Debug().Err(err).Msg("host route (may already exist)")
	}

	// 10a. TCP MSS clamping inside namespace — prevents TLS handshake hangs
	// caused by MTU mismatch (GCP VPC MTU 1460 vs default 1500). Clamps the
	// MSS in SYN packets so the remote server never sends packets larger than
	// the path MTU. See: https://cloud.google.com/vpc/docs/mtu
	_ = nsRun(ctx, nsName, "iptables", "--wait", "10", "-t", "mangle", "-A", "FORWARD",
		"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS", "--clamp-mss-to-pmtu")
	_ = nsRun(ctx, nsName, "iptables", "--wait", "10", "-t", "mangle", "-A", "POSTROUTING",
		"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS", "--clamp-mss-to-pmtu")

	// 11. Host forwarding + NAT for outbound internet.
	_ = run(ctx, "sysctl", "-w", "net.ipv4.ip_forward=1")
	_ = run(ctx, "iptables", "--wait", "10", "-A", "FORWARD", "-i", vethName, "-o", hostIface, "-j", "ACCEPT")
	_ = run(ctx, "iptables", "--wait", "10", "-A", "FORWARD", "-i", hostIface, "-o", vethName, "-j", "ACCEPT")
	_ = run(ctx, "iptables", "--wait", "10", "-t", "nat", "-A", "POSTROUTING", "-s", hostCIDR, "-o", hostIface, "-j", "MASQUERADE")

	// 11a. Host-level MSS clamping for traffic forwarded to/from VMs.
	_ = run(ctx, "iptables", "--wait", "10", "-t", "mangle", "-A", "FORWARD",
		"-o", hostIface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS", "--clamp-mss-to-pmtu")

	mac := fmt.Sprintf("AA:FC:00:%02X:%02X:%02X", 0, idx/256, idx%256)

	info := &VMNetInfo{
		Namespace:  nsName,
		TAPDevice:  TAPName,
		VMIP:       VMInternalIP,
		GatewayIP:  VMGatewayIP,
		HostIP:     hostIP,
		MACAddress: mac,
	}

	m.mu.Lock()
	m.devices[vmID] = info
	m.mu.Unlock()

	log.Info().
		Str("namespace", nsName).
		Str("host_ip", hostIP).
		Str("vm_ip", VMInternalIP).
		Msg("network namespace created")

	return info, nil
}

func (m *Manager) GetVMNetInfo(vmID string) *VMNetInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	info, ok := m.devices[vmID]
	if !ok {
		return nil
	}
	cp := *info
	return &cp
}

func (m *Manager) CleanupVM(vmID string) {
	m.mu.Lock()
	info, ok := m.devices[vmID]
	if ok {
		delete(m.devices, vmID)
	}
	m.mu.Unlock()

	// Recycle the slot index for reuse.
	if ok {
		var idx int
		fmt.Sscanf(info.Namespace, "ns-%d", &idx)
		m.mu.Lock()
		m.freeSlots = append(m.freeSlots, idx)
		m.mu.Unlock()
	}

	if !ok {
		return
	}

	log := m.log.With().Str("vm_id", vmID).Logger()

	// Find the slot index from the namespace name.
	var idx int
	fmt.Sscanf(info.Namespace, "ns-%d", &idx)
	vethName := fmt.Sprintf("veth-%d", idx)

	// Clean up host iptables rules.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	hostCIDR := fmt.Sprintf("%s/32", info.HostIP)
	vpeerIP := fmt.Sprintf("10.12.%d.%d", (idx*2)/256, (idx*2)%256)

	_ = run(ctx, "iptables", "--wait", "10", "-D", "FORWARD", "-i", vethName, "-o", m.hostInterface, "-j", "ACCEPT")
	_ = run(ctx, "iptables", "--wait", "10", "-D", "FORWARD", "-i", m.hostInterface, "-o", vethName, "-j", "ACCEPT")
	_ = run(ctx, "iptables", "--wait", "10", "-t", "nat", "-D", "POSTROUTING", "-s", hostCIDR, "-o", m.hostInterface, "-j", "MASQUERADE")
	_ = run(ctx, "ip", "route", "del", hostCIDR, "via", vpeerIP, "dev", vethName)

	// Delete veth (also removes peer in namespace).
	_ = run(ctx, "ip", "link", "del", vethName)

	// Delete namespace.
	_ = run(ctx, "ip", "netns", "del", info.Namespace)

	log.Info().Str("namespace", info.Namespace).Msg("network namespace cleaned up")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (m *Manager) removeNS(nsName string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = run(ctx, "ip", "netns", "del", nsName)
}

func (m *Manager) cleanupFull(nsName, vethName string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = run(ctx, "ip", "link", "del", vethName)
	_ = run(ctx, "ip", "netns", "del", nsName)
}

func run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v: %s: %w", name, args, string(out), err)
	}
	return nil
}

func nsRun(ctx context.Context, ns string, name string, args ...string) error {
	fullArgs := append([]string{"netns", "exec", ns, name}, args...)
	return run(ctx, "ip", fullArgs...)
}
