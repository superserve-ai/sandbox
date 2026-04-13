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

	// Default TCP proxy ports for the egress proxy.
	DefaultHTTPProxyPort  = 19080
	DefaultTLSProxyPort   = 19443
	DefaultOtherProxyPort = 19090
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
	Namespace  string    // Network namespace name.
	TAPDevice  string    // TAP device inside namespace (always "tap0").
	VMIP       string    // VM's internal IP (always VMInternalIP).
	GatewayIP  string    // Gateway inside namespace (always VMGatewayIP).
	HostIP     string    // Host-side IP to reach this VM.
	MACAddress string
	Firewall   *Firewall // nftables firewall for this VM (inside namespace).
}

// ---------------------------------------------------------------------------
// Manager
// ---------------------------------------------------------------------------

// MaxSlots is the maximum number of concurrent VMs. Limited by the IP scheme:
// hostIP uses 10.11.0.0/16 (one IP per VM), veth pairs use 10.12.0.0/16 (two IPs per VM).
// This supports up to ~32K concurrent VMs per node — hardware (RAM/CPU) is the real limit.
const MaxSlots = 32000

// ErrNoSlots is returned when no network slots are available.
var ErrNoSlots = fmt.Errorf("no available network slots (max %d concurrent VMs)", MaxSlots)

type Manager struct {
	hostInterface string
	log           zerolog.Logger

	mu        sync.Mutex
	devices   map[string]*VMNetInfo
	freeSlots []int // recycled slot indices
	nextSlot  int   // next new slot (used when freeSlots is empty)

	// Host-level nftables firewall (FORWARD + MASQUERADE + MSS clamping).
	hostFW *HostFirewall

	// TCP egress proxy — receives per-sandbox rule updates and cleanup.
	egressProxy *EgressProxy

	// Pre-allocated network slot pool (nil = disabled, on-demand setup).
	pool *Pool

	// Proxy ports for the TCP egress proxy.
	httpProxyPort  uint16
	tlsProxyPort   uint16
	otherProxyPort uint16
}

// SetEgressProxy attaches the TCP egress proxy so the manager can remove
// per-sandbox rules on cleanup. Must be called before any VMs are created.
func (m *Manager) SetEgressProxy(p *EgressProxy) {
	m.egressProxy = p
}

func NewManager(ctx context.Context, hostInterface string, log zerolog.Logger) (*Manager, error) {
	if err := enableIPForward(ctx); err != nil {
		return nil, err
	}

	hostFW, err := NewHostFirewall(hostInterface)
	if err != nil {
		return nil, fmt.Errorf("init host firewall: %w", err)
	}

	return &Manager{
		hostInterface:  hostInterface,
		log:            log.With().Str("component", "network").Logger(),
		devices:        make(map[string]*VMNetInfo),
		nextSlot:       1,
		hostFW:         hostFW,
		httpProxyPort:  DefaultHTTPProxyPort,
		tlsProxyPort:   DefaultTLSProxyPort,
		otherProxyPort: DefaultOtherProxyPort,
	}, nil
}

// Close tears down the host firewall. Should be called on VMD shutdown.
func (m *Manager) Close() error {
	if m.hostFW != nil {
		return m.hostFW.Close()
	}
	return nil
}

// SetProxyPorts overrides the default TCP proxy ports. Must be called before any VMs are created.
func (m *Manager) SetProxyPorts(http, tls, other uint16) {
	m.httpProxyPort = http
	m.tlsProxyPort = tls
	m.otherProxyPort = other
}

// SetupVM creates an isolated network namespace for a VM.
//
// Network topology:
//
//	Host:      veth-<idx> (10.12.x.y/31)  ←→  eth0 (10.12.x.y/31) :Namespace
//	Host:      route hostIP/32 via vpeerIP
//	Namespace: tap0 (169.254.0.22/30)  ←→  VM eth0 (169.254.0.21)
//	Namespace: nftables SNAT 169.254.0.21 → hostIP (outbound)
//	Namespace: nftables DNAT hostIP → 169.254.0.21 (inbound)
//
// IP addressing uses /16 subnets to support thousands of concurrent VMs:
//   - hostIP:  10.11.<idx/256>.<idx%256>  (one per VM)
//   - vpeerIP: 10.12.<(idx*2)/256>.<(idx*2)%256>  (namespace side of veth)
//   - vethIP:  10.12.<(idx*2+1)/256>.<(idx*2+1)%256>  (host side of veth)
//
// The host reaches the VM at hostIP:<port>. NAT inside the namespace
// translates to 169.254.0.21:<port>. No guest IP reconfig needed.
func (m *Manager) SetupVM(ctx context.Context, vmID string, cfg *Config) (*VMNetInfo, error) {
	// Try the pre-allocated pool first (microseconds instead of ~10-30ms).
	if m.pool != nil {
		if info := m.pool.Claim(vmID); info != nil {
			return info, nil
		}
		m.log.Debug().Str("vm_id", vmID).Msg("network pool empty, falling back to on-demand setup")
	}

	m.mu.Lock()
	var idx int
	if len(m.freeSlots) > 0 {
		idx = m.freeSlots[len(m.freeSlots)-1]
		m.freeSlots = m.freeSlots[:len(m.freeSlots)-1]
	} else {
		if m.nextSlot > MaxSlots {
			m.mu.Unlock()
			return nil, ErrNoSlots
		}
		idx = m.nextSlot
		m.nextSlot++
	}
	m.mu.Unlock()

	info, vethName, err := m.setupSlot(ctx, idx)
	if err != nil {
		m.mu.Lock()
		m.freeSlots = append(m.freeSlots, idx)
		m.mu.Unlock()
		return nil, err
	}

	// Host-level nftables rules require the vmID.
	hostCIDR := fmt.Sprintf("%s/32", info.HostIP)
	if err := m.hostFW.AddVM(vmID, vethName, hostCIDR); err != nil {
		m.cleanupFull(info.Namespace, vethName)
		return nil, fmt.Errorf("add host firewall rules: %w", err)
	}

	m.mu.Lock()
	m.devices[vmID] = info
	m.mu.Unlock()

	m.log.Info().
		Str("vm_id", vmID).
		Str("namespace", info.Namespace).
		Str("host_ip", info.HostIP).
		Msg("network namespace created")

	return info, nil
}

// setupSlot runs the expensive network setup (namespace, veth, TAP,
// nftables, routing) for a single slot index. Used by both SetupVM
// (on-demand) and Pool (pre-allocation). Does NOT add host-level
// firewall rules — that requires a vmID and is done by the caller.
func (m *Manager) setupSlot(ctx context.Context, idx int) (*VMNetInfo, string, error) {
	hostIP := fmt.Sprintf("10.11.%d.%d", idx/256, idx%256)
	vpeerIP := fmt.Sprintf("10.12.%d.%d", (idx*2)/256, (idx*2)%256)
	vethIP := fmt.Sprintf("10.12.%d.%d", (idx*2+1)/256, (idx*2+1)%256)
	nsName := fmt.Sprintf("ns-%d", idx)
	vethName := fmt.Sprintf("veth-%d", idx)
	vpeerName := "eth0"
	hostCIDR := fmt.Sprintf("%s/32", hostIP)

	if err := run(ctx, "ip", "netns", "add", nsName); err != nil {
		return nil, "", fmt.Errorf("create namespace: %w", err)
	}

	if err := nsRun(ctx, nsName, "ip", "link", "add", vethName, "type", "veth", "peer", "name", vpeerName); err != nil {
		m.removeNS(nsName)
		return nil, "", fmt.Errorf("create veth pair: %w", err)
	}

	if err := nsRun(ctx, nsName, "ip", "link", "set", vpeerName, "up"); err != nil {
		m.removeNS(nsName)
		return nil, "", fmt.Errorf("bring up vpeer: %w", err)
	}
	if err := nsRun(ctx, nsName, "ip", "link", "set", vpeerName, "mtu", ifaceMTU); err != nil {
		m.removeNS(nsName)
		return nil, "", fmt.Errorf("set vpeer MTU: %w", err)
	}
	if err := nsRun(ctx, nsName, "ip", "addr", "add", vpeerIP+"/31", "dev", vpeerName); err != nil {
		m.removeNS(nsName)
		return nil, "", fmt.Errorf("assign vpeer IP: %w", err)
	}

	if err := nsRun(ctx, nsName, "ip", "link", "set", vethName, "netns", "1"); err != nil {
		m.removeNS(nsName)
		return nil, "", fmt.Errorf("move veth to host: %w", err)
	}

	if err := run(ctx, "ip", "link", "set", vethName, "up"); err != nil {
		m.removeNS(nsName)
		return nil, "", fmt.Errorf("bring up veth: %w", err)
	}
	if err := run(ctx, "ip", "link", "set", vethName, "mtu", ifaceMTU); err != nil {
		m.removeNS(nsName)
		return nil, "", fmt.Errorf("set veth MTU: %w", err)
	}
	if err := run(ctx, "ip", "addr", "add", vethIP+"/31", "dev", vethName); err != nil {
		m.removeNS(nsName)
		return nil, "", fmt.Errorf("assign veth IP: %w", err)
	}

	if err := nsRun(ctx, nsName, "ip", "tuntap", "add", "dev", TAPName, "mode", "tap"); err != nil {
		m.cleanupFull(nsName, vethName)
		return nil, "", fmt.Errorf("create TAP: %w", err)
	}
	if err := nsRun(ctx, nsName, "ip", "link", "set", TAPName, "up"); err != nil {
		m.cleanupFull(nsName, vethName)
		return nil, "", fmt.Errorf("bring up TAP: %w", err)
	}
	if err := nsRun(ctx, nsName, "ip", "link", "set", TAPName, "mtu", ifaceMTU); err != nil {
		m.cleanupFull(nsName, vethName)
		return nil, "", fmt.Errorf("set TAP MTU: %w", err)
	}
	if err := nsRun(ctx, nsName, "ip", "addr", "add", tapCIDR, "dev", TAPName); err != nil {
		m.cleanupFull(nsName, vethName)
		return nil, "", fmt.Errorf("assign TAP IP: %w", err)
	}

	_ = nsRun(ctx, nsName, "ip", "link", "set", "lo", "up")

	if err := nsRun(ctx, nsName, "ip", "route", "add", "default", "via", vethIP); err != nil {
		m.cleanupFull(nsName, vethName)
		return nil, "", fmt.Errorf("add default route in ns: %w", err)
	}

	var fw *Firewall
	if err := nsExecGo(nsName, func() error {
		var fwErr error
		fw, fwErr = NewFirewall(FirewallConfig{
			TAPInterface:   TAPName,
			VethPeer:       vpeerName,
			VMIP:           VMInternalIP,
			HostIP:         hostIP,
			GatewayIP:      VMGatewayIP,
			HTTPProxyPort:  m.httpProxyPort,
			TLSProxyPort:   m.tlsProxyPort,
			OtherProxyPort: m.otherProxyPort,
		})
		return fwErr
	}); err != nil {
		m.cleanupFull(nsName, vethName)
		return nil, "", fmt.Errorf("init firewall: %w", err)
	}

	if err := run(ctx, "ip", "route", "add", hostCIDR, "via", vpeerIP, "dev", vethName); err != nil {
		m.log.Debug().Err(err).Str("ns", nsName).Msg("host route (may already exist)")
	}

	mac := fmt.Sprintf("AA:FC:00:%02X:%02X:%02X", 0, idx/256, idx%256)

	info := &VMNetInfo{
		Namespace:  nsName,
		TAPDevice:  TAPName,
		VMIP:       VMInternalIP,
		GatewayIP:  VMGatewayIP,
		HostIP:     hostIP,
		MACAddress: mac,
		Firewall:   fw,
	}

	return info, vethName, nil
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

	if !ok {
		return
	}

	// Parse slot index once.
	var idx int
	fmt.Sscanf(info.Namespace, "ns-%d", &idx)

	// Recycle the slot index for reuse.
	m.mu.Lock()
	m.freeSlots = append(m.freeSlots, idx)
	m.mu.Unlock()

	log := m.log.With().Str("vm_id", vmID).Logger()

	// Close nftables firewall inside namespace (kernel removes table + all rules).
	if info.Firewall != nil {
		if err := info.Firewall.Close(); err != nil {
			log.Warn().Err(err).Msg("error closing namespace firewall")
		}
	}

	// Remove host-level nftables rules for this VM.
	if err := m.hostFW.RemoveVM(vmID); err != nil {
		log.Warn().Err(err).Msg("error removing host firewall rules")
	}

	// Remove per-sandbox rules and connection limiter entries from the egress proxy.
	if m.egressProxy != nil {
		m.egressProxy.RemoveRules(info.HostIP)
	}

	vethName := fmt.Sprintf("veth-%d", idx)
	vpeerIP := fmt.Sprintf("10.12.%d.%d", (idx*2)/256, (idx*2)%256)
	hostCIDR := fmt.Sprintf("%s/32", info.HostIP)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Remove host route.
	_ = run(ctx, "ip", "route", "del", hostCIDR, "via", vpeerIP, "dev", vethName)

	// Delete veth (also removes peer in namespace).
	_ = run(ctx, "ip", "link", "del", vethName)

	// Delete namespace.
	_ = run(ctx, "ip", "netns", "del", info.Namespace)

	log.Info().Str("namespace", info.Namespace).Msg("network namespace cleaned up")
}

// UpdateFirewallRules atomically replaces the user allow/deny sets for a VM's firewall.
func (m *Manager) UpdateFirewallRules(vmID string, allowedCIDRs, deniedCIDRs []string) error {
	m.mu.Lock()
	info, ok := m.devices[vmID]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("VM %q not found", vmID)
	}
	if info.Firewall == nil {
		return fmt.Errorf("VM %q has no firewall", vmID)
	}
	return info.Firewall.ReplaceUserRules(allowedCIDRs, deniedCIDRs)
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
	if ctx == nil {
		ctx = context.Background()
	}
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
