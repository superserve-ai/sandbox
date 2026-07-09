package network

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
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
	Namespace  string // Network namespace name.
	TAPDevice  string // TAP device inside namespace (always "tap0").
	VMIP       string // VM's internal IP (always VMInternalIP).
	GatewayIP  string // Gateway inside namespace (always VMGatewayIP).
	HostIP     string // Host-side IP to reach this VM.
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
	freeSlots []int // recycled slot indices, guaranteed absent from slotOwner
	nextSlot  int   // next new slot (used when freeSlots is empty)

	// slotOwner is the single source of truth for slot allocation AND identity:
	// slotOwner[idx] == the current owner of slot index idx, one of
	//   - a VM/record vmID   (a live VM, or a record reserving its index)
	//   - poolOwner          (a warm/mid-build pool slot not yet handed to a VM)
	//   - teardownOwner      (a slot being torn down; held so no one re-claims it)
	// An index is free (claimable) iff it has NO entry.
	//
	// Identity is load-bearing, not decoration: a release/teardown acts ONLY when
	// the caller still owns the index (releaseIfOwned), so a stale cleanup for an
	// old vmID cannot tear down or free a slot the pool/another VM has since
	// reused. And because a warm pool slot's index stays owned for its whole life
	// (build → warm → claimed), claimSlotIndex can never rebuild the same index
	// into a second warm slot — the root guarantee against slot duplication.
	//
	// The transition helpers below are the ONLY way slotOwner/freeSlots change;
	// every slot path must route through them so ownership can never be dropped
	// (leak) or duplicated (double hand-out).
	slotOwner map[int]string

	// TCP egress proxy — receives per-sandbox rule updates and cleanup.
	egressProxy *EgressProxy

	// Pre-allocated network slot pool (nil = disabled, on-demand setup).
	pool *Pool

	// Proxy ports for the TCP egress proxy.
	httpProxyPort  uint16
	tlsProxyPort   uint16
	otherProxyPort uint16

	// Sandbox-facing address for the secretsproxy daemon. Zero port disables the REDIRECT.
	secretsProxyDst  string
	secretsProxyPort uint16

	// blockedEgressPorts are dropped in the host FORWARD chain for all
	// sandbox traffic. Sourced from the operator blocklist config.
	blockedEgressPorts []uint16

	// dnsRedirectPort, when non-zero, transparently redirects all sandbox
	// DNS (TCP and UDP dport 53) to this host port, where the operator
	// runs a resolver. Zero leaves guest DNS untouched.
	dnsRedirectPort uint16

	// ownsEgressPortChain marks this manager as the sole owner of the
	// shared SANDBOX_EGRESS_PORTS chain. Only the vmd daemon sets it;
	// auxiliary managers (template-builder) must not flush the chain or
	// they would wipe the daemon's port drops on every build.
	ownsEgressPortChain bool
}

// registerEgress attributes a VM's flows so logging covers every sandbox,
// not only those with explicit egress rules.
func (m *Manager) registerEgress(vmID string, info *VMNetInfo) {
	if m.egressProxy != nil && info != nil {
		m.egressProxy.RegisterSandbox(info.HostIP, vmID)
	}
}

// SetEgressProxy attaches the TCP egress proxy so the manager can remove
// per-sandbox rules on cleanup. Must be called before any VMs are created.
func (m *Manager) SetEgressProxy(p *EgressProxy) {
	m.egressProxy = p
}

// ManagerOption configures optional Manager behavior.
type ManagerOption func(*Manager)

// WithStartSlot sets the starting slot index for network allocation.
// Use to avoid collision when multiple processes manage VMs on the
// same host (e.g. vmd uses 1-100, template-builder uses 200+).
func WithStartSlot(idx int) ManagerOption {
	return func(m *Manager) { m.nextSlot = idx }
}

// WithHTTPProxyPort sets the HTTP proxy port for egress REDIRECT rules.
// Pass 0 to disable REDIRECT (e.g. for build VMs that don't need
// egress domain filtering).
func WithHTTPProxyPort(port uint16) ManagerOption {
	return func(m *Manager) { m.httpProxyPort = port }
}

// WithSecretsProxyAddr sets the sandbox-facing address for the secretsproxy
// daemon. Port 0 disables the REDIRECT.
func WithSecretsProxyAddr(host string, port uint16) ManagerOption {
	return func(m *Manager) {
		m.secretsProxyDst = host
		m.secretsProxyPort = port
	}
}

// WithBlockedEgressPorts sets destination ports dropped in the host FORWARD
// chain for all sandbox traffic (TCP and UDP). Ports come from the operator
// blocklist config.
func WithBlockedEgressPorts(ports []uint16) ManagerOption {
	return func(m *Manager) { m.blockedEgressPorts = ports }
}

// WithDNSRedirectPort redirects all sandbox DNS traffic (TCP and UDP port
// 53) to the given port on the host, regardless of which nameserver the
// guest has configured. The operator is responsible for running a resolver
// on that port; with the redirect active, encrypted-DNS bypass on port 853
// (DoT/DoQ) is dropped. Pass 0 (default) to leave guest DNS untouched.
func WithDNSRedirectPort(port uint16) ManagerOption {
	return func(m *Manager) { m.dnsRedirectPort = port }
}

// WithEgressPortChainOwner marks this manager as the owner of the shared
// SANDBOX_EGRESS_PORTS chain, so it reconciles (flushes and rebuilds) that
// chain on startup. Set this only for the vmd daemon — auxiliary managers
// (e.g. template-builder) must leave the chain alone so concurrent builds
// don't wipe the daemon's port drops.
func WithEgressPortChainOwner() ManagerOption {
	return func(m *Manager) { m.ownsEgressPortChain = true }
}

func NewManager(ctx context.Context, hostInterface string, log zerolog.Logger, opts ...ManagerOption) (*Manager, error) {
	if err := enableIPForward(ctx); err != nil {
		return nil, err
	}

	mgr := &Manager{
		hostInterface:  hostInterface,
		log:            log.With().Str("component", "network").Logger(),
		devices:        make(map[string]*VMNetInfo),
		slotOwner:      make(map[int]string),
		nextSlot:       1,
		httpProxyPort:  DefaultHTTPProxyPort,
		tlsProxyPort:   DefaultTLSProxyPort,
		otherProxyPort: DefaultOtherProxyPort,
	}
	for _, opt := range opts {
		opt(mgr)
	}

	if err := installHostFirewall(hostInterface, mgr.httpProxyPort, mgr.tlsProxyPort, mgr.dnsRedirectPort, mgr.secretsProxyDst, mgr.secretsProxyPort, mgr.blockedEgressPorts, mgr.ownsEgressPortChain, log.With().Str("component", "host_fw").Logger()); err != nil {
		return nil, fmt.Errorf("install host firewall: %w", err)
	}

	return mgr, nil
}

// Close is retained for caller symmetry. Host iptables rules persist in the
// kernel across vmd restarts; the next installHostFirewall reinstalls them.
func (m *Manager) Close() error {
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
	// Try the pre-allocated pool first; fall back to on-demand setup.
	if m.pool != nil {
		if info := m.pool.Claim(vmID); info != nil {
			m.registerEgress(vmID, info)
			return info, nil
		}
		m.log.Info().Str("vm_id", vmID).Msg("network pool empty, falling back to on-demand setup")
	}

	idx, err := m.claimSlotIndex(vmID)
	if err != nil {
		return nil, err
	}

	info, _, err := m.setupSlot(ctx, idx)
	if err != nil {
		// Build failed — release the index (we are its sole owner) so it isn't
		// leaked. releaseIfOwned keeps it correct even if state moved under us.
		m.releaseIfOwned(idx, vmID)
		return nil, err
	}

	m.mu.Lock()
	m.devices[vmID] = info
	m.mu.Unlock()
	m.registerEgress(vmID, info)

	m.log.Info().
		Str("vm_id", vmID).
		Str("namespace", info.Namespace).
		Str("host_ip", info.HostIP).
		Msg("network namespace created")

	return info, nil
}

// hostIPForSlot returns the host-side IP for a given slot index. The full
// range across all valid idx values must stay within hostfw.go's vmIPRange.
func hostIPForSlot(idx int) string {
	return fmt.Sprintf("10.11.%d.%d", idx/256, idx%256)
}

// setupSlot runs the expensive network setup (namespace, veth, TAP,
// nftables, routing) for a single slot index. Used by both SetupVM
// (on-demand) and Pool (pre-allocation).
func (m *Manager) setupSlot(ctx context.Context, idx int) (*VMNetInfo, string, error) {
	// Ownership of idx is NOT touched here: claimSlotIndex owns it before this
	// runs (pool/on-demand), and record paths reserve it. On success the slot is
	// live and stays owned; on failure the caller releases idx (freeSlot).
	hostIP := hostIPForSlot(idx)
	vpeerIP := fmt.Sprintf("10.12.%d.%d", (idx*2)/256, (idx*2)%256)
	vethIP := fmt.Sprintf("10.12.%d.%d", (idx*2+1)/256, (idx*2+1)%256)
	nsName := fmt.Sprintf("ns-%d", idx)
	vethName := fmt.Sprintf("veth-%d", idx)
	vpeerName := "eth0"
	hostCIDR := fmt.Sprintf("%s/32", hostIP)

	// If the namespace already exists, this slot is in use by a
	// running sandbox from a previous VMD lifetime. Skip it — the
	// pool caller will retry with the next slot index.
	if nsExists(nsName) {
		return nil, "", fmt.Errorf("namespace %s already exists (slot in use)", nsName)
	}

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
			TAPInterface: TAPName,
			VethPeer:     vpeerName,
			VMIP:         VMInternalIP,
			HostIP:       hostIP,
			GatewayIP:    VMGatewayIP,
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

	idx, parsed := slotFromNamespace(info.Namespace)
	if !parsed {
		m.log.Warn().Str("vm_id", vmID).Str("namespace", info.Namespace).Msg("cleanup: unparseable namespace — skipping slot reclaim")
		return
	}
	vethName := fmt.Sprintf("veth-%d", idx)

	// Remove per-sandbox egress proxy rules.
	if m.egressProxy != nil {
		m.egressProxy.RemoveRules(info.HostIP)
	}

	// Recycle the slot into the pool — namespace, veth, TAP, and base
	// nftables stay configured; the next Claim re-adds vmID-specific
	// rules. Skipped when info.Firewall is nil (reattached VM whose
	// in-ns handle couldn't be rebound) — pooling would let the next
	// Claim silently lose per-VM egress filtering. Return transfers ownership
	// from this VM back to the pool.
	if m.pool != nil && info.Firewall != nil {
		_ = info.Firewall.ReplaceUserRules(nil, nil)
		m.pool.Return(&preallocSlot{idx: idx, info: info, vethName: vethName})
		return
	}

	// No pool — full teardown. Release the index only if this VM still owns it.
	m.releaseIfOwned(idx, vmID)

	if info.Firewall != nil {
		if err := info.Firewall.Close(); err != nil {
			m.log.Warn().Err(err).Str("vm_id", vmID).Msg("error closing namespace firewall")
		}
	}

	vpeerIP := fmt.Sprintf("10.12.%d.%d", (idx*2)/256, (idx*2)%256)
	hostCIDR := fmt.Sprintf("%s/32", info.HostIP)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_ = run(ctx, "ip", "route", "del", hostCIDR, "via", vpeerIP, "dev", vethName)
	_ = run(ctx, "ip", "link", "del", vethName)
	_ = run(ctx, "ip", "netns", "del", info.Namespace)

	m.log.Info().Str("vm_id", vmID).Str("namespace", info.Namespace).Msg("network namespace cleaned up")
}

// CleanupVMOrNamespace tears down a VM's network slot. When the VM is tracked
// in devices it delegates to CleanupVM (which may recycle the slot to the
// pool). When it is not tracked — e.g. a reattached VM whose network state was
// never restored into devices — it reclaims the slot directly from the
// namespace so the ns/veth/slot isn't leaked until the next restart sweep.
// A no-op only when the namespace is empty or malformed.
func (m *Manager) CleanupVMOrNamespace(vmID, fallbackNamespace string) {
	m.mu.Lock()
	_, tracked := m.devices[vmID]
	m.mu.Unlock()
	if tracked {
		m.CleanupVM(vmID)
		return
	}

	idx, ok := slotFromNamespace(fallbackNamespace)
	if !ok {
		return
	}
	// Only tear down if this vmID still owns the index, so a stale cleanup racing
	// the pool's reuse of the slot can't destroy a new tenant's ns/veth. Claim the
	// teardown atomically (vmID → teardownOwner) so claimSlotIndex can't grab idx
	// while cleanupFull runs below.
	m.mu.Lock()
	if m.slotOwner[idx] != vmID {
		m.mu.Unlock()
		return
	}
	m.slotOwner[idx] = teardownOwner
	m.mu.Unlock()
	// Release even if cleanupFull panics — otherwise the index stays stuck as
	// teardownOwner forever (no other path releases that sentinel).
	defer m.releaseIfOwned(idx, teardownOwner)

	// Tear down both sides even if the netns is already gone: `ip netns del`
	// only removes the in-namespace side, so the host-side veth-N can outlive it.
	m.cleanupFull(fallbackNamespace, fmt.Sprintf("veth-%d", idx))
	m.log.Info().Str("vm_id", vmID).Str("namespace", fallbackNamespace).Int("slot", idx).
		Msg("reclaimed network slot for untracked VM")
}

// Forget reverses an in-memory reattach that raced a concurrent DestroyVM/
// markStale: it drops vmID from devices and releases only the index this vmID
// still owns (releaseIfOwned), so if the racing destroy already freed or the pool
// reused it, Forget leaves it untouched. No kernel teardown here (the destroy
// path did that); the host IP stays registered in the egress proxy (keyed by
// slot, which a reused slot's new owner may already hold).
func (m *Manager) Forget(vmID string) {
	m.mu.Lock()
	info, ok := m.devices[vmID]
	delete(m.devices, vmID)
	m.mu.Unlock()
	if !ok {
		return
	}
	if idx, parsed := slotFromNamespace(info.Namespace); parsed {
		m.releaseIfOwned(idx, vmID)
	}
}

// ReattachVM rebinds vmd's view of an already-running VM's network state
// at startup. After this call: the slot is marked in-use (no SetupVM
// collisions), devices[vmID] is populated (CleanupVM can tear it down),
// and the in-namespace nftables Firewall handle is reattached so the
// customer's subsequent UpdateFirewallRules calls apply to the existing
// kernel state.
func (m *Manager) ReattachVM(vmID, namespace, hostIP, macAddress string) error {
	idx, ok := slotFromNamespace(namespace)
	if !ok {
		return fmt.Errorf("reattach %s: cannot parse slot from namespace %q", vmID, namespace)
	}

	// Rebind in-namespace nftables handle. Non-fatal on failure: kernel
	// rules already enforce traffic; only future updates would be lost.
	fwCfg := FirewallConfig{
		TAPInterface: TAPName,
		VethPeer:     "eth0",
		VMIP:         VMInternalIP,
		HostIP:       hostIP,
		GatewayIP:    VMGatewayIP,
	}
	var fw *Firewall
	if err := nsExecGo(namespace, func() error {
		f, err := AttachFirewall(fwCfg)
		if err != nil {
			return err
		}
		fw = f
		return nil
	}); err != nil {
		m.log.Warn().Err(err).Str("vm_id", vmID).Msg("reattach: in-namespace firewall handle not restored (existing rules still enforce traffic)")
	}

	m.mu.Lock()
	// Reserve this record's index under its vmID so the pool can't build on it.
	// Usually done at startup already; idempotent, and keeps a lazy reattach safe.
	m.reserveSlotLocked(idx, vmID)
	if idx >= m.nextSlot {
		m.nextSlot = idx + 1
	}
	info := &VMNetInfo{
		Namespace:  namespace,
		TAPDevice:  TAPName,
		VMIP:       VMInternalIP,
		GatewayIP:  VMGatewayIP,
		HostIP:     hostIP,
		MACAddress: macAddress,
		Firewall:   fw, // nil if AttachFirewall failed; CleanupVM tolerates it
	}
	// Idempotent: if a concurrent reattach of the same VM already bound a handle,
	// close it before replacing so a double restore doesn't leak the nftables
	// connection.
	prev := m.devices[vmID]
	m.devices[vmID] = info
	m.mu.Unlock()
	if prev != nil && prev.Firewall != nil && prev.Firewall != fw {
		_ = prev.Firewall.Close()
	}
	m.registerEgress(vmID, info)

	m.log.Info().Str("vm_id", vmID).Int("slot", idx).Str("host_ip", hostIP).Bool("fw_attached", fw != nil).Msg("reattached VM network state")
	return nil
}

// ReserveSlotsAbove reserves every existing record's slot index under its vmID
// (and bumps nextSlot past it) so the pool can never build on an index a record
// holds. Called once at startup with vmID→namespace for every record, BEFORE
// StartPool.
//
// Records are reserved unconditionally — including stale/dead ones whose netns is
// gone. A dead slot is only stranded transiently: the background reattach frees
// it back to the recycle list when it cleans the record. That's deliberately
// simpler and safer than freeing dead slots up front, which is what let the pool
// collide with a record and duplicate a slot.
func (m *Manager) ReserveSlotsAbove(reservations map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for vmID, ns := range reservations {
		idx, ok := slotFromNamespace(ns)
		if !ok {
			continue
		}
		m.reserveSlotLocked(idx, vmID)
		if idx >= m.nextSlot {
			m.nextSlot = idx + 1
		}
	}
}

// EnsureVMSlot guarantees the kernel network state for vmID is present and
// tracked. Idempotent.
//
// IP and MAC are deterministic from the slot index parsed out of namespace,
// so a rebuild preserves the VM's network identity. Per-customer egress
// rules are NOT restored here; the caller reapplies them.
func (m *Manager) EnsureVMSlot(ctx context.Context, vmID, namespace, hostIP, macAddress string) (*VMNetInfo, error) {
	idx, ok := slotFromNamespace(namespace)
	if !ok {
		return nil, fmt.Errorf("ensure %s: cannot parse slot from namespace %q", vmID, namespace)
	}

	// Reserve this record's index under its vmID BEFORE any rebuild, so the pool
	// can't claim idx during the cleanupFull/setupSlot window below. Ownership was
	// almost always taken at startup already; this is idempotent.
	m.mu.Lock()
	existing, hasDevice := m.devices[vmID]
	m.reserveSlotLocked(idx, vmID)
	if idx >= m.nextSlot {
		m.nextSlot = idx + 1
	}
	m.mu.Unlock()

	var info *VMNetInfo

	switch {
	case hasDevice && nsExists(namespace):
		// Preserve Firewall handle for future UpdateFirewallRules.
		info = existing
	case !nsExists(namespace):
		m.log.Warn().Str("vm_id", vmID).Str("namespace", namespace).Int("slot", idx).Msg("netns missing — rebuilding slot at original index")
		// ip netns delete only tears down the inside-ns side; the host-side
		// veth-N can survive and collide with setupSlot's fresh veth creation.
		m.cleanupFull(namespace, fmt.Sprintf("veth-%d", idx))
		built, _, err := m.setupSlot(ctx, idx)
		if err != nil {
			return nil, fmt.Errorf("ensure %s: rebuild slot %d: %w", vmID, idx, err)
		}
		if macAddress != "" && built.MACAddress != macAddress {
			m.log.Warn().Str("vm_id", vmID).Str("expected", macAddress).Str("got", built.MACAddress).Msg("rebuilt MAC differs from stored — deterministic mapping may have drifted")
		}
		info = built
	default:
		// Firewall handle stays nil; UpdateFirewallRules creates a fresh one.
		info = &VMNetInfo{
			Namespace:  namespace,
			TAPDevice:  TAPName,
			VMIP:       VMInternalIP,
			GatewayIP:  VMGatewayIP,
			HostIP:     hostIP,
			MACAddress: macAddress,
		}
	}

	m.mu.Lock()
	m.devices[vmID] = info
	m.mu.Unlock()
	m.registerEgress(vmID, info)

	return info, nil
}

// slotFromNamespace parses "ns-N" → N (digits only). Returns (0, false)
// on malformed input. Strict: trailing non-digit characters are rejected
// to avoid silently mapping "ns-2-something" to slot 2.
func slotFromNamespace(namespace string) (int, bool) {
	const prefix = "ns-"
	if len(namespace) <= len(prefix) || namespace[:len(prefix)] != prefix {
		return 0, false
	}
	digits := namespace[len(prefix):]
	idx := 0
	for _, c := range digits {
		if c < '0' || c > '9' {
			return 0, false
		}
		idx = idx*10 + int(c-'0')
	}
	return idx, true
}

// Sentinel owners (see slotOwner). Prefixed with NUL so they can never collide
// with a real vmID.
const (
	poolOwner     = "\x00pool"     // warm/mid-build pool slot, not yet a VM's
	teardownOwner = "\x00teardown" // slot mid-teardown; held so it isn't reclaimed
)

// assignSlotLocked sets the owner of idx (a fresh claim or an owner transfer,
// e.g. pool→VM on Claim). Caller must hold m.mu and must have already removed
// idx from freeSlots (claimSlotIndex pops it; transfers keep it out).
func (m *Manager) assignSlotLocked(idx int, owner string) { m.slotOwner[idx] = owner }

// reserveSlotLocked marks idx owned by a record and removes it from freeSlots if
// present — the record-path acquire. Caller must hold m.mu.
func (m *Manager) reserveSlotLocked(idx int, owner string) {
	m.slotOwner[idx] = owner
	m.removeFromFreeSlotsLocked(idx)
}

func (m *Manager) removeFromFreeSlotsLocked(idx int) {
	for i, s := range m.freeSlots {
		if s == idx {
			m.freeSlots = append(m.freeSlots[:i], m.freeSlots[i+1:]...)
			return
		}
	}
}

// releaseIfOwned releases idx only when it is still owned by owner, returning
// whether it did — the identity guard described on slotOwner.
func (m *Manager) releaseIfOwned(idx int, owner string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.slotOwner[idx] != owner {
		return false
	}
	delete(m.slotOwner, idx)
	m.freeSlots = append(m.freeSlots, idx)
	return true
}

// claimSlotIndex picks a slot idx that is unowned and not present in the kernel,
// assigns it to owner, and returns it. owner is poolOwner for pool pre-allocation
// or the vmID for an on-demand SetupVM.
func (m *Manager) claimSlotIndex(owner string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for {
		var idx int
		if len(m.freeSlots) > 0 {
			idx = m.freeSlots[len(m.freeSlots)-1]
			m.freeSlots = m.freeSlots[:len(m.freeSlots)-1]
		} else {
			if m.nextSlot > MaxSlots {
				return 0, ErrNoSlots
			}
			idx = m.nextSlot
			m.nextSlot++
		}

		if _, isOwned := m.slotOwner[idx]; isOwned || nsExists(fmt.Sprintf("ns-%d", idx)) {
			// Owned by a live slot/record/build, or its kernel ns already
			// exists. Discard; returning idx to freeSlots would loop.
			m.log.Warn().Int("slot", idx).Msg("allocator: skipping idx — owned or kernel ns exists")
			continue
		}

		m.assignSlotLocked(idx, owner)
		return idx, nil
	}
}

// SweepOrphanNamespaces removes host namespaces and veth interfaces
// matching ns-N/veth-N that aren't in the keep set. Kills any process
// still in the ns first so slot recycling can't collide with a
// vmd-crash-orphaned firecracker still holding veth/TAP peers.
func (m *Manager) SweepOrphanNamespaces(keep map[string]bool) (swept int) {
	entries, err := os.ReadDir(netnsDir)
	if err != nil {
		if !os.IsNotExist(err) {
			m.log.Warn().Err(err).Msg("sweep: list netns dir failed")
		}
		return 0
	}

	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "ns-") {
			continue
		}
		if keep[name] {
			continue
		}

		var idx int
		if _, err := fmt.Sscanf(name, "ns-%d", &idx); err != nil {
			continue
		}
		if killed := killProcessesInNs(name); killed > 0 {
			m.log.Info().Str("ns", name).Int("killed", killed).Msg("killed processes in orphan namespace before sweep")
		}
		veth := fmt.Sprintf("veth-%d", idx)
		m.cleanupFull(name, veth)
		m.log.Info().Str("ns", name).Str("veth", veth).Msg("swept orphan namespace")
		swept++
	}

	// Also sweep host-side veth-N interfaces that survived their namespace
	// being deleted (happens when the peer end was moved back to the host
	// before ns deletion, or when a crash left the host side orphaned).
	if veths, err := listHostVeths(); err == nil {
		for _, veth := range veths {
			var idx int
			if _, err := fmt.Sscanf(veth, "veth-%d", &idx); err != nil {
				continue
			}
			if keep[fmt.Sprintf("ns-%d", idx)] {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := run(ctx, "ip", "link", "del", veth); err == nil {
				m.log.Info().Str("veth", veth).Msg("swept orphan host veth")
			}
			cancel()
		}
	}

	return swept
}

// killProcessesInNs SIGKILLs every process whose net namespace matches
// /run/netns/<name>. Returns the number of pids signalled. Best-effort: a
// failed /proc scan (see pidsInNs) just means nothing gets killed this pass.
func killProcessesInNs(name string) int {
	pids, _ := pidsInNs(name)
	killed := 0
	for _, pid := range pids {
		if err := syscall.Kill(pid, syscall.SIGKILL); err == nil {
			killed++
		}
	}
	return killed
}

// pidsInNs returns the PIDs whose net namespace matches /run/netns/<name>,
// found by comparing /proc/<pid>/ns/net's inode against the namespace file's.
// ok is false only when the /proc scan itself failed (e.g. transient
// resource pressure) — a genuine "don't know" that callers must not treat as
// "clear" the way an actually-empty scan is; conflating the two would let a
// still-occupied namespace be recycled, reintroducing the exact race this
// guards against. A namespace file that no longer exists can't have
// anything attached to it, so that case is a confident (nil, true).
func pidsInNs(name string) (pids []int, ok bool) {
	nsPath := netnsDir + "/" + name
	nsStat, err := os.Stat(nsPath)
	if err != nil {
		return nil, true
	}
	nsIno := nsStat.Sys().(*syscall.Stat_t).Ino
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return nil, false
	}
	for _, e := range procs {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		procNsStat, err := os.Stat("/proc/" + e.Name() + "/ns/net")
		if err != nil {
			continue
		}
		if procNsStat.Sys().(*syscall.Stat_t).Ino != nsIno {
			continue
		}
		pids = append(pids, pid)
	}
	return pids, true
}

// listHostVeths returns all veth-N interfaces visible in the host namespace.
func listHostVeths() ([]string, error) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "veth-") {
			out = append(out, e.Name())
		}
	}
	return out, nil
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

// netnsDir is overridden by tests.
var netnsDir = "/run/netns"

func nsExists(nsName string) bool {
	_, err := os.Stat(netnsDir + "/" + nsName)
	return err == nil
}

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
