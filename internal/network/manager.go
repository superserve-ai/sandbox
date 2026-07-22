package network

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/shellquote"
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

	mu         sync.Mutex
	devices    map[string]*VMNetInfo
	freeSlots  []int // recycled slot indices, guaranteed absent from slotOwner
	nextSlot   int   // next new slot (used when freeSlots is empty)
	maxSlot    int   // new-slot ceiling; meaningful only when slotPinned (WithExactSlot)
	slotPinned bool  // WithExactSlot: allocate exactly maxSlot or fail, never advance

	// slotOwner is the single source of truth for slot allocation AND identity:
	// slotOwner[idx] == the current owner of slot index idx, one of
	//   - a VM/record vmID   (a live VM, or a record reserving its index)
	//   - poolOwner          (a warm/mid-build pool slot not yet handed to a VM)
	//   - teardownOwner      (a slot being torn down; held so no one re-claims it)
	//   - withheldOwner      (kernel state known dirty and unremovable; parked
	//                         for this process lifetime, next boot retries)
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

// WithExactSlot pins the Manager to exactly slot idx: it claims that one index
// or fails with ErrNoSlots, never advancing to idx+1. A template-builder
// subprocess uses this to build precisely the slot vmd reserved for it via
// ReserveSlot; if that slot is somehow unavailable the build fails cleanly
// instead of silently running on an index vmd never reserved.
func WithExactSlot(idx int) ManagerOption {
	return func(m *Manager) { m.nextSlot = idx; m.maxSlot = idx; m.slotPinned = true }
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

// Deterministic slot identity: everything about a slot derives from its index,
// which is what makes namespaces left by a previous vmd lifetime adoptable —
// the kernel objects carry all the state, nothing needs to be persisted.
func nsNameForSlot(idx int) string    { return fmt.Sprintf("ns-%d", idx) }
func vethNameForSlot(idx int) string  { return fmt.Sprintf("veth-%d", idx) }
func vpeerIPForSlot(idx int) string   { return fmt.Sprintf("10.12.%d.%d", (idx*2)/256, (idx*2)%256) }
func vethIPForSlot(idx int) string    { return fmt.Sprintf("10.12.%d.%d", (idx*2+1)/256, (idx*2+1)%256) }
func macForSlot(idx int) string       { return fmt.Sprintf("AA:FC:00:%02X:%02X:%02X", 0, idx/256, idx%256) }

// setupSlot runs the expensive network setup (namespace, veth, TAP,
// nftables, routing) for a single slot index. Used by both SetupVM
// (on-demand) and Pool (pre-allocation).
func (m *Manager) setupSlot(ctx context.Context, idx int) (*VMNetInfo, string, error) {
	// Ownership of idx is NOT touched here: claimSlotIndex owns it before this
	// runs (pool/on-demand), and record paths reserve it. On success the slot is
	// live and stays owned; on failure the caller releases idx (freeSlot).
	hostIP := hostIPForSlot(idx)
	vpeerIP := vpeerIPForSlot(idx)
	vethIP := vethIPForSlot(idx)
	nsName := nsNameForSlot(idx)
	vethName := vethNameForSlot(idx)
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

	// One tap-construction path for fresh and recycled slots, so their tap
	// config can't diverge (the leading delete is a no-op on a fresh namespace).
	if err := m.resetTap(ctx, nsName); err != nil {
		m.cleanupFull(nsName, vethName)
		return nil, "", err
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

	mac := macForSlot(idx)

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

// resetTap deletes and recreates tap0 in nsName, leaving a TAP that is
// unattached by construction — a recycled slot can't rely on the namespace
// being process-free (that doesn't guarantee the previous owner's fd is
// released). Returns an error if the tap can't be rebuilt, so the caller can
// decline to recycle. nftables rules match tap0 by name, so reusing the name
// keeps them valid. Also the tap-construction path for setupSlot (the delete
// is a no-op on a fresh namespace), keeping fresh and recycled taps identical.
//
// One exec for the whole rebuild: per-command `ip netns exec` invocations fork
// twice each and serialize on the kernel's netlink lock under concurrent
// resets. Interpolants are shell-quoted package constants.
func (m *Manager) resetTap(ctx context.Context, nsName string) error {
	script := fmt.Sprintf(
		"ip link del %[1]s 2>/dev/null; ip tuntap add dev %[1]s mode tap && ip link set %[1]s up && ip link set %[1]s mtu %[2]s && ip addr add %[3]s dev %[1]s",
		shellquote.Single(TAPName), shellquote.Single(ifaceMTU), shellquote.Single(tapCIDR))
	if err := nsRun(ctx, nsName, "sh", "-c", script); err != nil {
		return fmt.Errorf("reset TAP: %w", err)
	}
	return nil
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

// CleanupVM releases a VM's network slot, recycling it into the pool when one
// is configured.
func (m *Manager) CleanupVM(vmID string) { m.cleanupVM(vmID, true) }

// TeardownVM releases a VM's network slot with a full teardown, never recycling
// it. Used when the slot is suspect — e.g. a create that failed to attach tap0 —
// so its index is rebuilt from scratch (fresh tap) before reuse instead of being
// handed straight to the next claim, which could inherit the same bad tap.
func (m *Manager) TeardownVM(vmID string) { m.cleanupVM(vmID, false) }

func (m *Manager) cleanupVM(vmID string, recycle bool) {
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

	// Ownership gates every slot-keyed side effect below (egress rules, firewall,
	// kernel state): they belong to whoever owns the index now.

	// Recycle the slot into the pool — namespace, veth, TAP, and base
	// nftables stay configured; the next Claim re-adds vmID-specific
	// rules. Skipped when info.Firewall is nil (reattached VM whose
	// in-ns handle couldn't be rebound) — pooling would let the next
	// Claim silently lose per-VM egress filtering. Return transfers ownership
	// from this VM back to the pool.
	if recycle && m.pool != nil && info.Firewall != nil {
		m.mu.Lock()
		owned := m.slotOwner[idx] == vmID
		m.mu.Unlock()
		if !owned {
			m.log.Warn().Str("vm_id", vmID).Int("slot", idx).
				Msg("cleanup skipped — slot no longer owned by this VM")
			return
		}
		if m.egressProxy != nil {
			m.egressProxy.RemoveRules(info.HostIP)
		}
		_ = info.Firewall.ReplaceUserRules(nil, nil)
		m.pool.Return(&preallocSlot{idx: idx, info: info, vethName: vethName})
		return
	}

	// Full teardown (no pool, or a forced teardown of a suspect slot). Park the
	// index as teardownOwner for the duration — releasing it first would let a
	// concurrent claim pop the idx, see the netns still present, and discard it
	// for good.
	if !m.claimTeardown(idx, vmID) {
		m.log.Warn().Str("vm_id", vmID).Int("slot", idx).
			Msg("teardown skipped — slot no longer owned by this VM")
		return
	}
	defer m.releaseIfOwned(idx, teardownOwner)

	if m.egressProxy != nil {
		m.egressProxy.RemoveRules(info.HostIP)
	}
	if info.Firewall != nil {
		if err := info.Firewall.Close(); err != nil {
			m.log.Warn().Err(err).Str("vm_id", vmID).Msg("error closing namespace firewall")
		}
	}

	// Kill any process still in the namespace before removing it — `ip netns
	// del` only unlinks the name, so a live holder (e.g. the still-attached tap
	// owner on the teardown-not-recycle path) would keep the namespace and its
	// tap alive but anonymous: unfindable by pidsInNs, the sweep, or the gauge.
	if killed := killProcessesInNs(info.Namespace); killed > 0 {
		m.log.Info().Str("namespace", info.Namespace).Int("killed", killed).
			Msg("cleanup: killed lingering processes before namespace teardown")
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
	// the pool's reuse of the slot can't destroy a new tenant's ns/veth.
	if !m.claimTeardown(idx, vmID) {
		return
	}
	// Release even if cleanupFull panics — otherwise the index stays stuck as
	// teardownOwner forever (no other path releases that sentinel).
	defer m.releaseIfOwned(idx, teardownOwner)

	// Kill any process still in the namespace before removing it — `ip netns del`
	// only unlinks the name, so a namespace with a live holder lingers (keeping
	// its tap0) until that process exits. Mirrors SweepOrphanNamespaces.
	if killed := killProcessesInNs(fallbackNamespace); killed > 0 {
		m.log.Info().Str("namespace", fallbackNamespace).Int("killed", killed).
			Msg("cleanup: killed lingering processes before namespace teardown")
	}
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
	withheldOwner = "\x00withheld" // kernel state dirty and unremovable; parked until next boot
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

// withholdIfOwned converts owner's hold on idx into a process-lifetime park —
// for indexes whose kernel state is known dirty but couldn't be removed (e.g.
// a stray host link that failed to delete). Merely dropping ownership would
// only protect until the sequential allocator's high-water mark reaches the
// index; the sentinel keeps every allocation path off it. Next boot starts
// clean and retries.
func (m *Manager) withholdIfOwned(idx int, owner string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.slotOwner[idx] == owner {
		m.slotOwner[idx] = withheldOwner
	}
}

// ClaimFreshSlot claims a fresh, unused slot index under owner without building
// any kernel network state. The caller — a template-builder subprocess —
// creates ns-<idx>/veth-<idx> itself; the reservation is what stops vmd's
// sandbox allocator from handing the same index to a VM, so builds and
// sandboxes draw from one authoritative allocator instead of racing disjoint
// ranges. Distinct from ReserveSlotsAbove, which pins already-known indices
// via reserveSlotLocked (bypassing the owned/nsExists checks). Pair every
// ClaimFreshSlot with a ReleaseSlot.
func (m *Manager) ClaimFreshSlot(owner string) (int, error) {
	return m.claimSlotIndex(owner)
}

// ReleaseSlot frees a slot claimed via ClaimFreshSlot and tears down any ns/veth
// the caller built at idx. It releases strictly by (owner, idx) — never routing
// through the tracked-VM path — so a caller-supplied build ID that collides with
// a live sandbox's VM ID can't tear down that sandbox's namespace or leak the
// reserved index. Owns the namespace naming so callers never reconstruct
// "ns-<idx>"; a no-op if owner no longer owns idx (already reclaimed/reused).
func (m *Manager) ReleaseSlot(owner string, idx int) {
	if !m.claimTeardown(idx, owner) {
		return
	}
	// Release even if cleanupFull panics — otherwise idx stays stuck as
	// teardownOwner forever (no other path releases that sentinel).
	defer m.releaseIfOwned(idx, teardownOwner)
	m.cleanupFull(fmt.Sprintf("ns-%d", idx), fmt.Sprintf("veth-%d", idx))
}

// claimTeardown atomically transfers idx from owner to the teardown sentinel so
// claimSlotIndex can't grab it mid-teardown. False when owner no longer holds
// idx — the slot moved on and its state belongs to the new tenant, so the
// caller must touch none of it. Pair with `defer m.releaseIfOwned(idx,
// teardownOwner)`.
func (m *Manager) claimTeardown(idx int, owner string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.slotOwner[idx] != owner {
		return false
	}
	m.slotOwner[idx] = teardownOwner
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
		// A pinned Manager (WithExactSlot) must claim exactly maxSlot or fail —
		// so it never draws from freeSlots (which could hand back a different
		// index); it only takes the pinned nextSlot path below.
		if !m.slotPinned && len(m.freeSlots) > 0 {
			idx = m.freeSlots[len(m.freeSlots)-1]
			m.freeSlots = m.freeSlots[:len(m.freeSlots)-1]
		} else {
			ceiling := MaxSlots
			if m.slotPinned {
				ceiling = m.maxSlot // WithExactSlot: allow only the pinned index
			}
			if m.nextSlot > ceiling {
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
		if keep[name] {
			continue
		}

		// Strict ns-<int> parse: trailing garbage must not map a foreign
		// namespace onto another slot's veth.
		idx, ok := slotFromNamespace(name)
		if !ok {
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
			// Same strict parse as the ns loop.
			idxStr, isVeth := strings.CutPrefix(veth, "veth-")
			idx, err := strconv.Atoi(idxStr)
			if !isVeth || err != nil || idx < 0 {
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

// claimOrphanSlots takes ownership of every ns-N namespace present in the
// kernel but owned by nothing — slots a previous vmd lifetime left behind
// (graceful abandon and crash look identical here). Reservation happens in one
// locked pass before any validation, so the refill loop can never build over a
// namespace that is about to be adopted. Callers must either adopt or tear
// down every returned index; the ownership taken here is not dropped otherwise.
func (m *Manager) claimOrphanSlots() []int {
	entries, err := os.ReadDir(netnsDir)
	if err != nil {
		if !os.IsNotExist(err) {
			m.log.Warn().Err(err).Msg("adopt: list netns dir failed")
		}
		return nil
	}
	var outOfRange []int
	m.mu.Lock()
	var out []int
	claimed := make(map[int]bool)
	for _, e := range entries {
		idx, ok := slotFromNamespace(e.Name())
		if !ok {
			continue
		}
		// Ownership outranks everything: a record or pinned build may hold any
		// index, including ones a changed ceiling would now call out of range.
		if _, owned := m.slotOwner[idx]; owned {
			continue
		}
		if idx < 1 || idx > MaxSlots {
			// Outside the allocator's range: it starts at 1 and hands out up
			// to and including MaxSlots. Below it: ns-0 is never built (and a
			// long-enough name overflows slotFromNamespace negative); above
			// it, claiming would push the high-water mark past the ceiling
			// and starve fresh allocation.
			outOfRange = append(outOfRange, idx)
			continue
		}
		m.assignSlotLocked(idx, poolOwner)
		claimed[idx] = true
		if idx >= m.nextSlot {
			m.nextSlot = idx + 1
		}
		out = append(out, idx)
	}
	if len(claimed) > 0 && len(m.freeSlots) > 0 {
		// Preserve the freeSlots invariant (never overlaps slotOwner) rather
		// than lean on claimSlotIndex's discard path to absorb the breach.
		kept := m.freeSlots[:0]
		for _, idx := range m.freeSlots {
			if !claimed[idx] {
				kept = append(kept, idx)
			}
		}
		m.freeSlots = kept
	}
	m.mu.Unlock()

	// Not adoptable — remove like the legacy sweep would (outside the lock:
	// teardown execs kernel commands).
	for _, idx := range outOfRange {
		ns := nsNameForSlot(idx)
		m.log.Warn().Str("ns", ns).Msg("adopt: namespace outside allocator range — sweeping")
		killProcessesInNs(ns)
		m.cleanupFull(ns, vethNameForSlot(idx))
	}
	return out
}

// adoptSlot rebuilds the identity of an existing ns-<idx> so it can re-enter
// the pool: kills any occupant, verifies the veth pair and the peer's derived
// address, reinstalls the current base firewall from scratch, and re-adds the
// host route (idempotent). The structural checks double as the layout/version
// check, so a namespace built by an incompatible vmd fails here and gets torn
// down. tap0 is NOT checked: adopted slots always rebuild it before recycling
// (unknown provenance — the previous owner may have died holding its fd).
func (m *Manager) adoptSlot(ctx context.Context, idx int) (*VMNetInfo, string, error) {
	nsName := nsNameForSlot(idx)
	vethName := vethNameForSlot(idx)
	hostIP := hostIPForSlot(idx)

	if !nsExists(nsName) {
		return nil, "", fmt.Errorf("adopt slot %d: namespace vanished", idx)
	}
	// Kill any occupant and prove the namespace empty before touching
	// enforcement: SIGKILL is asynchronous for a process in an uninterruptible
	// wait, and the firewall rewrite below would leave a still-running
	// workload without its egress restrictions (briefly without any table at
	// all). A failed /proc scan is "don't know", never "empty". If emptiness
	// can't be proven within the slot's budget, the caller skips the slot —
	// with the occupant's rules untouched.
	killProcessesInNs(nsName)
	for {
		pids, ok := pidsInNsFunc(nsName)
		if ok && len(pids) == 0 {
			break
		}
		select {
		case <-ctx.Done():
			return nil, "", fmt.Errorf("adopt slot %d: namespace still occupied: %w", idx, ctx.Err())
		case <-time.After(defaultVerifyPollInterval):
		}
	}

	if _, err := os.Stat("/sys/class/net/" + vethName); err != nil {
		return nil, "", fmt.Errorf("adopt slot %d: host veth missing: %w", idx, err)
	}

	fwCfg := FirewallConfig{
		TAPInterface: TAPName,
		VethPeer:     "eth0",
		VMIP:         VMInternalIP,
		HostIP:       hostIP,
		GatewayIP:    VMGatewayIP,
	}
	// The in-namespace work (netlink, nftables) cannot observe ctx once it is
	// on the pinned thread, and a wedged netlink socket would otherwise hang
	// the adoption worker forever — bound it from outside. On timeout the
	// abandoned goroutine is reaped when (if) it finishes: its thread stays
	// pinned until then, an accepted, bounded cost of surviving a wedge.
	type nsResult struct {
		fw  *Firewall
		err error
	}
	resCh := make(chan nsResult, 1)
	go func() {
		var fw *Firewall
		err := nsExecGo(nsName, func() error {
			iface, err := net.InterfaceByName("eth0")
			if err != nil {
				return fmt.Errorf("in-namespace peer missing: %w", err)
			}
			addrs, err := iface.Addrs()
			if err != nil {
				return fmt.Errorf("peer addrs: %w", err)
			}
			want := vpeerIPForSlot(idx)
			found := false
			for _, a := range addrs {
				if strings.HasPrefix(a.String(), want+"/") {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("peer address mismatch: want %s", want)
			}
			f, err := ReinstallFirewall(fwCfg)
			if err != nil {
				return err
			}
			fw = f
			return nil
		})
		resCh <- nsResult{fw: fw, err: err}
	}()
	var fw *Firewall
	select {
	case res := <-resCh:
		if res.err != nil {
			return nil, "", fmt.Errorf("adopt slot %d: %w", idx, res.err)
		}
		fw = res.fw
	case <-ctx.Done():
		go func() {
			if res := <-resCh; res.fw != nil {
				_ = res.fw.Close()
			}
		}()
		return nil, "", fmt.Errorf("adopt slot %d: namespace validation: %w", idx, ctx.Err())
	}

	// Both routes must exist for the claimed VM to work — host side to reach
	// it, namespace side for its outbound traffic — and a crash can strand a
	// namespace between address config and route install. Replace is
	// idempotent, so any failure means the slot is structurally broken.
	if err := run(ctx, "ip", "route", "replace", hostIP+"/32", "via", vpeerIPForSlot(idx), "dev", vethName); err != nil {
		_ = fw.Close()
		return nil, "", fmt.Errorf("adopt slot %d: host route: %w", idx, err)
	}
	if err := nsRun(ctx, nsName, "ip", "route", "replace", "default", "via", vethIPForSlot(idx)); err != nil {
		_ = fw.Close()
		return nil, "", fmt.Errorf("adopt slot %d: namespace default route: %w", idx, err)
	}
	_ = nsRun(ctx, nsName, "ip", "link", "set", "lo", "up")

	return &VMNetInfo{
		Namespace:  nsName,
		TAPDevice:  TAPName,
		VMIP:       VMInternalIP,
		GatewayIP:  VMGatewayIP,
		HostIP:     hostIP,
		MACAddress: macForSlot(idx),
		Firewall:   fw,
	}, vethName, nil
}

// SweepStrayHostVeths deletes host-side veth-N interfaces whose namespace is
// gone and whose slot nothing owns — leftovers of a namespace deletion that
// raced the host-side link. Owned slots are skipped: a mid-build pool slot
// parks its veth on the host before the namespace side is complete.
func (m *Manager) SweepStrayHostVeths() (swept int) {
	veths, err := listHostVeths()
	if err != nil {
		return 0
	}
	for _, veth := range veths {
		idxStr, isVeth := strings.CutPrefix(veth, "veth-")
		idx, err := strconv.Atoi(idxStr)
		if !isVeth || err != nil {
			continue
		}
		if idx < 1 || idx > MaxSlots {
			// Outside the allocator's range nothing can race us building
			// here, and the index must never become claimable — delete the
			// stray link and move on.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := run(ctx, "ip", "link", "del", veth); err == nil {
				m.log.Info().Str("veth", veth).Msg("swept stray host veth")
				swept++
			}
			cancel()
			continue
		}
		// Hold the index through the delete: checking and then deleting
		// unowned would race the refill loop building a fresh slot at this
		// idx between the check and the `ip link del` — which would sever a
		// brand-new live slot's host side.
		m.mu.Lock()
		if _, owned := m.slotOwner[idx]; owned || nsExists(nsNameForSlot(idx)) {
			m.mu.Unlock()
			continue
		}
		m.assignSlotLocked(idx, teardownOwner)
		m.mu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		delErr := run(ctx, "ip", "link", "del", veth)
		cancel()
		if delErr == nil {
			m.log.Info().Str("veth", veth).Msg("swept stray host veth")
			swept++
			m.releaseIfOwned(idx, teardownOwner)
			continue
		}
		// The link may still exist: any future build here collides with it on
		// the move-to-host step. Park the index for this process lifetime;
		// the next boot's sweep retries.
		m.log.Warn().Err(delErr).Str("veth", veth).Msg("stray host veth delete failed — index withheld")
		m.withholdIfOwned(idx, teardownOwner)
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

// NetnsStats reports the ns-N namespaces on the host, the owned slot indices
// (slotOwner covers every legitimate holder), and orphaned — namespaces with
// no owner, the leak signal. Measured per namespace so owners without a
// backing namespace (e.g. record reservations after a reboot) don't distort it.
func (m *Manager) NetnsStats() (netnsTotal, ownedSlots, orphaned int) {
	var indices []int
	if entries, err := os.ReadDir(netnsDir); err == nil {
		for _, e := range entries {
			if idx, ok := slotFromNamespace(e.Name()); ok {
				netnsTotal++
				indices = append(indices, idx)
			}
		}
	}
	m.mu.Lock()
	ownedSlots = len(m.slotOwner)
	for _, idx := range indices {
		if _, ok := m.slotOwner[idx]; !ok {
			orphaned++
		}
	}
	m.mu.Unlock()
	return netnsTotal, ownedSlots, orphaned
}

func run(ctx context.Context, name string, args ...string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	cmd := exec.CommandContext(ctx, name, args...)
	// Run in its own process group and cancel the whole group, so a timeout
	// also kills any children the command spawned (resetTap's shell) — a lone
	// process kill would orphan them to finish after the caller moved on.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if err == syscall.ESRCH {
			// Group already gone: report "done" so a command that finished
			// just as the deadline fired isn't turned into a spurious failure.
			return os.ErrProcessDone
		}
		return err
	}
	// Bound the post-kill wait for output pipes: a descendant that detached
	// into its own group survives the group kill and would otherwise hold
	// stdout open indefinitely.
	cmd.WaitDelay = time.Second
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v: %s: %w", name, args, string(out), err)
	}
	return nil
}

func nsRun(ctx context.Context, ns string, name string, args ...string) error {
	fullArgs := append([]string{"netns", "exec", ns, name}, args...)
	return run(ctx, "ip", fullArgs...)
}
