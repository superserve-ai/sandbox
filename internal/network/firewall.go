package network

import (
	"fmt"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

const (
	tableName = "sandbox-firewall"

	// AllTrafficCIDR is a special value meaning "match all IPv4 traffic".
	// nftables rejects 0.0.0.0 as "unspecified", so we handle it specially.
	AllTrafficCIDR = "0.0.0.0/0"
)

// Firewall manages nftables rules for a single sandbox namespace.
// It provides:
//   - NAT (SNAT outbound, DNAT inbound, MASQUERADE for internet)
//   - Egress filtering with 4 IP sets (predefined allow/deny + user allow/deny)
//   - ESTABLISHED/RELATED conntrack acceptance
//   - MSS clamping for GCP MTU compatibility
//   - TCP REDIRECT rules for the egress proxy
type Firewall struct {
	conn  *nftables.Conn
	table *nftables.Table

	filterChain *nftables.Chain // PREROUTING filter at priority -150
	natChain    *nftables.Chain // PREROUTING NAT (DNAT + REDIRECT)
	postChain   *nftables.Chain // POSTROUTING NAT (SNAT)
	fwdChain    *nftables.Chain // FORWARD (MSS clamping)

	predefinedDenySet  *nftables.Set
	predefinedAllowSet *nftables.Set
	userDenySet        *nftables.Set
	userAllowSet       *nftables.Set

	tapIface   string
	vethPeer   string // namespace-side veth (e.g. "eth0")
	vmIP       string // VM internal IP (169.254.0.21)
	hostIP     string // host-side IP for this sandbox
	gatewayIP  string // orchestrator IP allowed through firewall

	// TCP proxy ports for domain-based filtering.
	httpProxyPort  uint16
	tlsProxyPort   uint16
	otherProxyPort uint16
}

// FirewallConfig holds the parameters needed to create a Firewall.
type FirewallConfig struct {
	TAPInterface   string
	VethPeer       string // namespace-side veth name
	VMIP           string
	HostIP         string
	GatewayIP      string // IP always allowed (orchestrator/gateway)
	HTTPProxyPort  uint16
	TLSProxyPort   uint16
	OtherProxyPort uint16
}

// NewFirewall creates nftables rules inside the current network namespace.
// Must be called from within the sandbox's network namespace.
func NewFirewall(cfg FirewallConfig) (*Firewall, error) {
	conn, err := nftables.New(nftables.AsLasting())
	if err != nil {
		return nil, fmt.Errorf("new nftables conn: %w", err)
	}

	// Single table for all rules (inet = IPv4 + IPv6).
	table := conn.AddTable(&nftables.Table{
		Name:   tableName,
		Family: nftables.TableFamilyINet,
	})

	// --- Chains ---

	acceptPolicy := nftables.ChainPolicyAccept

	// Filter chain: PREROUTING at priority -150 (before NAT).
	filterChain := conn.AddChain(&nftables.Chain{
		Name:     "preroute_filter",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityRef(-150),
		Policy:   &acceptPolicy,
	})

	// NAT chain: PREROUTING for DNAT + TCP REDIRECT.
	natChain := conn.AddChain(&nftables.Chain{
		Name:     "preroute_nat",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
		Policy:   &acceptPolicy,
	})

	// POSTROUTING chain: SNAT for outbound traffic.
	postChain := conn.AddChain(&nftables.Chain{
		Name:     "postroute_nat",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
		Policy:   &acceptPolicy,
	})

	// FORWARD chain: MSS clamping.
	fwdChain := conn.AddChain(&nftables.Chain{
		Name:     "forward_mangle",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityMangle,
		Policy:   &acceptPolicy,
	})

	// --- IP Sets ---

	predefinedDenySet := &nftables.Set{
		Table:    table,
		Name:     "predefined_deny",
		KeyType:  nftables.TypeIPAddr,
		Interval: true,
	}
	if err := conn.AddSet(predefinedDenySet, nil); err != nil {
		conn.CloseLasting()
		return nil, fmt.Errorf("add predefined deny set: %w", err)
	}

	predefinedAllowSet := &nftables.Set{
		Table:    table,
		Name:     "predefined_allow",
		KeyType:  nftables.TypeIPAddr,
		Interval: true,
	}
	if err := conn.AddSet(predefinedAllowSet, nil); err != nil {
		conn.CloseLasting()
		return nil, fmt.Errorf("add predefined allow set: %w", err)
	}

	userDenySet := &nftables.Set{
		Table:    table,
		Name:     "user_deny",
		KeyType:  nftables.TypeIPAddr,
		Interval: true,
	}
	if err := conn.AddSet(userDenySet, nil); err != nil {
		conn.CloseLasting()
		return nil, fmt.Errorf("add user deny set: %w", err)
	}

	userAllowSet := &nftables.Set{
		Table:    table,
		Name:     "user_allow",
		KeyType:  nftables.TypeIPAddr,
		Interval: true,
	}
	if err := conn.AddSet(userAllowSet, nil); err != nil {
		conn.CloseLasting()
		return nil, fmt.Errorf("add user allow set: %w", err)
	}

	fw := &Firewall{
		conn:               conn,
		table:              table,
		filterChain:        filterChain,
		natChain:           natChain,
		postChain:          postChain,
		fwdChain:           fwdChain,
		predefinedDenySet:  predefinedDenySet,
		predefinedAllowSet: predefinedAllowSet,
		userDenySet:        userDenySet,
		userAllowSet:       userAllowSet,
		tapIface:           cfg.TAPInterface,
		vethPeer:           cfg.VethPeer,
		vmIP:               cfg.VMIP,
		hostIP:             cfg.HostIP,
		gatewayIP:          cfg.GatewayIP,
		httpProxyPort:      cfg.HTTPProxyPort,
		tlsProxyPort:       cfg.TLSProxyPort,
		otherProxyPort:     cfg.OtherProxyPort,
	}

	if err := fw.installRules(); err != nil {
		conn.CloseLasting()
		return nil, err
	}

	// Populate sets with initial data (no user rules).
	if err := fw.ReplaceUserRules(nil, nil); err != nil {
		conn.CloseLasting()
		return nil, fmt.Errorf("initial set population: %w", err)
	}

	return fw, nil
}

// Close tears down the nftables connection. The kernel automatically
// removes the table and all rules when the lasting connection closes.
func (fw *Firewall) Close() error {
	if fw.conn == nil {
		return nil
	}
	err := fw.conn.CloseLasting()
	fw.conn = nil
	return err
}

// installRules adds all static rules (filter, NAT, MSS clamping, TCP redirect).
// Called once during NewFirewall. Dynamic data goes into IP sets via ReplaceUserRules.
func (fw *Firewall) installRules() error {
	fw.installFilterRules()
	fw.installNATRules()
	fw.installMSSClamping()
	fw.installTCPRedirect()

	if err := fw.conn.Flush(); err != nil {
		return fmt.Errorf("flush nftables rules: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Filter rules (PREROUTING, priority -150)
// ---------------------------------------------------------------------------
//
// Order:
//   0. Any IPv6 from TAP → drop (fail-closed; sandboxes are IPv4-only)
//   1. ESTABLISHED/RELATED → accept
//   2. predefinedAllowSet → accept (all protocols)
//   3. predefinedDenySet  → drop   (all protocols)
//   4. Non-TCP: userAllowSet → accept
//   5. Non-TCP: userDenySet  → drop
//   6. Default: accept (TCP goes to proxy via REDIRECT)

func (fw *Firewall) installFilterRules() {
	// Rule 0: drop all IPv6 traffic from the TAP interface.
	//
	// The namespace is IPv4-only (no IPv6 address on TAP, no IPv6 default
	// route) so global IPv6 egress already cannot leave the sandbox. This
	// rule is defense in depth: if IPv6 routing is ever accidentally
	// enabled, or a user assumes v6 rules in their allow/deny lists are
	// enforced, we fail closed at the firewall layer instead of silently
	// leaking. The API layer rejects v6 entries outright so users get a
	// clear error instead of surprised-by-enforcement-gap behavior.
	fw.conn.AddRule(&nftables.Rule{
		Table: fw.table,
		Chain: fw.filterChain,
		Exprs: flatten(
			fw.tapIfaceMatch(),
			protoIPv6(),
			verdictDrop(),
		),
	})

	// Rule 1: ESTABLISHED/RELATED → accept.
	fw.conn.AddRule(&nftables.Rule{
		Table: fw.table,
		Chain: fw.filterChain,
		Exprs: flatten(
			fw.tapIfaceMatch(),
			ctStateMatch(expr.CtStateBitESTABLISHED|expr.CtStateBitRELATED),
			verdictAccept(),
		),
	})

	// Rule 2: predefinedAllowSet → accept (all protocols).
	fw.addSetFilterRule(fw.predefinedAllowSet, false)

	// Rule 3: predefinedDenySet → drop (all protocols).
	fw.addSetFilterRule(fw.predefinedDenySet, true)

	// Rule 4: non-TCP + userAllowSet → accept.
	fw.addNonTCPSetFilterRule(fw.userAllowSet, false)

	// Rule 5: non-TCP + userDenySet → drop.
	fw.addNonTCPSetFilterRule(fw.userDenySet, true)
}

// addSetFilterRule matches destination IPs in a set for ALL protocols.
func (fw *Firewall) addSetFilterRule(ipSet *nftables.Set, drop bool) {
	verdict := verdictAccept()
	if drop {
		verdict = verdictDrop()
	}
	fw.conn.AddRule(&nftables.Rule{
		Table: fw.table,
		Chain: fw.filterChain,
		Exprs: flatten(
			fw.tapIfaceMatch(),
			ipv4DstLookup(ipSet),
			verdict,
		),
	})
}

// addNonTCPSetFilterRule matches only non-TCP traffic to destinations in a set.
// TCP traffic is handled by the egress proxy via REDIRECT.
func (fw *Firewall) addNonTCPSetFilterRule(ipSet *nftables.Set, drop bool) {
	verdict := verdictAccept()
	if drop {
		verdict = verdictDrop()
	}
	fw.conn.AddRule(&nftables.Rule{
		Table: fw.table,
		Chain: fw.filterChain,
		Exprs: flatten(
			fw.tapIfaceMatch(),
			protoNotTCP(),
			ipv4DstLookup(ipSet),
			verdict,
		),
	})
}

// ---------------------------------------------------------------------------
// NAT rules
// ---------------------------------------------------------------------------

func (fw *Firewall) installNATRules() {
	vmIP := mustParseAddr(fw.vmIP)
	hostIP := mustParseAddr(fw.hostIP)

	// POSTROUTING: SNAT outbound from VM IP → host IP.
	fw.conn.AddRule(&nftables.Rule{
		Table: fw.table,
		Chain: fw.postChain,
		Exprs: flatten(
			oifMatch(fw.vethPeer),
			ipv4SrcMatch(vmIP),
			snat(hostIP),
		),
	})

	// PREROUTING: DNAT inbound from host IP → VM IP.
	fw.conn.AddRule(&nftables.Rule{
		Table: fw.table,
		Chain: fw.natChain,
		Exprs: flatten(
			iifMatch(fw.vethPeer),
			ipv4DstMatch(hostIP),
			dnat(vmIP),
		),
	})
}

// ---------------------------------------------------------------------------
// MSS clamping (FORWARD chain)
// ---------------------------------------------------------------------------
//
// Prevents TLS handshake hangs caused by MTU mismatch (GCP VPC MTU 1460 vs
// default 1500). Clamps MSS in SYN packets so remote servers never send
// packets larger than the path MTU.

func (fw *Firewall) installMSSClamping() {
	synMatch := tcpSYNMatch()

	// FORWARD: clamp MSS on SYN packets.
	fw.conn.AddRule(&nftables.Rule{
		Table: fw.table,
		Chain: fw.fwdChain,
		Exprs: flatten(
			synMatch,
			mssClampToPMTU(),
		),
	})
}

// ---------------------------------------------------------------------------
// TCP REDIRECT rules for egress proxy
// ---------------------------------------------------------------------------
//
// Redirects TCP traffic from the sandbox to local proxy ports for inspection:
//   - Port 80  → httpProxyPort  (HTTP Host header inspection)
//   - Port 443 → tlsProxyPort   (TLS SNI inspection)
//   - Other    → otherProxyPort (CIDR-only)

func (fw *Firewall) installTCPRedirect() {
	veth := fw.vethPeer

	// Port 80 → HTTP proxy.
	fw.conn.AddRule(&nftables.Rule{
		Table: fw.table,
		Chain: fw.natChain,
		Exprs: flatten(
			iifMatch(veth),
			protoTCP(),
			tcpDportMatch(80),
			redirect(fw.httpProxyPort),
		),
	})

	// Port 443 → TLS proxy.
	fw.conn.AddRule(&nftables.Rule{
		Table: fw.table,
		Chain: fw.natChain,
		Exprs: flatten(
			iifMatch(veth),
			protoTCP(),
			tcpDportMatch(443),
			redirect(fw.tlsProxyPort),
		),
	})

	// All other TCP → CIDR-only proxy.
	// This rule must come after the port-specific rules.
	fw.conn.AddRule(&nftables.Rule{
		Table: fw.table,
		Chain: fw.natChain,
		Exprs: flatten(
			iifMatch(veth),
			protoTCP(),
			redirect(fw.otherProxyPort),
		),
	})
}

// ---------------------------------------------------------------------------
// ReplaceUserRules — atomic set replacement
// ---------------------------------------------------------------------------

// ReplaceUserRules atomically replaces all four IP sets in a single flush.
// Pass nil to clear user rules (default: allow all).
func (fw *Firewall) ReplaceUserRules(allowedCIDRs, deniedCIDRs []string) error {
	// 1. Predefined deny set → always-blocked private ranges.
	fw.conn.FlushSet(fw.predefinedDenySet)
	denyElems, err := cidrsToElements(DeniedCIDRs)
	if err != nil {
		return fmt.Errorf("parse denied CIDRs: %w", err)
	}
	if err := fw.conn.SetAddElements(fw.predefinedDenySet, denyElems); err != nil {
		return fmt.Errorf("populate predefined deny set: %w", err)
	}

	// 2. Predefined allow set → gateway/orchestrator IP.
	fw.conn.FlushSet(fw.predefinedAllowSet)
	allowElems, err := cidrsToElements([]string{fw.gatewayIP + "/32"})
	if err != nil {
		return fmt.Errorf("parse gateway CIDR: %w", err)
	}
	if err := fw.conn.SetAddElements(fw.predefinedAllowSet, allowElems); err != nil {
		return fmt.Errorf("populate predefined allow set: %w", err)
	}

	// 3. User deny set.
	fw.conn.FlushSet(fw.userDenySet)
	if len(deniedCIDRs) > 0 {
		if err := fw.addCIDRsToSet(fw.userDenySet, deniedCIDRs); err != nil {
			return fmt.Errorf("populate user deny set: %w", err)
		}
	}

	// 4. User allow set.
	fw.conn.FlushSet(fw.userAllowSet)
	if len(allowedCIDRs) > 0 {
		if err := fw.addCIDRsToSet(fw.userAllowSet, allowedCIDRs); err != nil {
			return fmt.Errorf("populate user allow set: %w", err)
		}
	}

	// Single atomic flush.
	if err := fw.conn.Flush(); err != nil {
		return fmt.Errorf("flush rule replacement: %w", err)
	}
	return nil
}

func (fw *Firewall) addCIDRsToSet(s *nftables.Set, cidrs []string) error {
	elems, err := cidrsToElements(cidrs)
	if err != nil {
		return err
	}
	if len(elems) == 0 {
		return nil
	}
	return fw.conn.SetAddElements(s, elems)
}

// ---------------------------------------------------------------------------
// nftables expression helpers
// ---------------------------------------------------------------------------

func flatten(parts ...[]expr.Any) []expr.Any {
	var out []expr.Any
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func verdictAccept() []expr.Any {
	return []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}
}

func verdictDrop() []expr.Any {
	return []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}}
}

// tapIfaceMatch matches packets arriving on the TAP interface.
func (fw *Firewall) tapIfaceMatch() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{
			Register: 1,
			Op:       expr.CmpOpEq,
			Data:     ifname(fw.tapIface),
		},
	}
}

func iifMatch(name string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Register: 1, Op: expr.CmpOpEq, Data: ifname(name)},
	}
}

func oifMatch(name string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Register: 1, Op: expr.CmpOpEq, Data: ifname(name)},
	}
}

// ifname returns a null-terminated, 16-byte padded interface name for nftables.
func ifname(name string) []byte {
	b := make([]byte, 16)
	copy(b, name)
	return b
}

func ctStateMatch(bits uint32) []expr.Any {
	return []expr.Any{
		&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(bits),
			Xor:            binaryutil.NativeEndian.PutUint32(0),
		},
		&expr.Cmp{
			Op:       expr.CmpOpNeq,
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(0),
		},
	}
}

func protoTCP() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Register: 1, Op: expr.CmpOpEq, Data: []byte{unix.IPPROTO_TCP}},
	}
}

func protoNotTCP() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Register: 1, Op: expr.CmpOpNeq, Data: []byte{unix.IPPROTO_TCP}},
	}
}

// protoIPv6 matches packets where the network-layer protocol is IPv6.
// Used to drop all IPv6 egress from sandbox namespaces (which are IPv4-only).
func protoIPv6() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Register: 1, Op: expr.CmpOpEq, Data: []byte{unix.NFPROTO_IPV6}},
	}
}

// ipv4DstLookup loads the IPv4 destination address and performs a set lookup.
func ipv4DstLookup(s *nftables.Set) []expr.Any {
	return []expr.Any{
		// Load IPv4 dst addr (offset 16 in network header, 4 bytes).
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       16,
			Len:          4,
		},
		&expr.Lookup{
			SourceRegister: 1,
			SetName:        s.Name,
			SetID:          s.ID,
		},
	}
}

func ipv4SrcMatch(addr netip.Addr) []expr.Any {
	a4 := addr.As4()
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
		&expr.Cmp{Register: 1, Op: expr.CmpOpEq, Data: a4[:]},
	}
}

func ipv4DstMatch(addr netip.Addr) []expr.Any {
	a4 := addr.As4()
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
		&expr.Cmp{Register: 1, Op: expr.CmpOpEq, Data: a4[:]},
	}
}

func snat(addr netip.Addr) []expr.Any {
	a4 := addr.As4()
	return []expr.Any{
		&expr.Immediate{Register: 1, Data: a4[:]},
		&expr.NAT{
			Type:       expr.NATTypeSourceNAT,
			Family:     unix.NFPROTO_IPV4,
			RegAddrMin: 1,
		},
	}
}

func dnat(addr netip.Addr) []expr.Any {
	a4 := addr.As4()
	return []expr.Any{
		&expr.Immediate{Register: 1, Data: a4[:]},
		&expr.NAT{
			Type:       expr.NATTypeDestNAT,
			Family:     unix.NFPROTO_IPV4,
			RegAddrMin: 1,
		},
	}
}

func tcpDportMatch(port uint16) []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Register: 1, Op: expr.CmpOpEq, Data: binaryutil.BigEndian.PutUint16(port)},
	}
}

func redirect(port uint16) []expr.Any {
	return []expr.Any{
		&expr.Immediate{Register: 1, Data: binaryutil.BigEndian.PutUint16(port)},
		&expr.Redir{RegisterProtoMin: 1},
	}
}

func tcpSYNMatch() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Register: 1, Op: expr.CmpOpEq, Data: []byte{unix.IPPROTO_TCP}},
		// TCP flags offset 13, check SYN set and RST clear.
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 13, Len: 1},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            1,
			Mask:           []byte{0x06}, // SYN | RST
			Xor:            []byte{0x00},
		},
		&expr.Cmp{Register: 1, Op: expr.CmpOpEq, Data: []byte{0x02}}, // SYN set, RST clear
	}
}

func mssClampToPMTU() []expr.Any {
	return []expr.Any{
		// Use the rt expression to get PMTU, then set TCP option MSS.
		// nft equivalent: tcp option maxseg size set rt mtu
		&expr.Rt{Key: expr.RtTCPMSS, Register: 1},
		&expr.Exthdr{
			SourceRegister: 1,
			Type:           2, // TCP option MSS
			Offset:         2,
			Len:            2,
			Op:             expr.ExthdrOpTcpopt,
		},
	}
}

// cidrsToElements converts CIDR strings to nftables interval set elements.
//
// Each CIDR becomes a (start, end) pair where `end` is the first address
// past the prefix range. IPv6 entries are silently skipped — they are not
// supported in these sets (a separate nftables rule drops all IPv6 egress
// wholesale, and the API layer rejects v6 entries).
//
// Edge cases handled:
//   - 0.0.0.0/0: nftables rejects the literal 0.0.0.0 as "unspecified", so
//     we emit the full-range interval [0.0.0.0, 255.255.255.255]+ directly
//     without round-tripping through prefix arithmetic.
//   - /32: the end calculation must not overflow uint32. We use uint64 math.
func cidrsToElements(cidrs []string) ([]nftables.SetElement, error) {
	var elems []nftables.SetElement
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}
		if !prefix.Addr().Is4() {
			continue
		}

		// 0.0.0.0/0 — nftables rejects 0.0.0.0 as an interval start.
		// Emit the canonical full-range pair directly.
		if cidr == AllTrafficCIDR {
			start := netip.MustParseAddr("0.0.0.0").As4()
			end := netip.MustParseAddr("255.255.255.255").As4()
			elems = append(elems,
				nftables.SetElement{Key: start[:]},
				nftables.SetElement{Key: end[:], IntervalEnd: true},
			)
			continue
		}

		s4 := prefix.Masked().Addr().As4()
		e4 := prefixEnd(prefix)
		elems = append(elems,
			nftables.SetElement{Key: s4[:]},
			nftables.SetElement{Key: e4[:], IntervalEnd: true},
		)
	}
	return elems, nil
}

// prefixEnd returns the first address past the prefix range as a 4-byte IPv4.
//
// Implementation uses uint64 to avoid the overflow that bit uint32 math
// would hit for prefixes covering 255.255.255.255/32 (where
// (0xFFFFFFFF | 0) + 1 would wrap to 0 and produce 0.0.0.0 — a
// nonsensical "end" that would create a malformed interval set element).
func prefixEnd(p netip.Prefix) [4]byte {
	addr := p.Masked().Addr().As4()
	bits := p.Bits()
	start := uint64(addr[0])<<24 | uint64(addr[1])<<16 | uint64(addr[2])<<8 | uint64(addr[3])
	size := uint64(1) << uint(32-bits)
	end := start + size
	if end > 0xFFFFFFFF {
		end = 0xFFFFFFFF
	}
	return [4]byte{
		byte(end >> 24),
		byte(end >> 16),
		byte(end >> 8),
		byte(end),
	}
}

func mustParseAddr(s string) netip.Addr {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		panic("invalid IP: " + s)
	}
	return addr
}
