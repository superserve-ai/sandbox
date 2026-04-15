package network

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/rs/zerolog"
)

const hostTableName = "sandbox-host"

// HostFirewall manages host-level nftables rules shared across all VMs.
// It handles:
//   - FORWARD rules between each VM's veth and the host interface
//   - MASQUERADE for outbound internet
//   - MSS clamping on forwarded traffic
//
// One HostFirewall is created per Manager and lives for the lifetime of the VMD process.
type HostFirewall struct {
	mu sync.Mutex

	conn  *nftables.Conn
	table *nftables.Table

	fwdChain *nftables.Chain // FORWARD: per-VM accept rules + MSS clamping
	natChain *nftables.Chain // POSTROUTING: per-VM MASQUERADE

	hostIface string

	// Per-VM rule handles for cleanup. Populated by reading back from kernel after Flush.
	vmRuleHandles map[string][]uint64 // vmID → rule handles
}

// NewHostFirewall creates a host-level nftables table, or reuses one that
// already exists in the kernel from a previous vmd lifetime.
//
// Restart safety:
//
//	nftables' NEWCHAIN netlink message REPLACES an existing chain of the
//	same name, which drops every rule inside it. Naive re-adding of the
//	"forward" and "postrouting" chains on every startup therefore wipes
//	the per-VM MASQUERADE/FORWARD rules for every VM that was already
//	running, leaving them internet-less. The bug manifested as DNS
//	timeouts inside template build VMs whose slot was claimed after a
//	vmd restart (see docs/sandbox-templates-v2.md#known-gaps).
//
// To avoid that, this constructor looks for an existing table first.
// When found, it fetches the live chain objects, preserves every rule,
// and rehydrates vmRuleHandles by reading back the per-VM rules — they
// carry the vmID in their UserData field, so the mapping is recoverable
// without any out-of-band bookkeeping. Only on a cold start do we create
// the table, chains, and static MSS clamp rule.
//
// Must be called from the host namespace.
func NewHostFirewall(hostIface string, log zerolog.Logger) (*HostFirewall, error) {
	conn, err := nftables.New(nftables.AsLasting())
	if err != nil {
		return nil, fmt.Errorf("new nftables conn: %w", err)
	}

	existing, existsErr := findExistingHostTable(conn)
	if existsErr != nil {
		conn.CloseLasting()
		return nil, fmt.Errorf("probe existing host firewall: %w", existsErr)
	}

	if existing != nil {
		hfw, err := reuseExistingHostFirewall(conn, existing, hostIface)
		if err != nil {
			conn.CloseLasting()
			return nil, fmt.Errorf("reuse existing host firewall: %w", err)
		}
		log.Info().
			Str("mode", "reused").
			Int("rehydrated_vms", len(hfw.vmRuleHandles)).
			Msg("host firewall ready")
		return hfw, nil
	}

	hfw, err := createFreshHostFirewall(conn, hostIface)
	if err != nil {
		return nil, err
	}
	log.Info().Str("mode", "fresh").Msg("host firewall ready")
	return hfw, nil
}

// findExistingHostTable returns the previously-created "sandbox-host"
// table if one is present in the kernel, or nil if this is a cold start.
func findExistingHostTable(conn *nftables.Conn) (*nftables.Table, error) {
	tables, err := conn.ListTables()
	if err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}
	for _, t := range tables {
		if t.Name == hostTableName && t.Family == nftables.TableFamilyIPv4 {
			return t, nil
		}
	}
	return nil, nil
}

// reuseExistingHostFirewall wires up a HostFirewall to a pre-existing
// kernel table + chains and rebuilds the vmRuleHandles map from the
// UserData tag we stamp on every per-VM rule at AddVM time. This is the
// restart-recovery path — any VM we had rules for before the restart
// stays connected, and we can still clean up those rules later.
func reuseExistingHostFirewall(conn *nftables.Conn, table *nftables.Table, hostIface string) (*HostFirewall, error) {
	chains, err := conn.ListChainsOfTableFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return nil, fmt.Errorf("list chains: %w", err)
	}

	var fwdChain, natChain *nftables.Chain
	for _, c := range chains {
		if c.Table == nil || c.Table.Name != hostTableName {
			continue
		}
		switch c.Name {
		case "forward":
			fwdChain = c
		case "postrouting":
			natChain = c
		}
	}
	if fwdChain == nil || natChain == nil {
		// Table exists but our chains don't — likely a corrupted prior state.
		// Safer to fail than to call AddChain and risk wiping half a table.
		return nil, fmt.Errorf("host table %q present but expected chains missing (forward=%v, postrouting=%v)", hostTableName, fwdChain != nil, natChain != nil)
	}

	handles, err := rehydrateVMRuleHandles(conn, table, fwdChain, natChain)
	if err != nil {
		return nil, fmt.Errorf("rehydrate vm rule handles: %w", err)
	}

	return &HostFirewall{
		conn:          conn,
		table:         table,
		fwdChain:      fwdChain,
		natChain:      natChain,
		hostIface:     hostIface,
		vmRuleHandles: handles,
	}, nil
}

// rehydrateVMRuleHandles walks the existing forward/postrouting rules
// and groups their handles by the vmID carried in UserData. Rules with
// no UserData (the static MSS clamp) are skipped. Used only on the
// restart path.
func rehydrateVMRuleHandles(conn *nftables.Conn, table *nftables.Table, fwd, nat *nftables.Chain) (map[string][]uint64, error) {
	handles := make(map[string][]uint64)

	fwdRules, err := conn.GetRules(table, fwd)
	if err != nil {
		return nil, fmt.Errorf("get forward rules: %w", err)
	}
	for _, r := range fwdRules {
		if len(r.UserData) == 0 {
			continue
		}
		vmID := string(r.UserData)
		handles[vmID] = append(handles[vmID], r.Handle)
	}

	natRules, err := conn.GetRules(table, nat)
	if err != nil {
		return nil, fmt.Errorf("get nat rules: %w", err)
	}
	for _, r := range natRules {
		if len(r.UserData) == 0 {
			continue
		}
		vmID := string(r.UserData)
		handles[vmID] = append(handles[vmID], r.Handle)
	}

	return handles, nil
}

// createFreshHostFirewall is the cold-start path: create the table,
// chains, and static MSS clamp rule. Only runs when no prior vmd has
// left a host table on this kernel.
func createFreshHostFirewall(conn *nftables.Conn, hostIface string) (*HostFirewall, error) {
	table := conn.AddTable(&nftables.Table{
		Name:   hostTableName,
		Family: nftables.TableFamilyIPv4,
	})

	acceptPolicy := nftables.ChainPolicyAccept

	fwdChain := conn.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &acceptPolicy,
	})

	natChain := conn.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
		Policy:   &acceptPolicy,
	})

	// Static rule: MSS clamping on all forwarded TCP SYN packets going out via host interface.
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: fwdChain,
		Exprs: flatten(
			oifMatch(hostIface),
			tcpSYNMatch(),
			mssClampToPMTU(),
		),
	})

	if err := conn.Flush(); err != nil {
		conn.CloseLasting()
		return nil, fmt.Errorf("flush host firewall: %w", err)
	}

	return &HostFirewall{
		conn:          conn,
		table:         table,
		fwdChain:      fwdChain,
		natChain:      natChain,
		hostIface:     hostIface,
		vmRuleHandles: make(map[string][]uint64),
	}, nil
}

// AddVM adds forwarding and MASQUERADE rules for a VM's veth interface.
func (hfw *HostFirewall) AddVM(vmID, vethName, hostCIDR string) error {
	hfw.mu.Lock()
	defer hfw.mu.Unlock()

	hostPrefix, err := netip.ParsePrefix(hostCIDR)
	if err != nil {
		return fmt.Errorf("parse host CIDR: %w", err)
	}
	srcIP := hostPrefix.Addr().As4()

	// Snapshot current rule count so we can identify new rules after flush.
	fwdBefore, err := hfw.conn.GetRules(hfw.table, hfw.fwdChain)
	if err != nil {
		return fmt.Errorf("get forward rules: %w", err)
	}
	natBefore, err := hfw.conn.GetRules(hfw.table, hfw.natChain)
	if err != nil {
		return fmt.Errorf("get nat rules: %w", err)
	}

	// FORWARD: veth → host interface (outbound).
	hfw.conn.AddRule(&nftables.Rule{
		Table:    hfw.table,
		Chain:    hfw.fwdChain,
		UserData: []byte(vmID),
		Exprs: flatten(
			iifMatch(vethName),
			oifMatch(hfw.hostIface),
			verdictAccept(),
		),
	})

	// FORWARD: host interface → veth (inbound/response).
	hfw.conn.AddRule(&nftables.Rule{
		Table:    hfw.table,
		Chain:    hfw.fwdChain,
		UserData: []byte(vmID),
		Exprs: flatten(
			iifMatch(hfw.hostIface),
			oifMatch(vethName),
			verdictAccept(),
		),
	})

	// POSTROUTING: MASQUERADE outbound traffic from this VM's host IP.
	hfw.conn.AddRule(&nftables.Rule{
		Table:    hfw.table,
		Chain:    hfw.natChain,
		UserData: []byte(vmID),
		Exprs: flatten(
			oifMatch(hfw.hostIface),
			[]expr.Any{
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
				&expr.Cmp{Register: 1, Op: expr.CmpOpEq, Data: srcIP[:]},
			},
			[]expr.Any{&expr.Masq{}},
		),
	})

	if err := hfw.conn.Flush(); err != nil {
		return fmt.Errorf("flush VM rules: %w", err)
	}

	// Read back rules from kernel to get handles for the rules we just added.
	var handles []uint64

	fwdAfter, err := hfw.conn.GetRules(hfw.table, hfw.fwdChain)
	if err != nil {
		return fmt.Errorf("get forward rules after flush: %w", err)
	}
	for _, r := range fwdAfter {
		if isNewRule(r, fwdBefore) && string(r.UserData) == vmID {
			handles = append(handles, r.Handle)
		}
	}

	natAfter, err := hfw.conn.GetRules(hfw.table, hfw.natChain)
	if err != nil {
		return fmt.Errorf("get nat rules after flush: %w", err)
	}
	for _, r := range natAfter {
		if isNewRule(r, natBefore) && string(r.UserData) == vmID {
			handles = append(handles, r.Handle)
		}
	}

	hfw.vmRuleHandles[vmID] = handles
	return nil
}

// RemoveVM removes all host-level rules for a VM using stored handles.
//
// If any step fails, the handles are kept in vmRuleHandles so a caller can
// retry. Silently dropping errors here used to leak rules into the kernel
// permanently — both a resource leak and a security issue (stale FORWARD
// ACCEPT and MASQUERADE for a VM that no longer exists).
func (hfw *HostFirewall) RemoveVM(vmID string) error {
	hfw.mu.Lock()
	defer hfw.mu.Unlock()

	handles, ok := hfw.vmRuleHandles[vmID]
	if !ok {
		return nil
	}

	// Build a lookup once.
	handleSet := make(map[uint64]bool, len(handles))
	for _, h := range handles {
		handleSet[h] = true
	}

	// Query both chains. If GetRules fails, surface the error — we cannot
	// safely delete by handle without knowing which chain each handle
	// belongs to, and we must NOT drop the handles from vmRuleHandles or
	// a retry will have nothing to work with.
	fwdRules, err := hfw.conn.GetRules(hfw.table, hfw.fwdChain)
	if err != nil {
		return fmt.Errorf("get forward rules for cleanup: %w", err)
	}
	natRules, err := hfw.conn.GetRules(hfw.table, hfw.natChain)
	if err != nil {
		return fmt.Errorf("get nat rules for cleanup: %w", err)
	}

	// Enqueue deletes for every matching rule.
	matched := 0
	for _, r := range fwdRules {
		if handleSet[r.Handle] {
			if err := hfw.conn.DelRule(r); err != nil {
				return fmt.Errorf("delete forward rule handle %d: %w", r.Handle, err)
			}
			matched++
		}
	}
	for _, r := range natRules {
		if handleSet[r.Handle] {
			if err := hfw.conn.DelRule(r); err != nil {
				return fmt.Errorf("delete nat rule handle %d: %w", r.Handle, err)
			}
			matched++
		}
	}

	// Flush to the kernel. Only remove the VM from the tracking map on
	// success — if flush fails, a retry can try again.
	if err := hfw.conn.Flush(); err != nil {
		return fmt.Errorf("flush rule deletion for vm %s: %w", vmID, err)
	}

	delete(hfw.vmRuleHandles, vmID)
	return nil
}

// Close tears down the host firewall and removes all rules.
func (hfw *HostFirewall) Close() error {
	hfw.mu.Lock()
	defer hfw.mu.Unlock()

	if hfw.conn == nil {
		return nil
	}
	hfw.conn.DelTable(hfw.table)
	_ = hfw.conn.Flush()
	err := hfw.conn.CloseLasting()
	hfw.conn = nil
	return err
}

// isNewRule checks if a rule (by handle) exists in the "before" snapshot.
func isNewRule(r *nftables.Rule, before []*nftables.Rule) bool {
	for _, b := range before {
		if b.Handle == r.Handle {
			return false
		}
	}
	return true
}

// enableIPForward enables IPv4 forwarding. Called once during Manager init.
func enableIPForward(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "sysctl", "-w", "net.ipv4.ip_forward=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("enable ip_forward: %s: %w", string(out), err)
	}
	return nil
}

