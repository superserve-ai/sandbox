package network

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
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

// NewHostFirewall creates a host-level nftables table. Must be called from the host namespace.
func NewHostFirewall(hostIface string) (*HostFirewall, error) {
	conn, err := nftables.New(nftables.AsLasting())
	if err != nil {
		return nil, fmt.Errorf("new nftables conn: %w", err)
	}

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
func (hfw *HostFirewall) RemoveVM(vmID string) error {
	hfw.mu.Lock()
	defer hfw.mu.Unlock()

	handles, ok := hfw.vmRuleHandles[vmID]
	if !ok {
		return nil
	}
	delete(hfw.vmRuleHandles, vmID)

	// Delete rules from both chains by handle.
	// We need to find which chain each handle belongs to, so query both.
	fwdRules, _ := hfw.conn.GetRules(hfw.table, hfw.fwdChain)
	natRules, _ := hfw.conn.GetRules(hfw.table, hfw.natChain)

	handleSet := make(map[uint64]bool, len(handles))
	for _, h := range handles {
		handleSet[h] = true
	}

	for _, r := range fwdRules {
		if handleSet[r.Handle] {
			_ = hfw.conn.DelRule(r)
		}
	}
	for _, r := range natRules {
		if handleSet[r.Handle] {
			_ = hfw.conn.DelRule(r)
		}
	}

	if err := hfw.conn.Flush(); err != nil {
		return fmt.Errorf("flush rule deletion: %w", err)
	}
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

