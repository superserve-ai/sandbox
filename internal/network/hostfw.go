package network

import (
	"context"
	"fmt"
	"os/exec"
	"sync"

	"github.com/coreos/go-iptables/iptables"
	"github.com/rs/zerolog"
)

// HostFirewall manages host-level iptables rules for VM internet access.
// Appends per-VM rules to the kernel's built-in chains:
//   - filter/FORWARD: allow traffic between each VM's veth and the host interface
//   - nat/POSTROUTING: MASQUERADE outbound traffic from each VM's host IP
//   - nat/PREROUTING: REDIRECT HTTP to the egress proxy for domain filtering
//   - filter/FORWARD: MSS clamping on forwarded TCP SYN packets
//
// Uses coreos/go-iptables (append to built-in chains, no custom table).
// Rules persist in the kernel across vmd restarts — leaked rules from
// prior lifetimes match dead veths and are harmless.
type HostFirewall struct {
	mu sync.Mutex

	ipt       *iptables.IPTables
	hostIface string

	httpProxyPort uint16 // egress proxy HTTP inspection port
	tlsProxyPort  uint16 // egress proxy TLS/SNI inspection port

	// Per-VM rule specs for cleanup.
	vmRules map[string][]vmRule
}

type vmRule struct {
	table   string
	chain   string
	args    []string
	prepend bool // insert at top of chain instead of appending
}

// NewHostFirewall initializes the host firewall. On first call it adds
// a static MSS clamp rule. On restart, existing per-VM rules from the
// previous process are already in the kernel (iptables rules persist)
// and will be cleaned up when RemoveVM is called — or leaked harmlessly
// if the VM was already destroyed.
func NewHostFirewall(hostIface string, httpProxyPort, tlsProxyPort uint16, log zerolog.Logger) (*HostFirewall, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, fmt.Errorf("init iptables: %w", err)
	}

	hfw := &HostFirewall{
		ipt:           ipt,
		hostIface:     hostIface,
		httpProxyPort: httpProxyPort,
		tlsProxyPort:  tlsProxyPort,
		vmRules:       make(map[string][]vmRule),
	}

	// Static MSS clamp: applies to all forwarded TCP SYN packets going
	// out via the host interface. Idempotent — AppendUnique is a no-op
	// if the rule already exists from a prior vmd lifetime.
	mssArgs := []string{
		"-o", hostIface,
		"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS", "--clamp-mss-to-pmtu",
	}
	if err := ipt.AppendUnique("filter", "FORWARD", mssArgs...); err != nil {
		return nil, fmt.Errorf("add MSS clamp rule: %w", err)
	}

	log.Info().Str("host_iface", hostIface).Msg("host firewall ready (iptables)")
	return hfw, nil
}

// AddVM adds FORWARD + MASQUERADE rules for a VM's veth interface.
func (hfw *HostFirewall) AddVM(vmID, vethName, hostCIDR string) error {
	hfw.mu.Lock()
	defer hfw.mu.Unlock()

	rules := []vmRule{}
	// Drop UDP/443 so QUIC can't bypass the TCP-only REDIRECT + SNI
	// allowlist. Must be inserted above the per-veth ACCEPT below.
	if hfw.tlsProxyPort > 0 {
		rules = append(rules, vmRule{
			table: "filter", chain: "FORWARD",
			args:    []string{"-i", vethName, "-p", "udp", "--dport", "443", "-j", "DROP"},
			prepend: true,
		})
	}
	rules = append(rules,
		// FORWARD: veth → host interface (outbound)
		vmRule{table: "filter", chain: "FORWARD", args: []string{"-i", vethName, "-o", hfw.hostIface, "-j", "ACCEPT"}},
		// FORWARD: host interface → veth (inbound/response)
		vmRule{table: "filter", chain: "FORWARD", args: []string{"-i", hfw.hostIface, "-o", vethName, "-j", "ACCEPT"}},
		// POSTROUTING: MASQUERADE outbound from this VM's host IP
		vmRule{table: "nat", chain: "POSTROUTING", args: []string{"-s", hostCIDR, "-o", hfw.hostIface, "-j", "MASQUERADE"}},
	)
	if hfw.httpProxyPort > 0 {
		rules = append(rules, vmRule{
			table: "nat", chain: "PREROUTING",
			args: []string{"-i", vethName, "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", hfw.httpProxyPort)},
		})
	}
	if hfw.tlsProxyPort > 0 {
		rules = append(rules, vmRule{
			table: "nat", chain: "PREROUTING",
			args: []string{"-i", vethName, "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", hfw.tlsProxyPort)},
		})
	}

	for _, r := range rules {
		if r.prepend {
			// Exists-check keeps Insert idempotent across vmd restarts.
			exists, err := hfw.ipt.Exists(r.table, r.chain, r.args...)
			if err != nil {
				return fmt.Errorf("check %s/%s rule for %s: %w", r.table, r.chain, vmID, err)
			}
			if !exists {
				if err := hfw.ipt.Insert(r.table, r.chain, 1, r.args...); err != nil {
					return fmt.Errorf("insert %s/%s rule for %s: %w", r.table, r.chain, vmID, err)
				}
			}
			continue
		}
		if err := hfw.ipt.AppendUnique(r.table, r.chain, r.args...); err != nil {
			return fmt.Errorf("add %s/%s rule for %s: %w", r.table, r.chain, vmID, err)
		}
	}

	hfw.vmRules[vmID] = rules
	return nil
}

// RemoveVM removes all host-level rules for a VM. Errors are logged
// but don't prevent cleanup of remaining rules — a leaked iptables
// rule is harmless (matches a veth/IP that no longer exists).
func (hfw *HostFirewall) RemoveVM(vmID string) error {
	hfw.mu.Lock()
	defer hfw.mu.Unlock()

	rules, ok := hfw.vmRules[vmID]
	if !ok {
		return nil
	}

	var firstErr error
	for _, r := range rules {
		if err := hfw.ipt.DeleteIfExists(r.table, r.chain, r.args...); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("delete %s/%s rule for %s: %w", r.table, r.chain, vmID, err)
		}
	}

	delete(hfw.vmRules, vmID)
	return firstErr
}

// Close removes all VM rules we've tracked during this vmd lifetime.
// Rules from prior lifetimes (if any) are left in the kernel — they
// match veths/IPs that no longer exist and are effectively dead.
func (hfw *HostFirewall) Close() error {
	hfw.mu.Lock()
	defer hfw.mu.Unlock()

	for vmID, rules := range hfw.vmRules {
		for _, r := range rules {
			_ = hfw.ipt.DeleteIfExists(r.table, r.chain, r.args...)
		}
		delete(hfw.vmRules, vmID)
	}

	return nil
}

// enableIPForward enables IPv4 forwarding. Called once during Manager init.
func enableIPForward(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "sysctl", "-w", "net.ipv4.ip_forward=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("enable ip_forward: %s: %w", string(out), err)
	}
	return nil
}
