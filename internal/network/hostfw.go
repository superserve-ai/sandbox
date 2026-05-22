package network

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/coreos/go-iptables/iptables"
	"github.com/rs/zerolog"
)

// hostFirewallAPI is the Manager's view of *HostFirewall, stubbed by tests.
type hostFirewallAPI interface {
	AddVM(vmID, vethName, hostCIDR string) error
	RemoveVM(vmID string) error
	Close() error
}

// vmIPRange must match Manager's host-IP allocation scheme.
const vmIPRange = "10.11.0.0/16"

// HostFirewall installs static iptables rules covering all VMs via the
// veth+ interface prefix and vmIPRange subnet: FORWARD ACCEPT, MSS clamp,
// POSTROUTING MASQUERADE, PREROUTING REDIRECT to the egress proxy, and a
// UDP/443 DROP so QUIC can't bypass the SNI allowlist. Idempotent.
type HostFirewall struct{}

// NewHostFirewall installs the rules. Idempotent.
func NewHostFirewall(hostIface string, httpProxyPort, tlsProxyPort uint16, log zerolog.Logger) (*HostFirewall, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, fmt.Errorf("init iptables: %w", err)
	}
	if err := installRules(ipt, hostIface, httpProxyPort, tlsProxyPort); err != nil {
		return nil, err
	}
	log.Info().Str("host_iface", hostIface).Msg("host firewall ready (static prefix rules)")
	return &HostFirewall{}, nil
}

func installRules(ipt *iptables.IPTables, hostIface string, httpProxyPort, tlsProxyPort uint16) error {
	// UDP/443 DROP at position 1 so QUIC is dropped before the broad
	// veth+ ACCEPT below terminates the chain walk.
	udpDrop := []string{"-i", "veth+", "-p", "udp", "--dport", "443", "-j", "DROP"}
	exists, err := ipt.Exists("filter", "FORWARD", udpDrop...)
	if err != nil {
		return fmt.Errorf("check veth+ UDP/443 DROP: %w", err)
	}
	if !exists {
		if err := ipt.Insert("filter", "FORWARD", 1, udpDrop...); err != nil {
			return fmt.Errorf("insert veth+ UDP/443 DROP: %w", err)
		}
	}

	if err := ipt.AppendUnique("filter", "FORWARD",
		"-o", hostIface,
		"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS", "--clamp-mss-to-pmtu",
	); err != nil {
		return fmt.Errorf("add MSS clamp: %w", err)
	}

	type rule struct {
		table, chain string
		args         []string
	}
	rules := []rule{
		{"filter", "FORWARD", []string{"-i", "veth+", "-o", hostIface, "-j", "ACCEPT"}},
		{"filter", "FORWARD", []string{"-i", hostIface, "-o", "veth+", "-j", "ACCEPT"}},
		{"nat", "POSTROUTING", []string{"-s", vmIPRange, "-o", hostIface, "-j", "MASQUERADE"}},
	}
	if httpProxyPort > 0 {
		rules = append(rules, rule{"nat", "PREROUTING",
			[]string{"-i", "veth+", "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", httpProxyPort)}})
	}
	if tlsProxyPort > 0 {
		rules = append(rules, rule{"nat", "PREROUTING",
			[]string{"-i", "veth+", "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", tlsProxyPort)}})
	}
	for _, r := range rules {
		if err := ipt.AppendUnique(r.table, r.chain, r.args...); err != nil {
			return fmt.Errorf("add %s/%s rule: %w", r.table, r.chain, err)
		}
	}
	return nil
}

// Per-VM hooks are no-ops — the static rules above cover every veth.

func (hfw *HostFirewall) AddVM(vmID, vethName, hostCIDR string) error { return nil }
func (hfw *HostFirewall) RemoveVM(vmID string) error                  { return nil }
func (hfw *HostFirewall) Close() error                                { return nil }

// enableIPForward enables IPv4 forwarding. Called once during Manager init.
func enableIPForward(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "sysctl", "-w", "net.ipv4.ip_forward=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("enable ip_forward: %s: %w", string(out), err)
	}
	return nil
}
