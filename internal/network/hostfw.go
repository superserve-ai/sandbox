package network

// hostfw.go installs the host-level iptables rules that route VM traffic.
// Rules match by interface-prefix (veth+) and subnet (vmIPRange) and assume
// vmd owns the host's filter/FORWARD, nat/PREROUTING, and nat/POSTROUTING
// chains. On a cohabitated host (Docker, kubelet, ...) veth+ would catch
// foreign interfaces; rules would need to move into vmd-owned custom chains.

import (
	"context"
	"fmt"
	"net"
	"os/exec"

	"github.com/coreos/go-iptables/iptables"
	"github.com/rs/zerolog"
)

// vmIPRange must contain every host IP that hostIPForSlot can return.
const vmIPRange = "10.11.0.0/16"

// portDropChain is the vmd-owned filter chain holding the operator-configured
// egress port drops. Kept separate from FORWARD so it can be flushed and
// rebuilt on each start, reconciling away ports removed from config.
const portDropChain = "SANDBOX_EGRESS_PORTS"

// dnsRedirectChain is the vmd-owned nat chain holding the optional guest DNS
// redirect. Same reconcile pattern as portDropChain: flushed and rebuilt on
// each start, so changing or unsetting the resolver port never leaves a stale
// REDIRECT behind.
const dnsRedirectChain = "SANDBOX_DNS_REDIRECT"

// installHostFirewall installs the static rules that route all VM traffic
// through the host: UDP/443 DROP (kills QUIC bypass of the SNI allowlist),
// operator-configured egress port DROPs, MSS clamp, FORWARD ACCEPT between
// veth+ and the host iface, MASQUERADE for vmIPRange to the host iface,
// REDIRECT HTTP/HTTPS from veth+ to the egress proxy, and an optional
// REDIRECT of all guest DNS to an operator-run resolver. All operations are
// idempotent.
//
// blockedPorts come from the operator blocklist config — only ports 80/443
// are redirected through the egress proxy, so anything else a VM dials goes
// straight through FORWARD and must be dropped here.
//
// dnsRedirectPort, when non-zero, redirects all VM DNS (TCP and UDP dport
// 53) to that port on the host, where the operator runs a resolver. The
// redirect is transparent: it applies no matter which nameserver the guest
// image has configured.
//
// manageOwnedChains gates ownership of the shared vmd-owned chains
// (SANDBOX_EGRESS_PORTS, SANDBOX_DNS_REDIRECT): only the vmd daemon
// reconciles them. Auxiliary managers pass false so a concurrent template
// build does not flush the daemon's rules.
func installHostFirewall(hostIface string, httpProxyPort, tlsProxyPort, dnsRedirectPort uint16, blockedPorts []uint16, manageOwnedChains bool, log zerolog.Logger) error {
	_, ipnet, err := net.ParseCIDR(vmIPRange)
	if err != nil {
		return fmt.Errorf("vmIPRange %s invalid: %w", vmIPRange, err)
	}
	if !ipnet.Contains(net.ParseIP(hostIPForSlot(0))) || !ipnet.Contains(net.ParseIP(hostIPForSlot(MaxSlots-1))) {
		return fmt.Errorf("vmIPRange %s does not cover the full slot allocation range", vmIPRange)
	}

	ipt, err := iptables.New()
	if err != nil {
		return fmt.Errorf("init iptables: %w", err)
	}

	// UDP/443 DROP must precede the veth+ ACCEPT below so QUIC traffic
	// (which would bypass the SNI allowlist) is dropped before the broad
	// ACCEPT terminates the chain walk. This rule is static.
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

	// Operator-configured egress port drops live in a vmd-owned chain so the
	// live ruleset stays in sync with config. ClearChain creates-or-flushes,
	// so a port removed from blockedPorts since the last start is dropped
	// from the chain instead of lingering in FORWARD forever. The chain is
	// entered via a single jump for veth+ traffic, placed before the ACCEPT.
	//
	// Only the chain owner (vmd) touches it. An auxiliary manager flushing
	// the shared chain would wipe the daemon's port drops for the duration
	// of, e.g., a template build.
	if manageOwnedChains {
		if err := ipt.ClearChain("filter", portDropChain); err != nil {
			return fmt.Errorf("reset %s chain: %w", portDropChain, err)
		}
		dropPorts := blockedPorts
		if dnsRedirectPort > 0 {
			// The DNS redirect below only captures plain DNS on port 53.
			// Encrypted DNS on its dedicated port (DoT/DoQ, 853) would
			// silently sidestep the operator's resolver, so it is dropped
			// whenever the redirect is active.
			dropPorts = append(append([]uint16(nil), blockedPorts...), 853)
		}
		for _, port := range dropPorts {
			for _, proto := range []string{"tcp", "udp"} {
				if err := ipt.AppendUnique("filter", portDropChain,
					"-p", proto, "--dport", fmt.Sprintf("%d", port), "-j", "DROP"); err != nil {
					return fmt.Errorf("add %s/%d DROP to %s: %w", proto, port, portDropChain, err)
				}
			}
		}
		portJump := []string{"-i", "veth+", "-j", portDropChain}
		exists, err = ipt.Exists("filter", "FORWARD", portJump...)
		if err != nil {
			return fmt.Errorf("check %s jump: %w", portDropChain, err)
		}
		if !exists {
			if err := ipt.Insert("filter", "FORWARD", 1, portJump...); err != nil {
				return fmt.Errorf("insert %s jump: %w", portDropChain, err)
			}
		}

		// Guest DNS redirect, in its own vmd-owned nat chain. The jump is
		// installed unconditionally; with the feature off the chain is
		// empty and the jump is a no-op, which is also what reconciles
		// away a redirect removed from config.
		if err := ipt.ClearChain("nat", dnsRedirectChain); err != nil {
			return fmt.Errorf("reset %s chain: %w", dnsRedirectChain, err)
		}
		for _, args := range dnsRedirectRules(dnsRedirectPort) {
			if err := ipt.AppendUnique("nat", dnsRedirectChain, args...); err != nil {
				return fmt.Errorf("add DNS redirect to %s: %w", dnsRedirectChain, err)
			}
		}
		dnsJump := []string{"-i", "veth+", "-j", dnsRedirectChain}
		exists, err = ipt.Exists("nat", "PREROUTING", dnsJump...)
		if err != nil {
			return fmt.Errorf("check %s jump: %w", dnsRedirectChain, err)
		}
		if !exists {
			if err := ipt.Insert("nat", "PREROUTING", 1, dnsJump...); err != nil {
				return fmt.Errorf("insert %s jump: %w", dnsRedirectChain, err)
			}
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

	log.Info().Str("host_iface", hostIface).Msg("host firewall ready (static prefix rules)")
	return nil
}

// dnsRedirectRules returns the nat rules for the guest DNS redirect: all TCP
// and UDP traffic destined to port 53 — whatever resolver address the guest
// has configured — is redirected to the operator's resolver port on the
// host. Returns nil when the feature is disabled (port 0).
func dnsRedirectRules(port uint16) [][]string {
	if port == 0 {
		return nil
	}
	var rules [][]string
	for _, proto := range []string{"udp", "tcp"} {
		rules = append(rules, []string{
			"-p", proto, "--dport", "53",
			"-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", port),
		})
	}
	return rules
}

// enableIPForward enables IPv4 forwarding. Called once during Manager init.
func enableIPForward(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "sysctl", "-w", "net.ipv4.ip_forward=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("enable ip_forward: %s: %w", string(out), err)
	}
	return nil
}
