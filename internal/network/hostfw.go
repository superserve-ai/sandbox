package network

// hostfw.go installs the host-level iptables rules that route VM traffic.
// Rules match by interface-prefix (veth+) and subnet (vmIPRange) and live in
// vmd-owned chains: the shared built-in chains carry only veth-scoped jumps
// into them (plus the source-scoped MASQUERADE), so on a cohabitated host
// (Docker, kubelet, ...) the other agents' rules and vmd's cannot interfere.

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strings"

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

// forwardChain is the vmd-owned filter chain that fully decides sandbox
// forwarding. FORWARD keeps only two veth-scoped jumps into it; the chain
// ends in an unconditional DROP, so sandbox traffic never falls back into
// FORWARD where another agent's rules could act on it.
const forwardChain = "SANDBOX_FORWARD"

// preroutingChain is the vmd-owned nat chain holding the guest-facing
// redirects (DNS resolver, HTTP/TLS egress proxy, secrets proxy), entered
// via a single veth-scoped jump at the head of PREROUTING.
const preroutingChain = "SANDBOX_PREROUTING"

// sandboxVethPattern matches exactly vmd's own interfaces (veth-<slot>) and
// nothing else. A bare veth+ would also capture other agents' veth-named
// interfaces (Docker's auto-generated vethXXXX ports, hand-made pairs) and
// pull their traffic into the sandbox chains — through to the terminal DROP.
const sandboxVethPattern = "veth-+"

// vmdOwnedChains names every chain vmd creates and reconciles. A rule that
// jumps into one of them is vmd's regardless of marker: the chain namespace
// itself is ours.
var vmdOwnedChains = map[string]bool{
	portDropChain:    true,
	dnsRedirectChain: true,
	forwardChain:     true,
	preroutingChain:  true,
}

// installHostFirewall installs the rules that route all VM traffic through
// the host. The owner builds the vmd-owned chains (flush + rebuild, so config
// changes reconcile): SANDBOX_FORWARD with the UDP/443 DROP (kills QUIC
// bypass of the SNI allowlist), the operator-configured egress port DROPs,
// the MSS clamp, the veth+↔host-iface ACCEPTs, and a terminal DROP;
// SANDBOX_PREROUTING with the optional guest DNS redirect, the HTTP/HTTPS
// egress proxy REDIRECTs, and (when secretsProxyPort > 0) the secrets proxy
// REDIRECT. The shared chains get only veth-scoped jumps into those, plus
// the vmIPRange MASQUERADE. All operations are idempotent.
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
// manageOwnedChains gates ownership of the vmd-owned chains and their entry
// jumps: only the vmd daemon reconciles them. Auxiliary managers (the
// template-builder) pass false and install just the MASQUERADE — the daemon
// on the same host provides the rest of the topology.
func installHostFirewall(hostIface string, httpProxyPort, tlsProxyPort, dnsRedirectPort uint16, secretsProxyDst string, secretsProxyPort uint16, blockedPorts []uint16, manageOwnedChains bool, log zerolog.Logger) error {
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

	// Owner topology — the owned chains and the shared-chain entry jumps —
	// is NOT installed here. Shared-chain ordering must be planned from a
	// locked pre-mutation snapshot so foreign policy is never silently
	// demoted; ensureHostFirewall owns that sequence (rebuildOwnedChains +
	// repairSharedOrdering). A blind insert-at-head from this installer was
	// exactly the bypass the planner exists to prevent.
	if manageOwnedChains {
		return fmt.Errorf("owner install must go through ensureHostFirewall (planned shared-chain ordering)")
	}

	if err := ipt.AppendUnique("nat", "POSTROUTING", marked(
		"-s", vmIPRange, "-o", hostIface, "-j", "MASQUERADE")...); err != nil {
		return fmt.Errorf("add MASQUERADE: %w", err)
	}
	// Async: callers may hold the cooperating-writer lock; an informational
	// write must not extend the hold.
	go func() {
		log.Info().
			Str("host_iface", hostIface).
			Str("secrets_proxy_dst", secretsProxyDst).
			Uint16("secrets_proxy_port", secretsProxyPort).
			Msg("host firewall ready (static prefix rules)")
	}()
	return nil
}

// rebuildOwnedChains rebuilds the vmd-owned chains ATOMICALLY, one
// iptables-restore transaction per table. The live entry jumps keep
// referencing these chains throughout the slow path, so a
// flush-and-repopulate through individual commands would open a window where
// sandbox traffic falls through an empty chain into the foreign FORWARD
// rules — and a failure mid-repopulation would strand it there. A declared
// chain inside a --noflush restore is created-or-flushed and refilled in a
// single commit; on error the previous contents remain. Each chain gets an
// explicit -F inside the transaction — --noflush preserves existing contents
// on the legacy backend, so relying on the declaration alone to clear a
// pre-existing chain would append after stale rules there. Contents come
// from the same spec the verifier checks, so the two cannot drift. Touches
// no shared chain. OWNER ONLY.
func rebuildOwnedChains(ctx context.Context, spec hostFWSpec) error {
	for _, table := range []string{"filter", "nat"} {
		var lines []string
		var chains []string
		for key := range spec.ownedChains {
			if strings.HasPrefix(key, table+"/") {
				chains = append(chains, strings.TrimPrefix(key, table+"/"))
			}
		}
		sort.Strings(chains)
		for _, chain := range chains {
			lines = append(lines, ":"+chain+" - [0:0]")
		}
		for _, chain := range chains {
			lines = append(lines, "-F "+chain)
		}
		for _, chain := range chains {
			for _, w := range spec.ownedChains[table+"/"+chain] {
				lines = append(lines, "-A "+chain+" "+emitRuleTokens(w.args))
			}
		}
		input := "*" + table + "\n" + strings.Join(lines, "\n") + "\nCOMMIT\n"
		if err := restoreIPTables(ctx, input); err != nil {
			return fmt.Errorf("atomic %s owned-chain rebuild: %w", table, err)
		}
	}
	return nil
}

// forwardChainRules returns SANDBOX_FORWARD's exact contents. The entry
// jumps scope traffic to veth ingress or egress, so the rules themselves
// need no veth match beyond direction.
func forwardChainRules(hostIface string) [][]string {
	return [][]string{
		{"-i", sandboxVethPattern, "-j", portDropChain},
		{"-i", sandboxVethPattern, "-p", "udp", "--dport", "443", "-j", "DROP"},
		{"-o", hostIface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"},
		{"-i", sandboxVethPattern, "-o", hostIface, "-j", "ACCEPT"},
		{"-i", hostIface, "-o", sandboxVethPattern, "-j", "ACCEPT"},
		{"-j", "DROP"},
	}
}

// preroutingChainRules returns SANDBOX_PREROUTING's exact contents: the DNS
// redirect jump (a no-op when the feature is off — its chain is empty), then
// the egress proxy REDIRECTs, then the secrets proxy REDIRECT.
func preroutingChainRules(httpProxyPort, tlsProxyPort uint16, secretsProxyDst string, secretsProxyPort uint16) ([][]string, error) {
	rules := [][]string{{"-j", dnsRedirectChain}}
	if httpProxyPort > 0 {
		rules = append(rules, []string{"-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", httpProxyPort)})
	}
	if tlsProxyPort > 0 {
		rules = append(rules, []string{"-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", tlsProxyPort)})
	}
	if secretsProxyPort > 0 {
		if ip := net.ParseIP(secretsProxyDst); ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("invalid secretsProxyDst %q (must be IPv4)", secretsProxyDst)
		}
		// -d narrows the match so we don't intercept unrelated traffic to
		// the same port.
		rules = append(rules, []string{"-p", "tcp", "-d", secretsProxyDst, "--dport", fmt.Sprintf("%d", secretsProxyPort),
			"-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", secretsProxyPort)})
	}
	return rules, nil
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
