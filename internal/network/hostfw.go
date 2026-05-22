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

// installHostFirewall installs the static rules that route all VM traffic
// through the host: UDP/443 DROP (kills QUIC bypass of the SNI allowlist),
// MSS clamp, FORWARD ACCEPT between veth+ and the host iface, MASQUERADE
// for vmIPRange to the host iface, and REDIRECT HTTP/HTTPS from veth+ to
// the egress proxy. All operations are idempotent.
func installHostFirewall(hostIface string, httpProxyPort, tlsProxyPort uint16, log zerolog.Logger) error {
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
	// is dropped before the broad ACCEPT terminates the chain walk.
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

	log.Info().Str("host_iface", hostIface).Msg("host firewall ready (static prefix rules)")
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
