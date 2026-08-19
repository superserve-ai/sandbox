package network

// hostfw_verify.go — one-shot verification of the host firewall against a
// single iptables-save dump, so steady-state startups skip the several dozen
// iptables invocations installHostFirewall makes. The kernel's dump is the
// only source of truth (nothing is mirrored or persisted); any doubt —
// missing rule, wrong order, duplicate, owned-chain drift, unparseable
// output — falls back to the full install path, which then MUST re-verify.
// False "intact" is the only dangerous failure, so parsing is strict and the
// expectations are generated from the same specification the installer uses.

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// fwRule is one vmd-managed rule, in installer argument form.
type fwRule struct {
	table string
	chain string
	args  []string
}

func (r fwRule) key() string { return r.table + "/" + r.chain }

// hostFWSpec is the single structured specification both the verifier and the
// ordering repair derive from. sharedOrdered holds, per shared built-in
// chain, the vmd rules in their canonical precedence order (drops and jumps
// before the broad ACCEPTs, MSS clamp before the outbound ACCEPT); unrelated
// host rules in those chains are ignored. ownedChains holds the exact,
// ordered, complete contents of the vmd-owned chains; nil when this process
// does not own them (template-builder), in which case they are neither
// verified nor touched.
type hostFWSpec struct {
	sharedOrdered map[string][]fwRule
	ownedChains   map[string][]fwRule
}

// hostFWSpecFor builds the specification from the same parameters
// installHostFirewall receives. The rule args here must stay in lockstep with
// the installer; the round-trip test (install → dump → verify) enforces that.
func hostFWSpecFor(hostIface string, httpProxyPort, tlsProxyPort, dnsRedirectPort uint16, secretsProxyDst string, secretsProxyPort uint16, blockedPorts []uint16, manageOwnedChains bool) hostFWSpec {
	spec := hostFWSpec{sharedOrdered: map[string][]fwRule{}}

	// filter/FORWARD, canonical precedence order. The udp/443 DROP and the
	// port-drop jump must run before the broad veth+→host ACCEPT terminates
	// the chain walk, and the MSS clamp must precede that ACCEPT too or
	// outbound SYNs are accepted before clamping.
	fwd := []fwRule{}
	if manageOwnedChains {
		fwd = append(fwd, fwRule{"filter", "FORWARD", []string{"-i", "veth+", "-j", portDropChain}})
	}
	fwd = append(fwd,
		fwRule{"filter", "FORWARD", []string{"-i", "veth+", "-p", "udp", "--dport", "443", "-j", "DROP"}},
		fwRule{"filter", "FORWARD", []string{"-o", hostIface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"}},
		fwRule{"filter", "FORWARD", []string{"-i", "veth+", "-o", hostIface, "-j", "ACCEPT"}},
		fwRule{"filter", "FORWARD", []string{"-i", hostIface, "-o", "veth+", "-j", "ACCEPT"}},
	)
	spec.sharedOrdered["filter/FORWARD"] = fwd

	// nat/PREROUTING, canonical order: the DNS jump first (installed via
	// Insert), then the REDIRECTs in installer append order — tls before the
	// secretsproxy REDIRECT keeps today's shadowing semantics on a port
	// collision.
	pre := []fwRule{}
	if manageOwnedChains {
		pre = append(pre, fwRule{"nat", "PREROUTING", []string{"-i", "veth+", "-j", dnsRedirectChain}})
	}
	if httpProxyPort > 0 {
		pre = append(pre, fwRule{"nat", "PREROUTING", []string{"-i", "veth+", "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", httpProxyPort)}})
	}
	if tlsProxyPort > 0 {
		pre = append(pre, fwRule{"nat", "PREROUTING", []string{"-i", "veth+", "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", tlsProxyPort)}})
	}
	if secretsProxyPort > 0 && net.ParseIP(secretsProxyDst) != nil {
		pre = append(pre, fwRule{"nat", "PREROUTING", []string{"-i", "veth+", "-p", "tcp", "-d", secretsProxyDst, "--dport", fmt.Sprintf("%d", secretsProxyPort), "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", secretsProxyPort)}})
	}
	spec.sharedOrdered["nat/PREROUTING"] = pre

	spec.sharedOrdered["nat/POSTROUTING"] = []fwRule{
		{"nat", "POSTROUTING", []string{"-s", vmIPRange, "-o", hostIface, "-j", "MASQUERADE"}},
	}

	if manageOwnedChains {
		spec.ownedChains = map[string][]fwRule{}
		var drops []fwRule
		dropPorts := blockedPorts
		if dnsRedirectPort > 0 {
			dropPorts = append(append([]uint16(nil), blockedPorts...), 853)
		}
		for _, port := range dropPorts {
			for _, proto := range []string{"tcp", "udp"} {
				drops = append(drops, fwRule{"filter", portDropChain, []string{"-p", proto, "--dport", fmt.Sprintf("%d", port), "-j", "DROP"}})
			}
		}
		spec.ownedChains["filter/"+portDropChain] = drops

		var dns []fwRule
		for _, args := range dnsRedirectRules(dnsRedirectPort) {
			dns = append(dns, fwRule{"nat", dnsRedirectChain, args})
		}
		spec.ownedChains["nat/"+dnsRedirectChain] = dns
	}
	return spec
}

// ruleArity maps every option that may appear in a vmd rule to its value
// count. Anything outside this table makes a rule non-canonicalizable, which
// can only ever cause a NON-match (→ slow path), never a false intact.
var ruleArity = map[string]int{
	"-i": 1, "-o": 1, "-p": 1, "-s": 1, "-d": 1, "-j": 1,
	"--dport": 1, "--to-port": 1, "--tcp-flags": 2, "--clamp-mss-to-pmtu": 0,
}

// canonicalRule reduces a rule's arguments to a sorted set of option groups,
// so installer argument order and iptables-save output order (which reorders
// matches: address first, then interface, protocol, ...) compare equal.
// Normalizations: the `-m tcp/udp` module iptables-save inserts for plain
// `-p` rules is dropped; `--to-ports` (save form) → `--to-port`; a trailing
// `/32` on an address is stripped. ok=false for any unknown or malformed
// option — strictness is the point.
func canonicalRule(args []string) (groups []string, ok bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-m" && i+1 < len(args) && (args[i+1] == "tcp" || args[i+1] == "udp") {
			i++
			continue
		}
		if a == "--to-ports" {
			a = "--to-port"
		}
		n, known := ruleArity[a]
		if !known || i+n >= len(args)+1 && n > 0 {
			return nil, false
		}
		if i+n > len(args) {
			return nil, false
		}
		vals := args[i+1 : i+1+n]
		if a == "-d" || a == "-s" {
			vals = []string{strings.TrimSuffix(vals[0], "/32")}
		}
		groups = append(groups, a+" "+strings.Join(vals, " "))
		i += n
	}
	sort.Strings(groups)
	return groups, true
}

func ruleEqual(specArgs, dumpArgs []string) bool {
	a, aok := canonicalRule(specArgs)
	b, bok := canonicalRule(dumpArgs)
	if !aok || !bok || len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// parsedDump is an iptables-save dump reduced to append-order rule lists per
// "table/chain", plus the set of chains each table declares.
type parsedDump struct {
	rules  map[string][][]string
	chains map[string]bool
}

// parseIPTablesSave strictly parses iptables-save output. Only line shapes it
// understands are accepted: table headers (*name), chain declarations
// (:NAME ...), rules (-A CHAIN args...), comments, and COMMIT. Anything else
// is an error — the caller treats that as mismatch and takes the slow path.
func parseIPTablesSave(out string) (*parsedDump, error) {
	d := &parsedDump{rules: map[string][][]string{}, chains: map[string]bool{}}
	table := ""
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "*"):
			table = line[1:]
			if table == "" {
				return nil, fmt.Errorf("empty table header")
			}
		case strings.HasPrefix(line, ":"):
			if table == "" {
				return nil, fmt.Errorf("chain declaration before table header: %q", line)
			}
			fields := strings.Fields(line)
			d.chains[table+"/"+strings.TrimPrefix(fields[0], ":")] = true
		case line == "COMMIT":
			table = ""
		case strings.HasPrefix(line, "-A "):
			if table == "" {
				return nil, fmt.Errorf("rule before table header: %q", line)
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return nil, fmt.Errorf("malformed rule line: %q", line)
			}
			key := table + "/" + fields[1]
			d.rules[key] = append(d.rules[key], fields[2:])
		default:
			return nil, fmt.Errorf("unrecognized iptables-save line: %q", line)
		}
	}
	return d, nil
}

// verifyHostFirewall checks a parsed dump against the spec. It returns
// ok=false with a mismatch class ("missing-rule", "duplicate-rule",
// "misordered", "owned-chain-drift", "missing-chain") naming the first
// divergence. Shared chains: every spec rule must appear exactly once, and
// the spec rules' relative order must equal the canonical order; unrelated
// rules are ignored. Owned chains: contents must equal the spec exactly, in
// order, with nothing extra.
func verifyHostFirewall(d *parsedDump, spec hostFWSpec) (ok bool, class string, detail string) {
	for key, want := range spec.sharedOrdered {
		got := d.rules[key]
		lastIdx := -1
		for _, w := range want {
			found := -1
			count := 0
			for i, g := range got {
				if ruleEqual(w.args, g) {
					count++
					if found == -1 {
						found = i
					}
				}
			}
			switch {
			case count == 0:
				return false, "missing-rule", key + ": " + strings.Join(w.args, " ")
			case count > 1:
				return false, "duplicate-rule", key + ": " + strings.Join(w.args, " ")
			case found < lastIdx:
				return false, "misordered", key + ": " + strings.Join(w.args, " ")
			}
			lastIdx = found
		}
	}
	for key, want := range spec.ownedChains {
		if !d.chains[key] {
			return false, "missing-chain", key
		}
		got := d.rules[key]
		if len(got) != len(want) {
			return false, "owned-chain-drift", fmt.Sprintf("%s: %d rules, want %d", key, len(got), len(want))
		}
		for i := range want {
			if !ruleEqual(want[i].args, got[i]) {
				return false, "owned-chain-drift", key + ": " + strings.Join(got[i], " ")
			}
		}
	}
	return true, "", ""
}

// dumpIPTables runs iptables-save once (both tables in one invocation) with a
// hard timeout. iptables-save is read-only and does not take the xtables
// lock; the timeout guards a wedged binary. Only stdout is parsed: on the
// iptables-nft backend, foreign native-nft tables (the host egress-block
// table) produce warnings that must not poison parsing — comment-form ones on
// stdout are skipped by the parser, and stderr never reaches it.
var dumpIPTables = func(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var stdout, stderr strings.Builder
	cmd := exec.CommandContext(ctx, "iptables-save")
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("iptables-save: %s: %w", strings.TrimSpace(stderr.String()), err)
	}
	return stdout.String(), nil
}
