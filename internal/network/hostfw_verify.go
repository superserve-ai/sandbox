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
	// headGuarded chains (owner only) additionally require that no rule
	// capable of matching sandbox traffic precedes the vmd security block:
	// relative order among our own rules is not enough when a foreign
	// `-i veth+ -j ACCEPT` above them would bypass the drops yet leave their
	// relative order intact.
	headGuarded map[string]bool
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
		spec.headGuarded = map[string]bool{"filter/FORWARD": true, "nat/PREROUTING": true}
		spec.ownedChains = map[string][]fwRule{}
		var drops []fwRule
		dropPorts := blockedPorts
		if dnsRedirectPort > 0 {
			dropPorts = append(append([]uint16(nil), blockedPorts...), 853)
		}
		// Deduplicate, preserving first-occurrence order: the installer's
		// AppendUnique collapses duplicates (853 configured AND implied by the
		// DNS redirect, or a doubled config entry), so a spec that kept them
		// could never verify post-install.
		seen := map[uint16]bool{}
		uniq := dropPorts[:0:0]
		for _, p := range dropPorts {
			if !seen[p] {
				seen[p] = true
				uniq = append(uniq, p)
			}
		}
		dropPorts = uniq
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
		if !known {
			return nil, false
		}
		if i+n >= len(args) && n > 0 { // operand(s) missing
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
// ruleCannotMatchSandboxIngress conservatively decides whether a foreign rule
// positioned above the vmd security block is provably unable to match sandbox
// (veth) traffic: it must carry a non-negated explicit input interface whose
// pattern cannot cover a veth device. Anything else — no -i at all, a
// negation, a veth-covering prefix wildcard, unparseable shapes — reads as
// capable, which at worst costs a repair pass, never a bypass.
func ruleCannotMatchSandboxIngress(tokens []string) bool {
	for i, t := range tokens {
		if t != "-i" {
			continue
		}
		if i > 0 && tokens[i-1] == "!" {
			return false // "everything except X" matches veth
		}
		if i+1 >= len(tokens) {
			return false
		}
		v := tokens[i+1]
		if strings.HasPrefix(v, "veth") {
			return false
		}
		if strings.HasSuffix(v, "+") && strings.HasPrefix("veth", strings.TrimSuffix(v, "+")) {
			return false // e.g. "v+" or "+" covers veth devices
		}
		return true
	}
	return false // no input-interface constraint: can match anything
}

// foreignDisposition classifies a veth-capable foreign rule found above the
// vmd security block:
//   - "strict": DROP/REJECT — only tightens enforcement; allowed to stay
//     above the block, and repair must preserve it there.
//   - "inert": no -j and no -g — matches nothing into an action or control
//     transfer.
//   - "permissive": ACCEPT — a proven bypass; the only class repair may
//     auto-demote below the block.
//   - "ambiguous": anything else — RETURN, MARK, NAT actions, -j into an
//     operator chain, and -g/--goto (control flow into another chain even
//     without -j) — semantics unknown, so the owner fails startup without
//     mutating rather than guess.
func foreignDisposition(tokens []string) string {
	for i, t := range tokens {
		if t == "-g" || t == "--goto" {
			return "ambiguous"
		}
		if t == "-j" && i+1 < len(tokens) {
			switch tokens[i+1] {
			case "DROP", "REJECT":
				return "strict"
			case "ACCEPT":
				return "permissive"
			default:
				return "ambiguous"
			}
		}
	}
	return "inert"
}

// securityRule reports whether a spec rule is enforcement (a drop, an owned-
// chain jump, or a PREROUTING redirect) as opposed to plumbing a foreign rule
// may harmlessly shadow (ACCEPTs, the MSS clamp).
func securityRule(key string, w fwRule) bool {
	if key == "nat/PREROUTING" {
		return true // every vmd PREROUTING rule steers traffic into enforcement
	}
	last := w.args[len(w.args)-1]
	return last == "DROP" || last == portDropChain
}

// headRule reports whether repair re-inserts a spec rule at the chain head:
// the security rules, plus the MSS clamp — the clamp is non-terminal (running
// it before the drops is harmless) but MUST precede any terminal ACCEPT,
// including a tolerated foreign one, or sandbox SYNs leave FORWARD unclamped.
func headRule(key string, w fwRule) bool {
	if securityRule(key, w) {
		return true
	}
	return w.args[len(w.args)-1] == "--clamp-mss-to-pmtu"
}

// staleManagedRule reports whether a non-spec dump rule matches one of vmd's
// own PREROUTING redirect shapes with different parameter values — the
// previous configuration's rule (secretsproxy address/port or proxy port
// changed across a restart). These are reconciled (deleted) by repair rather
// than treated as unrecoverable foreign rules: the shapes are unmistakably
// vmd's (veth+ ingress REDIRECTs; the secretsproxy form additionally requires
// dport == to-port, which only vmd generates). Only PREROUTING shapes are
// recognized — stale variants elsewhere never block startup.
func staleManagedRule(key string, tokens []string) bool {
	if key != "nat/PREROUTING" {
		return false
	}
	groups, ok := canonicalRule(tokens)
	if !ok {
		return false
	}
	g := map[string]string{}
	for _, e := range groups {
		opt, val, _ := strings.Cut(e, " ")
		g[opt] = val
	}
	if g["-i"] != "veth+" || g["-p"] != "tcp" || g["-j"] != "REDIRECT" || g["--to-port"] == "" || g["--dport"] == "" {
		return false
	}
	switch len(groups) {
	case 5: // http/tls shape: fixed web dport, any to-port
		return g["--dport"] == "80" || g["--dport"] == "443"
	case 6: // secretsproxy shape: -d plus the vmd-distinctive dport==to-port
		return g["-d"] != "" && g["--dport"] == g["--to-port"]
	}
	return false
}

func verifyHostFirewall(d *parsedDump, spec hostFWSpec) (ok bool, class string, detail string) {
	for key, want := range spec.sharedOrdered {
		got := d.rules[key]
		// Stale managed rules (a previous configuration's redirects) are a
		// repairable mismatch, recognized before the head guard would
		// misclassify them as ambiguous foreign rules and block startup on a
		// supported config change.
		for _, g := range got {
			isOurs := false
			for _, w := range want {
				if ruleEqual(w.args, g) {
					isOurs = true
					break
				}
			}
			if !isOurs && staleManagedRule(key, g) {
				return false, "stale-managed", key + ": " + strings.Join(g, " ")
			}
		}
		// Head guard: no foreign rule capable of matching sandbox traffic may
		// sit above (or interleave) the vmd security rules — relative order
		// among our own rules alone would still verify with a foreign
		// `-i veth+ -j ACCEPT` above the drops. The guarded region extends
		// through our LAST security rule (drops/jumps/redirects); foreign
		// rules below that only shadow our own ACCEPTs/clamp, which drops have
		// already run ahead of.
		if spec.headGuarded[key] {
			guardEnd := -1 // index in got of our last security rule
			for _, w := range want {
				if !securityRule(key, w) {
					continue
				}
				for i, g := range got {
					if ruleEqual(w.args, g) && i > guardEnd {
						guardEnd = i
					}
				}
			}
			for i := 0; i < len(got); i++ {
				if guardEnd != -1 && i >= guardEnd {
					break
				}
				isOurs := false
				for _, w := range want {
					if ruleEqual(w.args, got[i]) {
						isOurs = true
						break
					}
				}
				if isOurs || ruleCannotMatchSandboxIngress(got[i]) {
					continue
				}
				switch foreignDisposition(got[i]) {
				case "strict", "inert":
					// Only tightens (or does nothing): allowed above the block.
				case "permissive":
					return false, "preceded", key + ": " + strings.Join(got[i], " ")
				default:
					return false, "preceded-ambiguous", key + ": " + strings.Join(got[i], " ")
				}
			}
		}
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
