package network

// hostfw_ensure.go — the verify-then-skip front door for the host firewall.
// Fast path: one iptables-save dump, verified in memory against the spec —
// zero mutations, no other execs. Slow path (owner): rebuild the owned chains
// atomically, plan every shared-chain change from a snapshot taken under the
// writer lock, apply, then re-dump and re-verify. A repair that cannot
// converge fails startup — serving with unverified enforcement is worse than
// not serving.

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/sentrylog"
)

// ensureHostFirewall verifies the host ruleset and installs/repairs only on
// mismatch. Drop-in replacement for calling installHostFirewall directly.
func ensureHostFirewall(ctx context.Context, hostIface string, httpProxyPort, tlsProxyPort, dnsRedirectPort uint16, secretsProxyDst string, secretsProxyPort uint16, blockedPorts []uint16, manageOwnedChains bool, log zerolog.Logger) error {
	// Validate before the fast path, with the installer's exact requirement:
	// a requested-but-invalid secrets redirect must fail startup, never
	// silently vanish from the spec and let an otherwise-intact ruleset
	// verify without it.
	if secretsProxyPort > 0 {
		if ip := net.ParseIP(secretsProxyDst); ip == nil || ip.To4() == nil {
			return fmt.Errorf("invalid secretsProxyDst %q (must be IPv4)", secretsProxyDst)
		}
	}
	if _, ipnet, err := net.ParseCIDR(vmIPRange); err != nil {
		return fmt.Errorf("vmIPRange %s invalid: %w", vmIPRange, err)
	} else if !ipnet.Contains(net.ParseIP(hostIPForSlot(0))) || !ipnet.Contains(net.ParseIP(hostIPForSlot(MaxSlots-1))) {
		return fmt.Errorf("vmIPRange %s does not cover the full slot allocation range", vmIPRange)
	}
	spec := hostFWSpecFor(hostIface, httpProxyPort, tlsProxyPort, dnsRedirectPort, secretsProxyDst, secretsProxyPort, blockedPorts, manageOwnedChains)

	tVerify := time.Now()
	class, detail := "dump-failed", ""
	if out, err := dumpIPTables(ctx); err == nil {
		if d, perr := parseIPTablesSave(out); perr == nil {
			var ok bool
			if ok, class, detail = verifyHostFirewall(d, spec); ok {
				// Async: an informational write must not extend the fast path.
				verifyDur := time.Since(tVerify)
				go func() {
					log.Info().Dur("verify_ms", verifyDur).
						Msg("host firewall verified intact — install skipped")
				}()
				return nil
			}
		} else {
			class, detail = "parse-failed", perr.Error()
		}
	} else {
		detail = err.Error()
	}
	go func() {
		log.Warn().Str("mismatch", class).Str("detail", detail).
			Msg("host firewall verification failed — running full install")
	}()

	// Serialize the read-modify-write against the cooperating writers (the
	// vmd daemon and template-builder both route through here) so their
	// install/repair sequences cannot interleave: the xtables lock only
	// covers individual commands, and iptables-nft ignores it entirely.
	// Third-party rules are safe regardless of any race — repair never
	// names, moves, or flushes a foreign rule (see repairSharedOrdering).
	unlock, waited, err := lockHostFirewall(ctx)
	if err != nil {
		return fmt.Errorf("host firewall lock: %w", err)
	}
	defer unlock()

	// A writer this process actually waited behind may have converged the
	// ruleset — re-verify before paying for the installer and its mutations.
	// Skipped on an uncontended acquire: nothing ran in between, and the
	// extra dump would tax every fresh-host and genuine-drift startup.
	if waited {
		if out, err := dumpIPTables(ctx); err == nil {
			if d, perr := parseIPTablesSave(out); perr == nil {
				if ok, _, _ := verifyHostFirewall(d, spec); ok {
					// Async: the write must not extend the lock hold or this
					// startup — every queued waiter is behind it.
					go func() {
						log.Info().Msg("host firewall converged by a concurrent writer while waiting — install skipped")
					}()
					return nil
				}
			}
		}
	}

	// Slow path. Non-owners run the presence-only installer (the MASQUERADE)
	// and never touch shared-chain ordering: their partial spec omits the
	// daemon's jumps, so "canonicalizing" it could hoist an ACCEPT above the
	// daemon's drops.
	//
	// The owner never blind-installs: every shared-chain change is planned
	// from a snapshot taken under the lock, so the foreign-rule analysis runs
	// before any mutation — including a first rollout, where a bare
	// insert-at-head would silently demote whatever sits there. Owned chains
	// rebuild first so the planned jumps reference existing chains.
	tRepair := time.Now()
	var predicted map[string][][]string
	// snapshot is the dump the last shared-chain transaction was planned
	// from; a raced writer's rule is whatever the next dump holds that this
	// one did not. corrections bounds the transactions that may follow the
	// plan (an ordering repair, a yield to an interloper) before startup
	// gives up — with vmd's rules always left installed.
	var snapshot *parsedDump
	corrections := 2
	if manageOwnedChains {
		out, err := dumpIPTables(ctx)
		if err != nil {
			return fmt.Errorf("host firewall pre-plan dump: %w", err)
		}
		d, perr := parseIPTablesSave(out)
		if perr != nil {
			return fmt.Errorf("host firewall pre-plan parse: %w", perr)
		}
		if err := rebuildOwnedChains(ctx, spec); err != nil {
			return err
		}
		if predicted, err = repairSharedOrdering(ctx, d, spec); err != nil {
			return fmt.Errorf("host firewall ordering: %w", err)
		}
		snapshot = d
	} else if err := installHostFirewallFn(hostIface, httpProxyPort, tlsProxyPort, dnsRedirectPort, secretsProxyDst, secretsProxyPort, blockedPorts, false, log); err != nil {
		return err
	}
	for pass := 0; ; pass++ {
		out, err := dumpIPTables(ctx)
		if err != nil {
			return fmt.Errorf("host firewall post-install dump: %w", err)
		}
		d, perr := parseIPTablesSave(out)
		if perr != nil {
			return fmt.Errorf("host firewall post-install parse: %w", perr)
		}
		// A repaired chain must contain exactly what the repair's snapshot
		// predicted. Any deviation means a non-cooperating writer interleaved
		// with the restore and the absolute-position inserts may have changed
		// its rule's effective position — refuse rather than serve a state
		// that silently reordered someone else's rule.
		var changed []string
		for key, wantChain := range predicted {
			gotChain := d.rules[key]
			same := len(gotChain) == len(wantChain)
			for i := 0; same && i < len(wantChain); i++ {
				// Preserved foreign rules may use options canonicalRule does
				// not know (ruleEqual fails closed on those) — but both
				// snapshots carry them as identical iptables-save tokens, so
				// exact token equality decides what canonicalization cannot.
				same = ruleEqual(wantChain[i], gotChain[i]) || slices.Equal(wantChain[i], gotChain[i])
			}
			if !same {
				changed = append(changed, key)
			}
		}
		if len(changed) > 0 {
			// A rule the other writer placed between our snapshot and our
			// restore was demoted by the head inserts, and no later dump
			// can tell it apart from one that was always below us — a
			// refusal alone would leave it shadowed for good. Undo the
			// demotion without ever removing enforcement: move our head
			// rules directly below the interloper, in one transaction, and
			// let verification classify it like any other foreign rule
			// above us.
			if corrections == 0 {
				return fmt.Errorf("host firewall chain %s changed underneath the repair again — concurrent non-cooperating writer; vmd rules left installed, refusing to serve", changed[0])
			}
			corrections--
			sort.Strings(changed)
			go func() {
				log.Warn().Strs("chains", changed).
					Msg("host firewall changed underneath the repair — yielding vmd rules below the concurrent writer's")
			}()
			var err error
			if predicted, err = yieldToInterlopers(ctx, snapshot, d, spec, changed); err != nil {
				return fmt.Errorf("host firewall yield after a raced repair: %w", err)
			}
			snapshot = d
			continue
		}
		ok, class, detail := verifyHostFirewall(d, spec)
		// Async: informational writes must not hold the lock (or startup)
		// hostage to a backpressured log sink — waiters are queued behind it.
		if ok {
			repairDur, passes := time.Since(tRepair), pass
			go func() {
				log.Info().Dur("repair_ms", repairDur).Int("repair_passes", passes).
					Msg("host firewall installed and verified")
			}()
			return nil
		}
		if !manageOwnedChains {
			go func() {
				log.Warn().Str("mismatch", class).Str("detail", detail).
					Msg("host firewall not fully verified — ordering repair is the daemon's; continuing with installed rules")
			}()
			return nil
		}
		repairable := class == "misordered" || class == "duplicate-rule" || class == "preceded" || class == "stale-managed"
		if corrections == 0 || !repairable {
			return fmt.Errorf("host firewall failed verification after install (%s: %s) — refusing to serve with unverified enforcement", class, detail)
		}
		corrections--
		go func() {
			log.Warn().Str("mismatch", class).Str("detail", detail).
				Msg("host firewall needs canonicalization after install — repairing rule order")
		}()
		if predicted, err = repairSharedOrdering(ctx, d, spec); err != nil {
			return fmt.Errorf("host firewall ordering repair: %w", err)
		}
		snapshot = d
	}
}

// yieldToInterlopers repositions vmd's head rules in each changed chain to
// sit directly BELOW every foreign rule not provably below them before the
// race — one atomic transaction per table, with vmd's rules never absent
// from a chain, so running sandboxes keep their forwarding, redirects, and
// NAT throughout. The anchor is vmd's own boundary in the snapshot: the
// first foreign rule that sat after our last head rule. Anything a writer
// inserted above that boundary — at the head, or between a known rule and
// our jumps — reads identically to an insert just below us once our
// transaction has moved us, so "above us" is the only placement that leaves
// nothing of theirs shadowed. Verification then classifies the interloper in
// place — strict or observer tolerated, permissive a repairable bypass,
// unknown control flow fails closed with our rules still installed. Tail
// plumbing (the MASQUERADE) is never terminal for the writer's rule and
// stays where the transaction put it. OWNER ONLY.
func yieldToInterlopers(ctx context.Context, snapshot, current *parsedDump, spec hostFWSpec, changed []string) (map[string][][]string, error) {
	predicted := map[string][][]string{}
	perTable := map[string][]string{}
	for _, key := range changed {
		want := spec.sharedOrdered[key]
		table, chain, _ := strings.Cut(key, "/")
		ours := func(g []string) (fwRule, bool) {
			for _, w := range want {
				if ruleEqual(w.args, g) {
					return w, true
				}
			}
			return fwRule{}, false
		}
		// suffix: the foreign rules the snapshot proves were beneath our
		// last head rule, IN ORDER — occurrence matters, since identical
		// foreign rules can sit on both sides of the boundary. With no
		// head of ours in the snapshot there is no boundary to prove, and
		// the suffix stays empty: every current foreign rule reads as
		// above us.
		var suffix [][]string
		lastHead := -1
		for i, g := range snapshot.rules[key] {
			if w, mine := ours(g); mine && headRule(key, w) {
				lastHead = i
			}
		}
		if lastHead >= 0 {
			for _, g := range snapshot.rules[key][lastHead+1:] {
				if _, mine := ours(g); !mine {
					suffix = append(suffix, g)
				}
			}
		}
		var lines []string
		var rest [][]string
		for _, g := range current.rules[key] {
			if w, mine := ours(g); mine && headRule(key, w) {
				lines = append(lines, "-D "+chain+" "+emitRuleTokens(w.args))
				continue
			}
			rest = append(rest, g)
		}
		// Right-align the suffix against the current chain: scanning from
		// the end pairs each suffix rule with its LATEST occurrence, so a
		// duplicate sitting above the boundary is never mistaken for the
		// one below it, and the anchor is the latest position that still
		// keeps every provably-below rule beneath us. If the suffix cannot
		// be aligned at all (a rule of it vanished), nothing is provable
		// and ours go below everything.
		anchor := len(rest)
		if len(suffix) > 0 {
			si := len(suffix) - 1
			for ri := len(rest) - 1; ri >= 0 && si >= 0; ri-- {
				if _, mine := ours(rest[ri]); mine || !slices.Equal(rest[ri], suffix[si]) {
					continue
				}
				if si == 0 {
					anchor = ri
				}
				si--
			}
			if si >= 0 {
				anchor = len(rest)
			}
		}
		var heads [][]string
		for _, w := range want {
			if headRule(key, w) {
				heads = append(heads, w.args)
			}
		}
		for i, h := range heads {
			lines = append(lines, fmt.Sprintf("-I %s %d %s", chain, anchor+1+i, emitRuleTokens(h)))
		}
		layout := append([][]string{}, rest[:anchor]...)
		layout = append(layout, heads...)
		layout = append(layout, rest[anchor:]...)
		predicted[key] = layout
		perTable[table] = append(perTable[table], lines...)
	}
	for _, table := range []string{"filter", "nat"} {
		lines := perTable[table]
		if len(lines) == 0 {
			continue
		}
		input := "*" + table + "\n" + strings.Join(lines, "\n") + "\nCOMMIT\n"
		if err := restoreIPTables(ctx, input); err != nil {
			return nil, fmt.Errorf("atomic %s yield: %w", table, err)
		}
	}
	return predicted, nil
}

// repairSharedOrdering repositions the vmd rules in each wrong shared chain
// in ONE atomic iptables-restore --noflush transaction per table, without
// ever naming, moving, or flushing a foreign rule — so a rule any third
// party adds or holds at any moment can never be deleted by repair, raced or
// not. Per chain the transaction is:
//
//   - `-D <chain> <our exact rulespec>`, once per existing copy — an exact-
//     rulespec delete can only ever match a vmd rule;
//   - security rules (drops, owned-chain jumps, PREROUTING redirects)
//     re-inserted at head positions 1..k, so they run before anything else;
//   - plumbing (the MASQUERADE) re-appended at the tail.
//
// Because the restore rebuilds each chain from the verification dump's
// snapshot, repair also returns the exact per-chain contents that snapshot
// plus the transaction predicts. The caller MUST compare the next dump
// against this prediction before trusting verification: a NON-cooperating
// writer (one not holding the flock) that inserts a rule between the dump
// and the restore would otherwise be silently reordered by the absolute-head
// inserts — e.g. a fresh strict rule demoted below a terminal redirect —
// with post-repair verification tolerating the result.
//
// Any foreign rule whose EFFECTIVE position the transaction would change —
// demoted below our terminal rules by the head inserts, or promoted above
// our plumbing by the tail re-append — is refused unless the move is
// provably verdict-neutral; the checks below spell out each case. The call
// on anything else is the operator's. OWNER ONLY.
func repairSharedOrdering(ctx context.Context, d *parsedDump, spec hostFWSpec) (map[string][][]string, error) {
	predicted := map[string][][]string{}
	perTable := map[string][]string{} // table → restore lines
	for key, want := range spec.sharedOrdered {
		if len(want) == 0 {
			continue
		}
		single := hostFWSpec{sharedOrdered: map[string][]fwRule{key: want}, headGuarded: map[string]bool{key: spec.headGuarded[key]}, owner: spec.owner}
		ok, class, detail := verifyHostFirewall(d, single)
		if ok {
			continue
		}
		if class == "preceded-ambiguous" {
			return nil, fmt.Errorf("%s — refusing to reorder past an ambiguous foreign rule", detail)
		}
		table, chain, _ := strings.Cut(key, "/")
		got := d.rules[key]
		// Reconcile stale managed rules (a previous configuration's
		// redirects): deleted by their exact dump rulespec — they are vmd's
		// own rules from an older parameterization, the shared-chain analog
		// of the owned chains' flush-and-rebuild reconciliation.
		var staleLines []string
		for _, g := range got {
			isOurs := false
			for _, w := range want {
				if ruleEqual(w.args, g) {
					isOurs = true
					break
				}
			}
			if !isOurs && staleVMDRule(spec, key, g, want) {
				staleLines = append(staleLines, "-D "+chain+" "+emitRuleTokens(g))
			}
		}
		// The head inserts demote everything above them below the entry
		// jumps, which are terminal for sandbox traffic: a demoted observer
		// is starved, a demoted strict rule becomes a no-op. Refuse rather
		// than insert position-relative, which would reintroduce the races
		// this design removed.
		if spec.headGuarded[key] {
			// Everything above our LAST terminal rule is demoted by the head
			// inserts. With no vmd terminal rule present at all — the first
			// rollout — every existing rule is above the enforcement about
			// to be created, so the whole chain is scanned.
			lastTerm := len(got)
			for i, g := range got {
				for _, w := range want {
					if securityRule(key, w) && ruleEqual(w.args, g) {
						lastTerm = i
					}
				}
			}
			for i, g := range got {
				if i >= lastTerm {
					break
				}
				isOurs := false
				for _, w := range want {
					if ruleEqual(w.args, g) {
						isOurs = true
						break
					}
				}
				if isOurs || staleVMDRule(spec, key, g, want) || unmarkedTwin(g, want) || ruleCannotMatchSandboxTraffic(g) {
					continue
				}
				// A chain transfer moves its whole tree: safe and
				// permissive trees may go (the latter loses only its
				// bypass ACCEPTs — the point); pinned and ambiguous
				// trees must not.
				if tgt, ok := controlTransferTarget(d, table, g); ok {
					switch chainSandboxDisposition(d, spec.hostIface, table, tgt, 0, map[string]bool{}) {
					case "safe", "permissive":
						continue
					}
					return nil, fmt.Errorf("pinned or ambiguous foreign chain transfer above a vmd terminal rule in %s (%s) — demoting it would change that tree's effective policy; refusing", key, strings.Join(g, " "))
				}
				switch disp := foreignDisposition(g); disp {
				case "observer", "strict":
					return nil, fmt.Errorf("foreign %s rule above a vmd terminal rule in %s (%s) — head-inserting ours would starve it of matching traffic; refusing", disp, key, strings.Join(g, " "))
				case "ambiguous":
					return nil, fmt.Errorf("ambiguous foreign rule above a vmd terminal rule in %s (%s) — refusing to reorder past unknown control flow", key, strings.Join(g, " "))
				}
			}
		}
		// Plumbing is re-appended at the tail, which promotes any foreign rule
		// currently sitting below our effective copy — rules our terminal
		// plumbing made unreachable would begin seeing traffic. Refuse when
		// the promoted rule could change a verdict: in nat, anything
		// terminal-capable (a promoted SNAT/MASQUERADE/ACCEPT changes the
		// mapping ours applied first; a strict rule below only ever tightens
		// what NAT already skipped); in filter, a strict or unknown rule
		// (promoted above our ACCEPTs it starts blocking sandbox traffic —
		// while a promoted ACCEPT is verdict-identical to ours). Inert and
		// observer rules never change a verdict.
		for _, w := range want {
			if headRule(key, w) {
				continue
			}
			first := -1
			for i, g := range got {
				if ruleEqual(w.args, g) {
					first = i
					break
				}
			}
			if first == -1 {
				continue
			}
			for _, g := range got[first+1:] {
				isOurs := false
				for _, o := range want {
					if ruleEqual(o.args, g) {
						isOurs = true
						break
					}
				}
				if isOurs || staleVMDRule(spec, key, g, want) || unmarkedTwin(g, want) || ruleCannotMatchSandboxTraffic(g) {
					continue
				}
				disp := foreignDisposition(g)
				tolerated := disp == "inert" || disp == "observer" ||
					(table == "nat" && disp == "strict") ||
					(table == "filter" && disp == "permissive")
				if !tolerated {
					return nil, fmt.Errorf("foreign %s rule below a vmd rule in %s (%s) — re-appending ours would promote it; refusing", disp, key, strings.Join(g, " "))
				}
			}
		}
		lines := staleLines
		for _, w := range want {
			for _, g := range got {
				if ruleEqual(w.args, g) {
					lines = append(lines, "-D "+chain+" "+emitRuleTokens(w.args))
				}
			}
		}
		var remainder [][]string
		for _, g := range got {
			isOurs := false
			for _, w := range want {
				if ruleEqual(w.args, g) {
					isOurs = true
					break
				}
			}
			if !isOurs && !staleVMDRule(spec, key, g, want) {
				remainder = append(remainder, g)
			}
		}
		headPos := 0
		var heads, tailRules [][]string
		var tail []string
		for _, w := range want {
			if headRule(key, w) {
				headPos++
				lines = append(lines, fmt.Sprintf("-I %s %d %s", chain, headPos, emitRuleTokens(w.args)))
				heads = append(heads, w.args)
			} else {
				tail = append(tail, "-A "+chain+" "+emitRuleTokens(w.args))
				tailRules = append(tailRules, w.args)
			}
		}
		lines = append(lines, tail...)
		predicted[key] = append(append(heads, remainder...), tailRules...)
		perTable[table] = append(perTable[table], lines...)
	}
	for _, table := range []string{"filter", "nat"} {
		lines := perTable[table]
		if len(lines) == 0 {
			continue
		}
		input := "*" + table + "\n" + strings.Join(lines, "\n") + "\nCOMMIT\n"
		if err := restoreIPTables(ctx, input); err != nil {
			return nil, fmt.Errorf("atomic %s repair: %w", table, err)
		}
	}
	return predicted, nil
}

// StartHostFWSampler periodically re-verifies the host firewall and repairs
// drift, so another agent restarting later (dockerd re-heading its jumps)
// cannot leave a bypass standing until the next vmd boot. Each tick is the
// startup ensure path: one read-only dump when intact, the locked
// plan-and-repair when not. Failures log loudly and the next tick retries —
// a serving daemon cannot fail closed the way a startup can. Owner only.
//
// Accepted tradeoff: polling leaves up to one interval of disturbed ordering;
// event-driven reconciliation (an nftables monitor) is the follow-up.
func (m *Manager) StartHostFWSampler(ctx context.Context, every time.Duration) {
	if !m.ownsEgressPortChain {
		return
	}
	log := m.log.With().Str("component", "host_fw").Logger()
	go func() {
		defer sentrylog.Recover("hostfw sampler")
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			if err := ensureHostFirewall(ctx, m.hostInterface, m.httpProxyPort, m.tlsProxyPort,
				m.dnsRedirectPort, m.secretsProxyDst, m.secretsProxyPort, m.blockedEgressPorts,
				m.ownsEgressPortChain, log); err != nil {
				log.Error().Err(err).
					Msg("periodic host firewall reconciliation failed — enforcement may be degraded until resolved")
			}
		}
	}()
}

// installHostFirewallFn is a test seam over the real installer, so the
// non-owner no-repair branch can be exercised without iptables.
var installHostFirewallFn = installHostFirewall

// hostFirewallLockPath is the advisory lock serializing cooperating
// firewall writers' slow paths. Var for tests.
var hostFirewallLockPath = "/run/sandbox-hostfw.lock"

// hostFirewallLockTimeout bounds lock acquisition: the holder is another
// cooperating startup (normally seconds), and a wedged one must fail this
// startup with a clear error rather than block it indefinitely — the
// supervisor's restart retries against a hopefully-unwedged holder.
const hostFirewallLockTimeout = 2 * time.Minute

// lockHostFirewall acquires the exclusive flock, polling non-blocking so the
// wait honors ctx and the timeout. waited reports whether another writer held
// the lock first — only then is a post-lock re-verify worth a dump.
func lockHostFirewall(ctx context.Context) (unlock func(), waited bool, err error) {
	f, err := os.OpenFile(hostFirewallLockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, false, err
	}
	deadline := time.Now().Add(hostFirewallLockTimeout)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() {
				_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				f.Close()
			}, waited, nil
		}
		if err != syscall.EWOULDBLOCK {
			f.Close()
			return nil, false, err
		}
		waited = true
		if time.Now().After(deadline) {
			f.Close()
			return nil, false, fmt.Errorf("timed out after %v waiting for %s (held by another firewall writer?)", hostFirewallLockTimeout, hostFirewallLockPath)
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, false, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// restoreIPTables applies one iptables-restore transaction. --noflush so only
// the chains the input explicitly flushes are touched; -w waits on the
// xtables lock, making the whole rebuild atomic against concurrent writers.
var restoreIPTables = func(ctx context.Context, input string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "iptables-restore", "-w", "5", "--noflush")
	cmd.Stdin = strings.NewReader(input)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("iptables-restore: %s: %w", strings.TrimSpace(stderr.String()), err)
	}
	return nil
}

// iptablesBackendProbe exists only to document why iptables.New is not called
// on the fast path: its constructor probes the binary for version/backend,
// which is an exec per boot the fast path exists to avoid.
var _ = iptables.New
