package network

// hostfw_ensure.go — the verify-then-skip front door for installHostFirewall.
// Fast path: one iptables-save dump, verified in memory against the spec →
// zero mutations, no iptables execs at all (iptables.New's version probe is
// deferred to the slow path on purpose). Slow path: the unchanged installer,
// plus an ordering/dedup repair for vmd rules the installer's AppendUnique
// idempotence would leave in an ineffective position, then a mandatory
// re-dump + re-verify. A repair that cannot converge fails startup — serving
// with unverified enforcement is worse than not serving.

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"slices"
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

	// Slow path. Non-owners run the presence-only installer (the MASQUERADE):
	// they never mutate shared-chain ordering — their partial spec omits the
	// daemon's jumps, so "canonicalizing" it could hoist an ACCEPT above the
	// daemon's drops.
	//
	// The OWNER never blind-installs: every shared-chain change is planned by
	// repairSharedOrdering from a snapshot taken UNDER THE LOCK, so the
	// foreign-rule safety analysis (pinned trees, observers, unknown control
	// flow) runs before any mutation — including the very first rollout,
	// where the entry jumps are missing and a bare insert-at-head would
	// silently demote whatever sits there. The owned chains rebuild first
	// (atomic, touching no shared chain) so the jumps the plan inserts always
	// reference existing chains.
	tRepair := time.Now()
	var predicted map[string][][]string
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
		changed := ""
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
				changed = key
				break
			}
		}
		if changed != "" {
			// The absolute-head inserts may have demoted a rule the other
			// writer placed between our snapshot and our restore — and no
			// later dump can tell that rule apart from one that was always
			// below us. Refusing to serve is not enough: the demotion
			// itself must be undone, or the next verification would find
			// vmd first, look no further, and leave the foreign rule
			// shadowed for good. Rolling our own rules back out (exact
			// rulespec deletes, which can only ever match a vmd rule)
			// restores exactly the ordering that writer produced. Then one
			// replan from a fresh snapshot: the interloper now sits above
			// nothing of ours, so it is scanned and classified like any
			// other foreign rule — tolerated, moved, or refused.
			if rbErr := rollbackSharedRules(ctx, spec); rbErr != nil {
				return fmt.Errorf("host firewall chain %s changed underneath the repair — concurrent non-cooperating writer; rollback of vmd rules failed: %w", changed, rbErr)
			}
			if pass > 0 {
				return fmt.Errorf("host firewall chain %s changed underneath the repair again — concurrent non-cooperating writer; vmd rules rolled back, refusing to serve", changed)
			}
			go func() {
				log.Warn().Str("chain", changed).
					Msg("host firewall changed underneath the repair — rolled vmd rules back, replanning from a fresh snapshot")
			}()
			out, err := dumpIPTables(ctx)
			if err != nil {
				return fmt.Errorf("host firewall post-rollback dump: %w", err)
			}
			fresh, perr := parseIPTablesSave(out)
			if perr != nil {
				return fmt.Errorf("host firewall post-rollback parse: %w", perr)
			}
			if predicted, err = repairSharedOrdering(ctx, fresh, spec); err != nil {
				return fmt.Errorf("host firewall ordering after rolling back a raced repair: %w", err)
			}
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
		if pass > 0 || !repairable {
			return fmt.Errorf("host firewall failed verification after install (%s: %s) — refusing to serve with unverified enforcement", class, detail)
		}
		go func() {
			log.Warn().Str("mismatch", class).Str("detail", detail).
				Msg("host firewall needs canonicalization after install — repairing rule order")
		}()
		if predicted, err = repairSharedOrdering(ctx, d, spec); err != nil {
			return fmt.Errorf("host firewall ordering repair: %w", err)
		}
	}
}

// rollbackSharedRules deletes every copy of vmd's own rules from the shared
// chains — exact-rulespec deletes, which can only ever match a vmd rule — so
// a chain a non-cooperating writer changed under our plan returns to the
// ordering that writer produced, minus us. Enforcement is absent until the
// replan lands, but the caller is already refusing to serve; the alternative
// is a foreign rule shadowed until an operator notices. OWNER ONLY.
func rollbackSharedRules(ctx context.Context, spec hostFWSpec) error {
	out, err := dumpIPTables(ctx)
	if err != nil {
		return fmt.Errorf("rollback dump: %w", err)
	}
	d, perr := parseIPTablesSave(out)
	if perr != nil {
		return fmt.Errorf("rollback parse: %w", perr)
	}
	perTable := map[string][]string{}
	for key, want := range spec.sharedOrdered {
		table, chain, _ := strings.Cut(key, "/")
		for _, g := range d.rules[key] {
			for _, w := range want {
				if ruleEqual(w.args, g) {
					perTable[table] = append(perTable[table], "-D "+chain+" "+emitRuleTokens(w.args))
					break
				}
			}
		}
	}
	for _, table := range []string{"filter", "nat"} {
		lines := perTable[table]
		if len(lines) == 0 {
			continue
		}
		input := "*" + table + "\n" + strings.Join(lines, "\n") + "\nCOMMIT\n"
		if err := restoreIPTables(ctx, input); err != nil {
			return fmt.Errorf("atomic %s rollback: %w", table, err)
		}
	}
	return nil
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
// A veth-capable AMBIGUOUS foreign rule above the entry jumps still
// aborts without mutation: head-inserting our rules would demote its unknown
// control flow below our enforcement, and that call is the operator's. The
// same refusal covers foreign rules whose EFFECTIVE position repair would
// change: an observer above any vmd terminal rule — a PREROUTING redirect or
// a FORWARD drop — would be starved of the traffic it currently sees by the
// head inserts, a strict rule above a PREROUTING redirect would be shadowed
// by the terminal redirect, and a terminal-capable foreign rule below a vmd
// nat plumbing rule would be promoted into the traffic ours handled first by
// the tail re-append. Only a foreign DROP in FORWARD keeps its exact
// observable behavior wherever it lands — a REJECT demoted below an
// overlapping vmd DROP would stop answering, turning configured rejections
// into silent drops, so it refuses like the rest.
// OWNER ONLY.
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
		// Head-inserting our rules demotes everything currently above them
		// below the entry jumps — which are TERMINAL for sandbox traffic
		// (the owned chains end in a verdict). A demoted observer would be
		// starved of the traffic it currently sees; a demoted strict rule
		// would be shadowed into a no-op. Resolved-safe foreign transfers
		// (another agent's head jumps) may move: they provably cannot change
		// a sandbox verdict either side of ours.
		// Position-relative insertion would reintroduce the races this design
		// removed, so refuse and leave the call to the operator.
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
				// A transfer into a foreign chain moves that whole tree
				// below vmd's terminal enforcement. Resolved from this
				// dump: safe trees cannot act on sandbox traffic,
				// permissive trees lose only their bypass ACCEPTs (the
				// point of the repair); pinned trees carry strict or
				// observer policy the demotion would starve, and unknown
				// control flow is never reordered past.
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
// drift, so protection does not decay between vmd restarts: another agent
// restarting later (dockerd re-inserting its jumps at position 1) would
// otherwise leave a bypass standing until the next boot. Each tick is the
// same ensure path as startup — one read-only dump when intact, the locked
// plan-and-repair when not. Failures are logged loudly, never fatal: a
// serving daemon cannot fail-closed the way a startup can, and the next tick
// retries. Owner only; non-owners have no reconciliation to run.
//
// Accepted tradeoff: this is polling, so another agent can disturb the
// shared-chain ordering for up to one interval before it is repaired.
// Event-driven reconciliation (a netlink/nftables monitor) would close that
// window and is the natural follow-up; the poll keeps this change free of a
// new long-lived kernel subscription.
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
