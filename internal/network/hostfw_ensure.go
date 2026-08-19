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
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/rs/zerolog"
)

// ensureHostFirewall verifies the host ruleset and installs/repairs only on
// mismatch. Drop-in replacement for calling installHostFirewall directly.
func ensureHostFirewall(ctx context.Context, hostIface string, httpProxyPort, tlsProxyPort, dnsRedirectPort uint16, secretsProxyDst string, secretsProxyPort uint16, blockedPorts []uint16, manageOwnedChains bool, log zerolog.Logger) error {
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
	log.Warn().Str("mismatch", class).Str("detail", detail).
		Msg("host firewall verification failed — running full install")

	// Serialize the read-modify-write against the cooperating writers (the
	// vmd daemon and template-builder both route through here) so their
	// install/repair sequences cannot interleave: the xtables lock only
	// covers individual commands, and iptables-nft ignores it entirely.
	// Third-party rules are safe regardless of any race — repair never
	// names, moves, or flushes a foreign rule (see repairSharedOrdering).
	unlock, err := lockHostFirewall(ctx)
	if err != nil {
		return fmt.Errorf("host firewall lock: %w", err)
	}
	defer unlock()

	// Slow path: the installer, byte-for-byte today's behavior.
	tRepair := time.Now()
	if err := installHostFirewallFn(hostIface, httpProxyPort, tlsProxyPort, dnsRedirectPort, secretsProxyDst, secretsProxyPort, blockedPorts, manageOwnedChains, log); err != nil {
		return err
	}

	// The installer is idempotent-by-presence, so a pre-existing rule in an
	// ineffective position (or a duplicate, or a foreign rule above the
	// security block) survives it. The OWNER repairs those and must then pass
	// verification before serving. Non-owners never mutate shared-chain
	// ordering: their partial spec omits the daemon's jumps, so
	// "canonicalizing" it could hoist an ACCEPT above the daemon's drops —
	// they install (presence only, today's behavior) and leave ordering to
	// the daemon.
	for pass := 0; ; pass++ {
		out, err := dumpIPTables(ctx)
		if err != nil {
			return fmt.Errorf("host firewall post-install dump: %w", err)
		}
		d, perr := parseIPTablesSave(out)
		if perr != nil {
			return fmt.Errorf("host firewall post-install parse: %w", perr)
		}
		ok, class, detail := verifyHostFirewall(d, spec)
		if ok {
			log.Info().Dur("repair_ms", time.Since(tRepair)).Int("repair_passes", pass).
				Msg("host firewall installed and verified")
			return nil
		}
		if !manageOwnedChains {
			log.Warn().Str("mismatch", class).Str("detail", detail).
				Msg("host firewall not fully verified — ordering repair is the daemon's; continuing with installed rules")
			return nil
		}
		repairable := class == "misordered" || class == "duplicate-rule" || class == "preceded" || class == "stale-managed"
		if pass > 0 || !repairable {
			return fmt.Errorf("host firewall failed verification after install (%s: %s) — refusing to serve with unverified enforcement", class, detail)
		}
		log.Warn().Str("mismatch", class).Str("detail", detail).
			Msg("host firewall needs canonicalization after install — repairing rule order")
		if err := repairSharedOrdering(ctx, d, spec); err != nil {
			return fmt.Errorf("host firewall ordering repair: %w", err)
		}
	}
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
//   - plumbing (MSS clamp, ACCEPTs, MASQUERADE) re-appended at the tail —
//     which is also why a stricter foreign DROP anywhere in the chain stays
//     effective: it always precedes the re-appended broad ACCEPT.
//
// A veth-capable AMBIGUOUS foreign rule above the security block still
// aborts without mutation: head-inserting our rules would demote its unknown
// control flow below our enforcement, and that call is the operator's.
// OWNER ONLY.
func repairSharedOrdering(ctx context.Context, d *parsedDump, spec hostFWSpec) error {
	perTable := map[string][]string{} // table → restore lines
	for key, want := range spec.sharedOrdered {
		if len(want) == 0 {
			continue
		}
		single := hostFWSpec{sharedOrdered: map[string][]fwRule{key: want}, headGuarded: map[string]bool{key: spec.headGuarded[key]}}
		ok, class, detail := verifyHostFirewall(d, single)
		if ok {
			continue
		}
		if class == "preceded-ambiguous" {
			return fmt.Errorf("%s — refusing to reorder past an ambiguous foreign rule", detail)
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
			if !isOurs && staleManagedRule(g, want) {
				staleLines = append(staleLines, "-D "+chain+" "+emitRuleTokens(g))
			}
		}
		// PREROUTING's head-inserted rules are TERMINAL redirects: re-inserting
		// them at the absolute head would demote a stricter foreign rule that
		// currently runs before one of ours to below the redirect, where the
		// terminal target shadows it into a no-op. (FORWARD is safe — its head
		// rules are drops, which a demoted foreign strict rule still runs
		// after.) Position-relative insertion would reintroduce the races this
		// design removed, so refuse and leave the call to the operator.
		if key == "nat/PREROUTING" {
			lastOurs := -1
			for i, g := range got {
				for _, w := range want {
					if ruleEqual(w.args, g) && i > lastOurs {
						lastOurs = i
					}
				}
			}
			for i, g := range got {
				if i >= lastOurs && lastOurs != -1 {
					break
				}
				isOurs := false
				for _, w := range want {
					if ruleEqual(w.args, g) {
						isOurs = true
						break
					}
				}
				if !isOurs && !staleManagedRule(g, want) && !ruleCannotMatchSandboxIngress(g) && foreignDisposition(g) == "strict" {
					return fmt.Errorf("stricter foreign rule above a vmd redirect in %s (%s) — refusing to reorder past it", key, strings.Join(g, " "))
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
		headPos := 0
		var tail []string
		for _, w := range want {
			if headRule(key, w) {
				headPos++
				lines = append(lines, fmt.Sprintf("-I %s %d %s", chain, headPos, emitRuleTokens(w.args)))
			} else {
				tail = append(tail, "-A "+chain+" "+emitRuleTokens(w.args))
			}
		}
		lines = append(lines, tail...)
		perTable[table] = append(perTable[table], lines...)
	}
	for _, table := range []string{"filter", "nat"} {
		lines := perTable[table]
		if len(lines) == 0 {
			continue
		}
		input := "*" + table + "\n" + strings.Join(lines, "\n") + "\nCOMMIT\n"
		if err := restoreIPTables(ctx, input); err != nil {
			return fmt.Errorf("atomic %s repair: %w", table, err)
		}
	}
	return nil
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
// wait honors ctx and the timeout.
func lockHostFirewall(ctx context.Context) (func(), error) {
	f, err := os.OpenFile(hostFirewallLockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(hostFirewallLockTimeout)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() {
				_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				f.Close()
			}, nil
		}
		if err != syscall.EWOULDBLOCK {
			f.Close()
			return nil, err
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, fmt.Errorf("timed out after %v waiting for %s (held by another firewall writer?)", hostFirewallLockTimeout, hostFirewallLockPath)
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
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
