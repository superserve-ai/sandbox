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
				log.Info().Dur("verify_ms", time.Since(tVerify)).
					Msg("host firewall verified intact — install skipped")
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

	// Serialize the whole read-modify-write against every cooperating writer
	// (the vmd daemon and template-builder both route through here): the
	// repair's flush-and-rebuild is built from a dump, and a rule another
	// process adds between dump and restore would be silently erased. The
	// xtables lock only covers individual commands (and iptables-nft ignores
	// it entirely), so cooperating processes hold this flock across the full
	// install→repair→verify sequence. Third-party writers racing the (µs)
	// dump→restore window remain a documented residual; their tools' own
	// retry/reconcile loops re-add what a raced rebuild dropped.
	unlock, err := lockHostFirewall()
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
		repairable := class == "misordered" || class == "duplicate-rule" || class == "preceded"
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

// repairSharedOrdering rewrites each wrong shared chain in ONE atomic
// iptables-restore --noflush transaction per table: the chain is flushed and
// rebuilt inside a single kernel commit, so there is no mid-repair window for
// traffic to observe and no line-number arithmetic to race a concurrent
// iptables writer (restore holds the xtables lock for the whole commit).
//
// The rebuilt chain is: foreign rules that legitimately preceded the block
// (provably veth-incapable, or veth-capable but strict/inert — an operator's
// stricter DROP stays ABOVE vmd's ACCEPT), then the canonical vmd block, then
// every remaining foreign rule in its original relative order. A veth-capable
// AMBIGUOUS foreign rule above the block aborts without mutation — the
// verifier fails startup for the operator to resolve. OWNER ONLY.
func repairSharedOrdering(ctx context.Context, d *parsedDump, spec hostFWSpec) error {
	perTable := map[string][]string{} // table → restore lines
	for key, want := range spec.sharedOrdered {
		if len(want) == 0 {
			continue
		}
		single := hostFWSpec{sharedOrdered: map[string][]fwRule{key: want}, headGuarded: map[string]bool{key: spec.headGuarded[key]}}
		if ok, _, _ := verifyHostFirewall(d, single); ok {
			continue
		}
		table, chain, _ := strings.Cut(key, "/")
		got := d.rules[key]
		isOurs := func(g []string) bool {
			for _, w := range want {
				if ruleEqual(w.args, g) {
					return true
				}
			}
			return false
		}
		oldLast := -1
		for i, g := range got {
			if isOurs(g) {
				oldLast = i
			}
		}
		// Partition every foreign rule that sat anywhere within the old block
		// span by DISPOSITION, not position: a restrictive DROP interleaved
		// between vmd rules must stay ABOVE the rebuilt block (demoting it
		// below the broad ACCEPT would silently disable it), a proven-
		// permissive ACCEPT is demoted below, and anything ambiguous aborts
		// without mutation. Foreign rules after the old block keep their tail
		// position untouched.
		var above, below [][]string
		for i, g := range got {
			if isOurs(g) {
				continue // all copies replaced by the canonical block
			}
			if i > oldLast {
				below = append(below, g)
				continue
			}
			switch {
			case ruleCannotMatchSandboxIngress(g):
				above = append(above, g) // cannot interact with sandbox traffic
			case foreignDisposition(g) == "strict" || foreignDisposition(g) == "inert":
				above = append(above, g)
			case foreignDisposition(g) == "permissive":
				below = append(below, g)
			default:
				return fmt.Errorf("ambiguous foreign rule within the security block span in %s (%s) — refusing to reorder", key, strings.Join(g, " "))
			}
		}
		lines := []string{"-F " + chain}
		for _, g := range above {
			lines = append(lines, "-A "+chain+" "+strings.Join(g, " "))
		}
		for _, w := range want {
			lines = append(lines, "-A "+chain+" "+strings.Join(w.args, " "))
		}
		for _, g := range below {
			lines = append(lines, "-A "+chain+" "+strings.Join(g, " "))
		}
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
	// Refresh the caller's dump for the next verification pass.
	out, err := dumpIPTables(ctx)
	if err != nil {
		return err
	}
	nd, perr := parseIPTablesSave(out)
	if perr != nil {
		return perr
	}
	*d = *nd
	return nil
}

// installHostFirewallFn is a test seam over the real installer, so the
// non-owner no-repair branch can be exercised without iptables.
var installHostFirewallFn = installHostFirewall

// hostFirewallLockPath is the advisory lock serializing cooperating
// firewall writers' slow paths. Var for tests.
var hostFirewallLockPath = "/run/sandbox-hostfw.lock"

// lockHostFirewall takes a blocking exclusive flock; the holder is another
// cooperating startup, so waiting (rather than timing out) is correct.
func lockHostFirewall() (func(), error) {
	f, err := os.OpenFile(hostFirewallLockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
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
