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
	"os/exec"
	"strconv"
	"strings"
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

	// Slow path: the installer, byte-for-byte today's behavior.
	tRepair := time.Now()
	if err := installHostFirewall(hostIface, httpProxyPort, tlsProxyPort, dnsRedirectPort, secretsProxyDst, secretsProxyPort, blockedPorts, manageOwnedChains, log); err != nil {
		return err
	}

	// The installer is idempotent-by-presence, so a pre-existing rule in an
	// ineffective position (or a duplicate) survives it. Repair ordering and
	// multiplicity for the vmd rules in shared chains, then require the
	// verifier to pass before this process is allowed to serve.
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
		// One repair attempt for the classes the installer cannot fix.
		if pass > 0 || (class != "misordered" && class != "duplicate-rule") {
			return fmt.Errorf("host firewall failed verification after install (%s: %s) — refusing to serve with unverified enforcement", class, detail)
		}
		log.Warn().Str("mismatch", class).Str("detail", detail).
			Msg("host firewall misordered/duplicated after install — canonicalizing rule order")
		if err := repairSharedOrdering(ctx, d, spec); err != nil {
			return fmt.Errorf("host firewall ordering repair: %w", err)
		}
	}
}

// repairSharedOrdering rewrites each shared chain's vmd rules into canonical
// order with multiplicity one, without ever weakening enforcement: the
// canonical block is INSERTED at the top first (a transient duplicate of a
// DROP/jump/clamp/ACCEPT never loosens anything), and only then are the old
// copies below it deleted, last occurrence first, by line number. Unrelated
// host rules are never touched.
func repairSharedOrdering(ctx context.Context, d *parsedDump, spec hostFWSpec) error {
	for key, want := range spec.sharedOrdered {
		if len(want) == 0 {
			continue
		}
		table, chain, _ := strings.Cut(key, "/")
		// Only repair chains that are actually wrong.
		single := hostFWSpec{sharedOrdered: map[string][]fwRule{key: want}}
		if ok, _, _ := verifyHostFirewall(d, single); ok {
			continue
		}
		// Insert the canonical block at the top (reverse order so want[0]
		// lands at position 1).
		for i := len(want) - 1; i >= 0; i-- {
			args := append([]string{"-w", "5", "-t", table, "-I", chain, "1"}, want[i].args...)
			if out, err := runIPTables(ctx, args); err != nil {
				return fmt.Errorf("insert canonical %s rule: %s: %w", key, out, err)
			}
		}
		// Delete every copy of each vmd rule beyond the first, last first so
		// line numbers stay valid, re-dumping after each pass of deletions.
		for {
			out, err := dumpIPTables(ctx)
			if err != nil {
				return err
			}
			nd, perr := parseIPTablesSave(out)
			if perr != nil {
				return perr
			}
			extra := -1 // 1-based line number of a duplicate to delete
			got := nd.rules[key]
			for _, w := range want {
				seen := 0
				for i, g := range got {
					if ruleEqual(w.args, g) {
						seen++
						if seen > 1 {
							extra = i + 1 // keep the topmost (canonical) copy
						}
					}
				}
			}
			if extra == -1 {
				*d = *nd // hand the refreshed dump back for the next chain's check
				break
			}
			args := []string{"-w", "5", "-t", table, "-D", chain, strconv.Itoa(extra)}
			if out, err := runIPTables(ctx, args); err != nil {
				return fmt.Errorf("delete duplicate %s rule %d: %s: %w", key, extra, out, err)
			}
		}
	}
	return nil
}

// runIPTables execs iptables with the xtables lock wait already in args and a
// hard timeout. Used only on the (rare) repair path.
var runIPTables = func(ctx context.Context, args []string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "iptables", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// iptablesBackendProbe exists only to document why iptables.New is not called
// on the fast path: its constructor probes the binary for version/backend,
// which is an exec per boot the fast path exists to avoid.
var _ = iptables.New
