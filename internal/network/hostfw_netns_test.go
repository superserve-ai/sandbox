package network

// Real-iptables round trip for the verify-then-skip path: installs the actual
// ruleset, dumps it with the real iptables-save, and proves the verifier (a)
// reads a genuine install as intact and (b) detects every mutation class,
// with ensureHostFirewall converging back to verified. Needs root + NET_ADMIN
// + the iptables binaries (run inside a disposable container/netns); skips
// itself anywhere it can't touch iptables.

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

// requireIsolatedIPTables re-execs the test inside a fresh network namespace
// (unshare -n) so it can never touch the machine's real firewall; the child
// runs with the env marker set and does the actual work. Skips where the
// namespace or iptables is unavailable. HOSTFW_DESTRUCTIVE_TEST=1 opts out of
// isolation for environments (a disposable container) where unshare is
// unavailable but mutating the namespace is acceptable.
func requireIsolatedIPTables(t *testing.T) {
	t.Helper()
	if os.Getenv("HOSTFW_TEST_IN_NETNS") == "1" || os.Getenv("HOSTFW_DESTRUCTIVE_TEST") == "1" {
		if err := exec.Command("iptables", "-w", "1", "-L", "-n").Run(); err != nil {
			t.Skipf("iptables unavailable (need root+NET_ADMIN): %v", err)
		}
		return
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skipf("unshare not installed: %v", err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("cannot resolve test binary: %v", err)
	}
	cmd := exec.Command("unshare", "-n", exe, "-test.run", "^"+t.Name()+"$", "-test.v")
	cmd.Env = append(os.Environ(), "HOSTFW_TEST_IN_NETNS=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "unavailable") || strings.Contains(string(out), "Operation not permitted") {
			t.Skipf("cannot isolate a network namespace: %v: %s", err, out)
		}
		t.Fatalf("isolated run failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "PASS") {
		t.Fatalf("isolated run did not pass:\n%s", out)
	}
	t.SkipNow() // work happened in the isolated child
}

func ipt(t *testing.T, args ...string) {
	t.Helper()
	out, err := exec.Command("iptables", append([]string{"-w", "5"}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("iptables %v: %s: %v", args, out, err)
	}
}

func ensure(t *testing.T) error {
	t.Helper()
	iface, hp, tp, dp, sd, sp, bp := testSpecParams()
	return ensureHostFirewall(context.Background(), iface, hp, tp, dp, sd, sp, bp, true, zerolog.Nop())
}

func verifyNow(t *testing.T) (bool, string) {
	t.Helper()
	out, err := dumpIPTables(context.Background())
	if err != nil {
		t.Fatalf("dump: %v", err)
	}
	d, err := parseIPTablesSave(out)
	if err != nil {
		t.Fatalf("parse real iptables-save output: %v", err)
	}
	ok, class, _ := verifyHostFirewall(d, testSpec(true))
	return ok, class
}

func TestRealInstallDumpVerifyRoundTrip(t *testing.T) {
	requireIsolatedIPTables(t)

	// Fresh install must converge and then verify intact — this is the
	// normalization ground truth (spec args vs real iptables-save output).
	if err := ensure(t); err != nil {
		t.Fatalf("initial ensure: %v", err)
	}
	if ok, class := verifyNow(t); !ok {
		t.Fatalf("fresh install reads as %s — normalization broken", class)
	}

	// Second ensure must take the fast path (still verified after).
	if err := ensure(t); err != nil {
		t.Fatalf("second ensure: %v", err)
	}

	// Mutation matrix: each sabotage must be detected, and ensure must
	// repair back to verified.
	inJump := marked("-i", "veth+", "-j", forwardChain)
	outJump := marked("-o", "veth+", "-j", forwardChain)
	sabotages := []struct {
		name string
		do   func(t *testing.T)
	}{
		{"remove entry jump", func(t *testing.T) {
			ipt(t, append([]string{"-D", "FORWARD"}, inJump...)...)
		}},
		{"duplicate entry jump", func(t *testing.T) {
			ipt(t, append([]string{"-A", "FORWARD"}, outJump...)...)
		}},
		{"reorder entry jumps", func(t *testing.T) {
			ipt(t, append([]string{"-D", "FORWARD"}, inJump...)...)
			ipt(t, append([]string{"-A", "FORWARD"}, inJump...)...)
		}},
		{"remove owned forward rule", func(t *testing.T) {
			ipt(t, "-D", forwardChain, "-i", "veth+", "-p", "udp", "--dport", "443", "-j", "DROP")
		}},
		{"extra rule in owned forward chain", func(t *testing.T) {
			ipt(t, "-A", forwardChain, "-p", "tcp", "--dport", "12345", "-j", "ACCEPT")
		}},
		{"mutate owned port chain", func(t *testing.T) {
			ipt(t, "-t", "filter", "-F", portDropChain)
			ipt(t, "-t", "filter", "-A", portDropChain, "-p", "tcp", "--dport", "9999", "-j", "DROP")
		}},
		{"flush nat prerouting chain", func(t *testing.T) {
			ipt(t, "-t", "nat", "-F", preroutingChain)
		}},
		{"flush nat redirect chain", func(t *testing.T) {
			ipt(t, "-t", "nat", "-F", dnsRedirectChain)
		}},
		{"legacy pre-marker redirect", func(t *testing.T) {
			ipt(t, "-t", "nat", "-I", "PREROUTING", "1",
				"-i", "veth+", "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", "9999")
		}},
		{"legacy pre-marker forward generation", func(t *testing.T) {
			ipt(t, "-A", "FORWARD", "-i", "veth+", "-p", "udp", "--dport", "443", "-j", "DROP")
			ipt(t, "-A", "FORWARD", "-i", "veth+", "-o", "eth0", "-j", "ACCEPT")
			ipt(t, "-A", "FORWARD", "-i", "eth0", "-o", "veth+", "-j", "ACCEPT")
		}},
	}
	for _, s := range sabotages {
		t.Run(s.name, func(t *testing.T) {
			s.do(t)
			if ok, _ := verifyNow(t); ok {
				t.Fatal("sabotage not detected")
			}
			if err := ensure(t); err != nil {
				t.Fatalf("repair ensure: %v", err)
			}
			if ok, class := verifyNow(t); !ok {
				t.Fatalf("not verified after repair: %s", class)
			}
		})
	}

	// Docker-style cohabitation, live: an unconstrained head jump whose tree
	// resolves safe must verify intact; adding a bridge-style accept makes it
	// a repairable bypass that ensure converges by re-heading vmd's jumps —
	// without touching the foreign chain.
	t.Run("cohabiting agent tree", func(t *testing.T) {
		ipt(t, "-N", "AGENT-HOOK")
		ipt(t, "-N", "AGENT-CT")
		ipt(t, "-A", "AGENT-HOOK", "-j", "AGENT-CT")
		ipt(t, "-A", "AGENT-CT", "-o", "br0", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
		ipt(t, "-I", "FORWARD", "1", "-j", "AGENT-HOOK")
		if ok, class := verifyNow(t); !ok {
			t.Fatalf("safe agent tree flagged: %s", class)
		}
		ipt(t, "-A", "AGENT-HOOK", "-i", "br0", "-j", "ACCEPT")
		if ok, class := verifyNow(t); ok || class != "preceded" {
			t.Fatalf("ok=%v class=%s, want preceded", ok, class)
		}
		if err := ensure(t); err != nil {
			t.Fatalf("ensure with permissive agent tree: %v", err)
		}
		if ok, class := verifyNow(t); !ok {
			t.Fatalf("not verified after re-heading: %s", class)
		}
		out, _ := dumpIPTables(context.Background())
		if !strings.Contains(out, "-j AGENT-HOOK") || !strings.Contains(out, "-i br0 -j ACCEPT") {
			t.Fatal("foreign agent tree damaged by repair")
		}
	})

	// Unrelated host rule must survive an install/repair cycle untouched.
	ipt(t, "-A", "FORWARD", "-i", "dummy0", "-j", "ACCEPT")
	ipt(t, append([]string{"-D", "FORWARD"}, inJump...)...) // force slow path
	if err := ensure(t); err != nil {
		t.Fatalf("ensure with unrelated rule: %v", err)
	}
	out, _ := dumpIPTables(context.Background())
	if !strings.Contains(out, "-i dummy0 -j ACCEPT") {
		t.Fatal("unrelated host rule removed by repair")
	}
}
