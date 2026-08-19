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
	sabotages := []struct {
		name string
		do   func(t *testing.T)
	}{
		{"remove shared rule", func(t *testing.T) {
			ipt(t, append([]string{"-D", "FORWARD"}, marked("-i", "veth+", "-p", "udp", "--dport", "443", "-j", "DROP")...)...)
		}},
		{"duplicate shared rule", func(t *testing.T) {
			ipt(t, append([]string{"-A", "FORWARD"}, marked("-i", "veth+", "-p", "udp", "--dport", "443", "-j", "DROP")...)...)
		}},
		{"reorder (clamp after accept)", func(t *testing.T) {
			clamp := marked("-o", "eth0", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu")
			ipt(t, append([]string{"-D", "FORWARD"}, clamp...)...)
			ipt(t, append([]string{"-A", "FORWARD"}, clamp...)...)
		}},
		{"mutate owned rule", func(t *testing.T) {
			ipt(t, "-t", "filter", "-F", portDropChain)
			ipt(t, "-t", "filter", "-A", portDropChain, "-p", "tcp", "--dport", "9999", "-j", "DROP")
		}},
		{"extra rule in owned chain", func(t *testing.T) {
			ipt(t, "-t", "filter", "-A", portDropChain, "-p", "tcp", "--dport", "12345", "-j", "DROP")
		}},
		{"delete owned chain jump", func(t *testing.T) {
			ipt(t, append([]string{"-D", "FORWARD"}, marked("-i", "veth+", "-j", portDropChain)...)...)
		}},
		{"flush nat redirect chain", func(t *testing.T) {
			ipt(t, "-t", "nat", "-F", dnsRedirectChain)
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

	// Unrelated host rule must survive an install/repair cycle untouched.
	ipt(t, "-A", "FORWARD", "-i", "dummy0", "-j", "ACCEPT")
	ipt(t, append([]string{"-D", "FORWARD"}, marked("-i", "veth+", "-o", "eth0", "-j", "ACCEPT")...)...) // force slow path
	if err := ensure(t); err != nil {
		t.Fatalf("ensure with unrelated rule: %v", err)
	}
	out, _ := dumpIPTables(context.Background())
	if !strings.Contains(out, "-i dummy0 -j ACCEPT") {
		t.Fatal("unrelated host rule removed by repair")
	}
}
