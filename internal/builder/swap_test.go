package builder

import "strings"

import "testing"

func TestGuestSwapSetupScript(t *testing.T) {
	t.Parallel()

	// Renders cleanly (no leftover format verbs) and carries the load-bearing
	// pieces: RAM-derived size, floor, cap, disk guard, and failure cleanup.
	for _, want := range []string{
		"MemTotal",                  // sizes from guest RAM
		"swap_mib=$((mem_mib / 4))", // RAM/4
		"swap_mib=128",              // floor
		"swap_mib=4096",             // cap
		"df -P -k /",                // POSIX single-line df for the guard
		`fallocate -l "${swap_mib}"M /swapfile`,
		"mkswap /swapfile",
		"swapon /swapfile",
		"rm -f /swapfile", // best-effort cleanup on failure
	} {
		if !strings.Contains(GuestSwapSetupScript, want) {
			t.Fatalf("GuestSwapSetupScript missing %q", want)
		}
	}
	if strings.Contains(GuestSwapSetupScript, "%!") {
		t.Fatalf("GuestSwapSetupScript has an unresolved format verb:\n%s", GuestSwapSetupScript)
	}
}
