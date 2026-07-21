package builder

import (
	"strings"
	"testing"
)

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
		`fallocate -l "${swap_mib}"M /.superserve-swapfile`,
		"mkswap /.superserve-swapfile",
		"swapon /.superserve-swapfile",
		"rm -f /.superserve-swapfile",    // best-effort cleanup on failure
		"[ ! -f /.superserve-swapfile ]", // guard on the builder-owned path
	} {
		if !strings.Contains(GuestSwapSetupScript, want) {
			t.Fatalf("GuestSwapSetupScript missing %q", want)
		}
	}
	if strings.Contains(GuestSwapSetupScript, "%!") {
		t.Fatalf("GuestSwapSetupScript has an unresolved format verb:\n%s", GuestSwapSetupScript)
	}
}
