package vm

import (
	"os"
	"testing"
)

// TestMain mirrors cmd/vmd's hidden launcher-prune dispatch: the launcher
// build re-execs /proc/<pid>/exe, which under `go test` resolves to the test
// binary. Without this hook the privileged integration build would re-enter
// the test harness inside the unshared namespace instead of pruning it.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == launcherPruneArg {
		os.Exit(LauncherPruneMain())
	}
	os.Exit(m.Run())
}
