package vm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
)

// trimOversizedConsoles bounds a console file to the first maxConsoleBytes,
// keeping boot output and dropping the untrusted overflow.
func TestTrimOversizedConsoles(t *testing.T) {
	runDir := t.TempDir()
	vmID := "vm-1"
	if err := os.MkdirAll(filepath.Join(runDir, vmID), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(runDir, vmID, "console.log")
	if err := os.WriteFile(path, make([]byte, maxConsoleBytes+4096), 0o644); err != nil {
		t.Fatal(err)
	}

	m := &Manager{log: zerolog.Nop()}
	m.cfg.RunDir = runDir
	m.cgroups = &cgroupTree{vms: t.TempDir()}
	// Register the VM cgroup so scanVMCgroups sees it.
	if err := os.MkdirAll(filepath.Join(m.cgroups.vms, vmID), 0o755); err != nil {
		t.Fatal(err)
	}

	m.trimOversizedConsoles()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != maxConsoleBytes {
		t.Fatalf("console size = %d, want %d (trimmed to cap)", fi.Size(), maxConsoleBytes)
	}
}
