package vm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTailFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "console.log")

	if _, _, err := tailFile(p, 64); err == nil {
		t.Fatal("missing file must error, not read as empty")
	}

	if err := os.WriteFile(p, []byte("short"), 0o644); err != nil {
		t.Fatal(err)
	}
	tail, size, err := tailFile(p, 64)
	if err != nil || tail != "short" || size != 5 {
		t.Fatalf("small file: tail=%q size=%d err=%v", tail, size, err)
	}

	big := strings.Repeat("x", 100) + "THE-END"
	if err := os.WriteFile(p, []byte(big), 0o644); err != nil {
		t.Fatal(err)
	}
	tail, size, err = tailFile(p, 16)
	if err != nil || size != int64(len(big)) || len(tail) != 16 || !strings.HasSuffix(tail, "THE-END") {
		t.Fatalf("tail window: tail=%q size=%d err=%v", tail, size, err)
	}

	// Empty file: no error, empty tail — "guest produced no output" is the
	// signal the forensics log relies on.
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	tail, size, err = tailFile(p, 16)
	if err != nil || tail != "" || size != 0 {
		t.Fatalf("empty file: tail=%q size=%d err=%v", tail, size, err)
	}
}

func TestSummarizeConsoleTail(t *testing.T) {
	fc := "2026-08-24T20:45:58.3 [vm-1:fc_vcpu 0] Received a VcpuEvent::Resume message\n" +
		"2026-08-24T20:45:58.4 [vm-1:fc_api] The API server received a Get request\n"
	boxd := "[boxd] 20:45:59 init: hostname set\n"
	guest := "EXT4-fs (vda): mounted filesystem\nsome tenant output here\n"

	fcN, bxN, gN, panicked := summarizeConsoleTail(fc + boxd + guest)
	if fcN != 2 || bxN != 1 || gN != 2 || panicked {
		t.Fatalf("classified fc=%d boxd=%d guest=%d panic=%v", fcN, bxN, gN, panicked)
	}
	// Empty console: all zeros — the "stalled before first output" signal.
	fcN, bxN, gN, panicked = summarizeConsoleTail("")
	if fcN+bxN+gN != 0 || panicked {
		t.Fatalf("empty console classified fc=%d boxd=%d guest=%d panic=%v", fcN, bxN, gN, panicked)
	}
	if _, _, _, p := summarizeConsoleTail(fc + "Kernel panic - not syncing: Attempted to kill init!\n"); !p {
		t.Fatal("kernel panic marker missed")
	}
}

func TestForensicsDirNameIsReserved(t *testing.T) {
	// The quarantine shares RunDir with per-VM dirs; a VM id equal to the
	// directory name would alias it — restore cleanup could delete evidence
	// and pruning could delete VM runtime files.
	if !isReservedRunDirName(stallForensicsDirName) {
		t.Fatal("stall-forensics dir name must be a reserved rundir name")
	}
}

func TestPruneOldest(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 5; i++ {
		if err := os.WriteFile(filepath.Join(dir, string(rune('a'+i))+".log"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pruneOldest(dir, 2)
	ents, _ := os.ReadDir(dir)
	if len(ents) != 2 || ents[0].Name() != "d.log" || ents[1].Name() != "e.log" {
		t.Fatalf("kept %v, want the 2 newest by name", ents)
	}
	pruneOldest(dir, 5) // under the cap: no-op
	if ents, _ := os.ReadDir(dir); len(ents) != 2 {
		t.Fatalf("prune under cap removed files: %v", ents)
	}
}
