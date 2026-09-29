package vm

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The snapshot-backup floor guard is safety-critical shell; these cases drive
// deploy/vmd-snapshot-backup-floor-guard the way the staged-intent guard's
// harness drives its guard.
func TestSnapshotBackupFloorGuard(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "deploy", "vmd-snapshot-backup-floor-guard"))
	if err != nil {
		t.Fatalf("read guard script: %v", err)
	}
	for _, want := range []string{SnapshotBackupCapability, snapshotBackupEvidencePath} {
		if !strings.Contains(string(src), want) {
			t.Fatalf("guard script no longer references %q — update this harness", want)
		}
	}
	world := func(t *testing.T) (guard, evidence, dir string) {
		dir = t.TempDir()
		evidence = filepath.Join(dir, "host", "evidence")
		if err := os.MkdirAll(filepath.Dir(evidence), 0o755); err != nil {
			t.Fatal(err)
		}
		guard = filepath.Join(dir, "guard.sh")
		body := strings.ReplaceAll(string(src), snapshotBackupEvidencePath, evidence)
		if err := os.WriteFile(guard, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		return guard, evidence, dir
	}
	run := func(guard, bin string) (bool, string) {
		out, err := exec.Command("sh", guard, bin).CombinedOutput()
		return err == nil, string(out)
	}

	t.Run("no_evidence_admits_any_binary", func(t *testing.T) {
		guard, _, dir := world(t)
		if ok, out := run(guard, writeMarkedBinary(t, filepath.Join(dir, "vmd"))); !ok {
			t.Fatalf("refused with no evidence: %s", out)
		}
	})
	t.Run("evidence_refuses_a_binary_without_the_capability", func(t *testing.T) {
		guard, evidence, dir := world(t)
		if err := os.WriteFile(evidence, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		previous := writeMarkedBinary(t, filepath.Join(dir, "previous"), wakeProtocolMarker, stagedIntentMarker)
		if ok, out := run(guard, previous); ok || !strings.Contains(out, "REFUSING") {
			t.Fatalf("a binary without the capability was admitted: ok=%v %s", ok, out)
		}
		current := writeMarkedBinary(t, filepath.Join(dir, "current"), wakeProtocolMarker, stagedIntentMarker, SnapshotBackupCapability)
		if ok, out := run(guard, current); !ok {
			t.Fatalf("current binary refused: %s", out)
		}
	})
	t.Run("an_unknowable_evidence_file_refuses_a_binary_without_the_capability", func(t *testing.T) {
		guard, evidence, dir := world(t)
		if err := os.Symlink(evidence, evidence); err != nil { // a loop
			t.Fatal(err)
		}
		if ok, out := run(guard, writeMarkedBinary(t, filepath.Join(dir, "previous"))); ok || !strings.Contains(out, "cannot look up") {
			t.Fatalf("admitted over unknowable evidence: ok=%v %s", ok, out)
		}
	})
	t.Run("evidence_with_a_missing_binary_refuses", func(t *testing.T) {
		guard, evidence, dir := world(t)
		if err := os.WriteFile(evidence, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if ok, _ := run(guard, filepath.Join(dir, "no-such-vmd")); ok {
			t.Fatal("a binary that cannot be checked was admitted")
		}
	})
}
