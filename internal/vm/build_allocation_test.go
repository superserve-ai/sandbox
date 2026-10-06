package vm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildAllocationProofSurvivesRecoveryWithoutCertifyingStatFailure(t *testing.T) {
	dir := t.TempDir()
	rootfs := filepath.Join(dir, "base.ext4")
	file, err := os.Create(rootfs)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(1 << 20); err != nil {
		t.Fatal(err)
	}
	file.Close()
	meta, _ := json.Marshal(map[string]any{"rootfs_path": rootfs})
	if err := os.WriteFile(filepath.Join(dir, buildMetaFilename), meta, 0600); err != nil {
		t.Fatal(err)
	}
	old, err := readBuildMetaJSON(dir)
	if err != nil || old.AllocationsVerified {
		t.Fatalf("old result gained proof: %+v, %v", old, err)
	}
	populateBuildAllocations(old)
	if !old.AllocationsVerified || old.RootfsAllocatedBytes != 0 {
		t.Fatalf("sparse measured zero is not a failed stat: %+v", old)
	}
	if err := writeBuildAllocations(dir, old); err != nil {
		t.Fatal(err)
	}
	recovered, err := readBuildMetaJSON(dir)
	if err != nil || !recovered.AllocationsVerified || recovered.RootfsAllocatedBytes != 0 {
		t.Fatalf("measured zero lost after recovery: %+v, %v", recovered, err)
	}
	// A single failed declared artifact invalidates the whole capability; the
	// old support flag alone must never certify the resulting numeric zero.
	recovered.DeltaPath = filepath.Join(dir, "missing.delta")
	populateBuildAllocations(recovered)
	if recovered.AllocationsVerified {
		t.Fatal("missing delta certified as zero")
	}
	if err := writeBuildAllocations(dir, recovered); err != nil {
		t.Fatal(err)
	}
	failed, err := readBuildMetaJSON(dir)
	if err != nil || failed.AllocationsVerified {
		t.Fatalf("failed stat acquired durable proof: %+v, %v", failed, err)
	}
}
