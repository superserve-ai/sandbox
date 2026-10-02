package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Staging lets go of a generation's promoted copy as soon as it is written:
// the copy waits in the upload queue and its pages would only crowd out cache
// live VMs need. A shared base is re-read by every generation on its template
// and keeps its pages, and a copy found already staged is not touched again.
func TestStageTaskDropsOnlyThePromotedCopy(t *testing.T) {
	var dropped []string
	prev := dropStagingPages
	dropStagingPages = func(path string) error {
		dropped = append(dropped, path)
		return nil
	}
	t.Cleanup(func() { dropStagingPages = prev })

	dir := t.TempDir()
	staging := filepath.Join(dir, "staging")
	base := filepath.Join(dir, "base.ext4")
	baseData := []byte("template base bytes")
	if err := os.WriteFile(base, baseData, 0o644); err != nil {
		t.Fatal(err)
	}
	baseSum := sha256.Sum256(baseData)
	overlay := filepath.Join(dir, "rootfs.ext4")
	odata := []byte("overlay bytes")
	if err := os.WriteFile(overlay, odata, 0o644); err != nil {
		t.Fatal(err)
	}
	osum := sha256.Sum256(odata)
	task := Task{
		SandboxID: "sb", Generation: "gen", EnqueuedAt: time.Unix(1, 0),
		Files: []TaskFile{{
			Name: "rootfs.ext4", Path: overlay,
			SHA256: hex.EncodeToString(osum[:]), Size: int64(len(odata)),
			BasePath: base, BaseSHA256: hex.EncodeToString(baseSum[:]),
		}},
	}
	if err := StageTask(staging, &task); err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 1 || dropped[0] != task.Files[0].Path {
		t.Fatalf("dropped %v, want only the promoted copy %s", dropped, task.Files[0].Path)
	}
	if got, err := os.ReadFile(task.Files[0].Path); err != nil || string(got) != string(odata) {
		t.Fatalf("promoted copy = %q, %v; want the source bytes intact", got, err)
	}

	// Already staged: reused, not copied, not dropped again.
	again := task
	again.Files = []TaskFile{{
		Name: "rootfs.ext4", Path: overlay,
		SHA256: hex.EncodeToString(osum[:]), Size: int64(len(odata)),
		BasePath: base, BaseSHA256: hex.EncodeToString(baseSum[:]),
	}}
	if err := StageTask(staging, &again); err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 1 {
		t.Fatalf("dropped %v after a reuse, want no new drop", dropped)
	}
}

// The real hint is harmless on a file that is then read back.
func TestDropPageCacheKeepsTheBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "copy")
	data := []byte("staged bytes that must survive the drop")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := DropPageCache(path); err != nil {
		t.Fatalf("DropPageCache: %v", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != string(data) {
		t.Fatalf("after drop = %q, %v; want %q", got, err, data)
	}
}
