package vm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDurableBuild(t *testing.T) {
	root := t.TempDir()
	const tid = "11111111-1111-1111-1111-111111111111"
	const bvid = "build-22222222-2222-2222-2222-222222222222"
	dir := filepath.Join(root, TemplatesDirName, tid, bvid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	snap := filepath.Join(dir, "snapshot")
	mem := filepath.Join(dir, "mem")
	base := filepath.Join(dir, "base.ext4")
	delta := filepath.Join(dir, "rootfs.delta")
	writeNonEmpty := func(p string) {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{snap, mem, base, delta} {
		writeNonEmpty(p)
	}

	writeMeta := func() {
		b, _ := json.Marshal(map[string]any{
			"snapshot_path":   snap,
			"mem_path":        mem,
			"rootfs_path":     base,
			"base_path":       base,
			"delta_path":      delta,
			"resolved_digest": "sha256:abc",
			"size_bytes":      int64(8589934592),
		})
		if err := os.WriteFile(filepath.Join(dir, "build.meta.json"), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("complete build is adopted as ready", func(t *testing.T) {
		writeMeta()
		got, ok := loadDurableBuild(root, bvid)
		if !ok {
			t.Fatal("expected a complete on-disk build to be adopted")
		}
		if got.Status != BuildStatusReady {
			t.Errorf("status = %q, want ready", got.Status)
		}
		if got.TemplateID != tid {
			t.Errorf("template id = %q, want %q", got.TemplateID, tid)
		}
		if got.Result == nil || got.Result.ResolvedDigest != "sha256:abc" {
			t.Error("result must be populated from build.meta.json")
		}
	})

	t.Run("missing referenced artifact is not adopted", func(t *testing.T) {
		writeMeta()
		if err := os.Remove(delta); err != nil {
			t.Fatal(err)
		}
		if _, ok := loadDurableBuild(root, bvid); ok {
			t.Error("must not adopt when a referenced artifact file is missing")
		}
		writeNonEmpty(delta) // restore for any later use
	})

	t.Run("unknown build returns not found", func(t *testing.T) {
		if _, ok := loadDurableBuild(root, "build-nonexistent"); ok {
			t.Error("unknown build must not be adopted")
		}
	})

	t.Run("no meta json is not adopted", func(t *testing.T) {
		_ = os.Remove(filepath.Join(dir, "build.meta.json"))
		if _, ok := loadDurableBuild(root, bvid); ok {
			t.Error("a build dir without build.meta.json must not be adopted")
		}
	})
}
