package vm

import (
	"os"
	"path/filepath"
	"testing"
)

// TestReadBuildMetaJSONImageConfig verifies that the image_config block written
// by template-builder survives the round-trip into BuildTemplateResult, so the
// captured ENTRYPOINT/CMD/env/user/workdir reach the control plane for the
// bring-your-image start path. (vm compiles on linux only; this runs there.)
func TestReadBuildMetaJSONImageConfig(t *testing.T) {
	dir := t.TempDir()
	const metaJSON = `{
  "snapshot_path": "/snap/snapshot",
  "mem_path": "/snap/mem",
  "rootfs_path": "/snap/base.ext4",
  "base_path": "/snap/base.ext4",
  "delta_path": "/snap/overlay.ext4",
  "resolved_digest": "sha256:deadbeef",
  "image_config": {
    "entrypoint": ["/usr/bin/python", "-u"],
    "cmd": ["app.py"],
    "env": {"PORT": "8080", "LANG": "C.UTF-8"},
    "working_dir": "/app",
    "user": "1000:1000"
  },
  "size_bytes": 12345,
  "built_at": "2026-06-21T00:00:00Z"
}`
	if err := os.WriteFile(filepath.Join(dir, "build.meta.json"), []byte(metaJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := readBuildMetaJSON(dir)
	if err != nil {
		t.Fatalf("readBuildMetaJSON: %v", err)
	}
	if res.ResolvedDigest != "sha256:deadbeef" {
		t.Errorf("digest = %q", res.ResolvedDigest)
	}
	d := res.ImageDefaults
	if got, want := d.Entrypoint, []string{"/usr/bin/python", "-u"}; !equalStr(got, want) {
		t.Errorf("entrypoint = %v, want %v", got, want)
	}
	if got, want := d.Cmd, []string{"app.py"}; !equalStr(got, want) {
		t.Errorf("cmd = %v, want %v", got, want)
	}
	if d.Env["PORT"] != "8080" || d.Env["LANG"] != "C.UTF-8" {
		t.Errorf("env = %v", d.Env)
	}
	if d.WorkingDir != "/app" {
		t.Errorf("workdir = %q", d.WorkingDir)
	}
	if d.User != "1000:1000" {
		t.Errorf("user = %q", d.User)
	}
}

// TestReadBuildMetaJSONNoImageConfig confirms older meta files without an
// image_config block still parse, yielding zero ImageDefaults (back-compat).
func TestReadBuildMetaJSONNoImageConfig(t *testing.T) {
	dir := t.TempDir()
	const metaJSON = `{"snapshot_path":"/s","mem_path":"/m","base_path":"/b","resolved_digest":"sha256:abc","size_bytes":1}`
	if err := os.WriteFile(filepath.Join(dir, "build.meta.json"), []byte(metaJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := readBuildMetaJSON(dir)
	if err != nil {
		t.Fatalf("readBuildMetaJSON: %v", err)
	}
	if !res.ImageDefaults.IsZero() {
		t.Errorf("expected zero ImageDefaults for legacy meta, got %#v", res.ImageDefaults)
	}
}

func equalStr(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
