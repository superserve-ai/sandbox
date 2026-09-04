package vm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The host-resident wake-floor guard is safety-critical shell with no other
// harness: these cases drive deploy/vmd-wake-floor-guard through its allow
// and refuse paths with the host world (evidence file, snapshot-directory
// breadcrumb, snapshot tree, vmd binary) stubbed into a temp dir.

// wakeProtocolMarker is the literal the guard greps a vmd binary for. A vmd
// that can wake a frozen image carries it; this one does not, on purpose.
const wakeProtocolMarker = "wake-protocol-1"

type wakeGuardWorld struct {
	t         *testing.T
	dir       string
	guard     string
	snapshots string
}

func newWakeGuardWorld(t *testing.T) *wakeGuardWorld {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("..", "..", "deploy", "vmd-wake-floor-guard"))
	if err != nil {
		t.Fatalf("read guard script: %v", err)
	}
	if !strings.Contains(string(src), wakeProtocolMarker) {
		t.Fatalf("guard script no longer greps for %q — update this harness", wakeProtocolMarker)
	}
	dir := t.TempDir()
	w := &wakeGuardWorld{t: t, dir: dir, snapshots: filepath.Join(dir, "default-snapshots")}
	rewritten := string(src)
	for from, to := range map[string]string{
		wakeProtocolEvidencePath:     filepath.Join(dir, "evidence"),
		SnapshotDirBreadcrumbPath:    filepath.Join(dir, "snapshot-dir"),
		"/var/lib/sandbox/snapshots": w.snapshots,
	} {
		if !strings.Contains(rewritten, from) {
			t.Fatalf("guard script no longer references %q — update this harness", from)
		}
		rewritten = strings.ReplaceAll(rewritten, from, to)
	}
	w.guard = filepath.Join(dir, "guard.sh")
	if err := os.WriteFile(w.guard, []byte(rewritten), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(w.snapshots, 0o755); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *wakeGuardWorld) binary(name string, capable bool) string {
	w.t.Helper()
	body := "not a real vmd\n"
	if capable {
		body += wakeProtocolMarker + "\n"
	}
	p := filepath.Join(w.dir, name)
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		w.t.Fatal(err)
	}
	return p
}

func strconvItoa(i int) string { return fmt.Sprintf("%d", i) }

func (w *wakeGuardWorld) run(bin string) (ok bool, out string) {
	w.t.Helper()
	res, err := exec.Command("sh", w.guard, bin).CombinedOutput()
	return err == nil, string(res)
}

func TestWakeFloorGuard(t *testing.T) {
	t.Run("no_witness_admits_any_binary", func(t *testing.T) {
		w := newWakeGuardWorld(t)
		if ok, out := w.run(w.binary("vmd", false)); !ok {
			t.Fatalf("refused with no witness: %s", out)
		}
	})
	t.Run("evidence_refuses_an_incapable_binary_and_admits_a_capable_one", func(t *testing.T) {
		w := newWakeGuardWorld(t)
		if err := os.WriteFile(filepath.Join(w.dir, "evidence"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if ok, out := w.run(w.binary("old-vmd", false)); ok || !strings.Contains(out, "REFUSING") {
			t.Fatalf("incapable binary admitted over evidence: ok=%v %s", ok, out)
		}
		if ok, out := w.run(w.binary("new-vmd", true)); !ok {
			t.Fatalf("capable binary refused: %s", out)
		}
	})
	t.Run("a_frozen_manifest_is_a_witness_an_unfrozen_one_is_not", func(t *testing.T) {
		w := newWakeGuardWorld(t)
		// The daemon's breadcrumb points the guard at a custom directory.
		custom := filepath.Join(w.dir, "custom-snapshots")
		tpl := filepath.Join(custom, TemplatesDirName, "tpl", "build-1")
		if err := os.MkdirAll(tpl, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(w.dir, "snapshot-dir"), []byte(custom+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := WriteWallClockManifest(filepath.Join(tpl, "mem.snap"), WallClockManifest{Version: WallClockManifestVersion, ArtifactID: "a", GuestCorrectsClock: true}); err != nil {
			t.Fatal(err)
		}
		if ok, out := w.run(w.binary("vmd", false)); !ok {
			t.Fatalf("refused over an unfrozen manifest: %s", out)
		}
		seedFrozenManifest(t, filepath.Join(tpl, "mem.snap"), "tok")
		if ok, out := w.run(w.binary("vmd", false)); ok || !strings.Contains(out, "frozen image manifest") {
			t.Fatalf("incapable binary admitted over a frozen template: ok=%v %s", ok, out)
		}
		if ok, out := w.run(w.binary("new-vmd", true)); !ok {
			t.Fatalf("capable binary refused: %s", out)
		}
	})
	// The walk is batched, so a host with many images neither overflows an
	// argument list nor admits a binary by accident; one frozen image among
	// thousands still refuses it.
	t.Run("thousands_of_images_are_walked_whole", func(t *testing.T) {
		w := newWakeGuardWorld(t)
		for i := 0; i < 3000; i++ {
			sb := filepath.Join(w.snapshots, "vm-"+strconvItoa(i))
			if err := os.MkdirAll(sb, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := writeWallClockManifestLazy(filepath.Join(sb, "mem.snap"), WallClockManifest{Version: WallClockManifestVersion, ArtifactID: "a", GuestCorrectsClock: true}); err != nil {
				t.Fatal(err)
			}
		}
		if ok, out := w.run(w.binary("vmd", false)); !ok {
			t.Fatalf("refused with only unfrozen images: %s", out)
		}
		seedFrozenManifest(t, filepath.Join(w.snapshots, "vm-1500", "mem.snap"), "tok")
		if ok, _ := w.run(w.binary("vmd", false)); ok {
			t.Fatal("incapable binary admitted over one frozen image among thousands")
		}
		if ok, out := w.run(w.binary("new-vmd", true)); !ok {
			t.Fatalf("capable binary refused: %s", out)
		}
	})
	t.Run("without_a_breadcrumb_the_default_directory_is_scanned", func(t *testing.T) {
		w := newWakeGuardWorld(t)
		sb := filepath.Join(w.snapshots, "vm-1")
		if err := os.MkdirAll(sb, 0o755); err != nil {
			t.Fatal(err)
		}
		seedFrozenManifest(t, filepath.Join(sb, "mem.snap"), "tok")
		if ok, _ := w.run(w.binary("vmd", false)); ok {
			t.Fatal("incapable binary admitted over a frozen paused image in the default directory")
		}
	})
}
