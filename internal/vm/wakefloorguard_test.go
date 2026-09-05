package vm

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The host-resident wake-floor guard is safety-critical shell with no other
// harness: these cases drive deploy/vmd-wake-floor-guard through its allow
// and refuse paths with the host world (evidence file, vmd binary) stubbed
// into a temp dir.

// wakeProtocolMarker is the literal the guard greps a vmd binary for. A vmd
// that can wake a frozen image carries it; this one does not, on purpose.
const wakeProtocolMarker = "wake-protocol-1"

type wakeGuardWorld struct {
	t        *testing.T
	dir      string
	guard    string
	evidence string
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
	if !strings.Contains(string(src), wakeProtocolEvidencePath) {
		t.Fatalf("guard script no longer references %q — update this harness", wakeProtocolEvidencePath)
	}
	dir := t.TempDir()
	host := filepath.Join(dir, "host")
	if err := os.MkdirAll(host, 0o755); err != nil {
		t.Fatal(err)
	}
	w := &wakeGuardWorld{t: t, dir: dir, evidence: filepath.Join(host, "evidence")}
	rewritten := strings.ReplaceAll(string(src), wakeProtocolEvidencePath, w.evidence)
	w.guard = filepath.Join(dir, "guard.sh")
	if err := os.WriteFile(w.guard, []byte(rewritten), 0o755); err != nil {
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

func (w *wakeGuardWorld) run(bin string) (ok bool, out string) {
	w.t.Helper()
	res, err := exec.Command("sh", w.guard, bin).CombinedOutput()
	return err == nil, string(res)
}

func TestWakeFloorGuard(t *testing.T) {
	t.Run("no_evidence_admits_any_binary", func(t *testing.T) {
		w := newWakeGuardWorld(t)
		if ok, out := w.run(w.binary("vmd", false)); !ok {
			t.Fatalf("refused with no evidence: %s", out)
		}
	})
	t.Run("evidence_refuses_an_incapable_binary_and_admits_a_capable_one", func(t *testing.T) {
		w := newWakeGuardWorld(t)
		if err := os.WriteFile(w.evidence, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if ok, out := w.run(w.binary("old-vmd", false)); ok || !strings.Contains(out, "REFUSING") {
			t.Fatalf("incapable binary admitted over evidence: ok=%v %s", ok, out)
		}
		if ok, out := w.run(w.binary("new-vmd", true)); !ok {
			t.Fatalf("capable binary refused: %s", out)
		}
	})
	// A lookup that fails any other way than "no such file" is not absence:
	// an incapable binary is refused, a capable one still starts.
	t.Run("an_unknowable_marker_refuses_an_incapable_binary", func(t *testing.T) {
		w := newWakeGuardWorld(t)
		if err := os.Symlink(w.evidence, w.evidence); err != nil { // a loop
			t.Fatal(err)
		}
		if ok, out := w.run(w.binary("old-vmd", false)); ok || !strings.Contains(out, "cannot look up") {
			t.Fatalf("incapable binary admitted over an unknowable marker: ok=%v %s", ok, out)
		}
		if ok, out := w.run(w.binary("new-vmd", true)); !ok {
			t.Fatalf("capable binary refused over an unknowable marker: %s", out)
		}
	})
	t.Run("evidence_with_a_missing_binary_refuses", func(t *testing.T) {
		w := newWakeGuardWorld(t)
		if err := os.WriteFile(w.evidence, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if ok, _ := w.run(filepath.Join(w.dir, "no-such-vmd")); ok {
			t.Fatal("a binary that cannot be checked was admitted")
		}
	})
	// The guard never looks at the snapshot trees: a frozen image with no
	// evidence beside it is invisible to it by design, which is why every
	// producer and importer of one raises the floor first.
	t.Run("no_evidence_means_no_walk", func(t *testing.T) {
		w := newWakeGuardWorld(t)
		sb := filepath.Join(w.dir, "snapshots", "vm-1")
		if err := os.MkdirAll(sb, 0o755); err != nil {
			t.Fatal(err)
		}
		seedFrozenManifest(t, filepath.Join(sb, "mem.snap"), "tok")
		if ok, out := w.run(w.binary("vmd", false)); !ok {
			t.Fatalf("the guard walked the trees: %s", out)
		}
	})
}
