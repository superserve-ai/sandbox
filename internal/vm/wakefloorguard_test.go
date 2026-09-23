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
// that can wake a frozen image carries it (see the daemon's capabilities
// command); that a binary built from that package does is shown there.
const wakeProtocolMarker = WakeProtocolCapability

// stagedIntentMarker is the second floor's literal; see StagedIntentCapability.
const stagedIntentMarker = StagedIntentCapability

type wakeGuardWorld struct {
	t        *testing.T
	dir      string
	guard    string
	evidence string
	staged   string
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
	for _, want := range []string{wakeProtocolEvidencePath, stagedIntentMarker, stagedIntentEvidencePath} {
		if !strings.Contains(string(src), want) {
			t.Fatalf("guard script no longer references %q — update this harness", want)
		}
	}
	dir := t.TempDir()
	host := filepath.Join(dir, "host")
	if err := os.MkdirAll(host, 0o755); err != nil {
		t.Fatal(err)
	}
	w := &wakeGuardWorld{t: t, dir: dir, evidence: filepath.Join(host, "evidence"), staged: filepath.Join(host, "staged-evidence")}
	rewritten := strings.ReplaceAll(string(src), wakeProtocolEvidencePath, w.evidence)
	rewritten = strings.ReplaceAll(rewritten, stagedIntentEvidencePath, w.staged)
	w.guard = filepath.Join(dir, "guard.sh")
	if err := os.WriteFile(w.guard, []byte(rewritten), 0o755); err != nil {
		t.Fatal(err)
	}
	return w
}

// binary is a current build when capable, carrying every marker; an old
// build carries none.
func (w *wakeGuardWorld) binary(name string, capable bool) string {
	w.t.Helper()
	if capable {
		return w.binaryWith(name, wakeProtocolMarker, stagedIntentMarker)
	}
	return w.binaryWith(name)
}

func (w *wakeGuardWorld) binaryWith(name string, markers ...string) string {
	w.t.Helper()
	body := "not a real vmd\n"
	for _, m := range markers {
		body += m + "\n"
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

// The second floor fences the build before staged intents: it carries the
// wake protocol, so the first floor admits it, and it would strip the
// manifest a staged intent leaves in place.
func TestStagedIntentFloorGuard(t *testing.T) {
	t.Run("staged_evidence_refuses_a_wake_only_binary_and_admits_a_current_one", func(t *testing.T) {
		w := newWakeGuardWorld(t)
		if err := os.WriteFile(w.staged, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if ok, out := w.run(w.binaryWith("previous-vmd", wakeProtocolMarker)); ok || !strings.Contains(out, "REFUSING") || !strings.Contains(out, stagedIntentMarker) {
			t.Fatalf("wake-only binary admitted over staged evidence: ok=%v %s", ok, out)
		}
		if ok, out := w.run(w.binary("current-vmd", true)); !ok {
			t.Fatalf("current binary refused: %s", out)
		}
	})
	t.Run("wake_evidence_alone_still_admits_a_wake_only_binary", func(t *testing.T) {
		w := newWakeGuardWorld(t)
		if err := os.WriteFile(w.evidence, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if ok, out := w.run(w.binaryWith("previous-vmd", wakeProtocolMarker)); !ok {
			t.Fatalf("a host with no staged intents refused the previous build: %s", out)
		}
	})
	t.Run("both_floors_are_checked", func(t *testing.T) {
		w := newWakeGuardWorld(t)
		for _, p := range []string{w.evidence, w.staged} {
			if err := os.WriteFile(p, nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if ok, _ := w.run(w.binaryWith("staged-only-vmd", stagedIntentMarker)); ok {
			t.Fatal("a binary without the wake protocol was admitted over wake evidence")
		}
		if ok, _ := w.run(w.binaryWith("wake-only-vmd", wakeProtocolMarker)); ok {
			t.Fatal("a binary without staged intents was admitted over staged evidence")
		}
		if ok, out := w.run(w.binary("current-vmd", true)); !ok {
			t.Fatalf("current binary refused: %s", out)
		}
	})
	t.Run("an_unknowable_staged_marker_refuses_a_wake_only_binary", func(t *testing.T) {
		w := newWakeGuardWorld(t)
		if err := os.Symlink(w.staged, w.staged); err != nil {
			t.Fatal(err)
		}
		if ok, out := w.run(w.binaryWith("previous-vmd", wakeProtocolMarker)); ok || !strings.Contains(out, "cannot look up") {
			t.Fatalf("wake-only binary admitted over an unknowable staged marker: ok=%v %s", ok, out)
		}
	})
}
