package vm

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The staged-intent floor guard is safety-critical shell with no other
// harness: these cases drive deploy/vmd-staged-intent-floor-guard the way
// the wake floor's harness drives its guard, then walk the rollback that
// gives it a file of its own.

// stagedIntentMarker is the literal the guard greps a vmd binary for.
const stagedIntentMarker = StagedIntentCapability

type stagedGuardWorld struct {
	t        *testing.T
	dir      string
	guard    string
	evidence string
}

func newStagedGuardWorld(t *testing.T) *stagedGuardWorld {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("..", "..", "deploy", "vmd-staged-intent-floor-guard"))
	if err != nil {
		t.Fatalf("read guard script: %v", err)
	}
	for _, want := range []string{stagedIntentMarker, stagedIntentEvidencePath} {
		if !strings.Contains(string(src), want) {
			t.Fatalf("guard script no longer references %q — update this harness", want)
		}
	}
	dir := t.TempDir()
	w := &stagedGuardWorld{t: t, dir: dir, evidence: filepath.Join(dir, "host", "staged-evidence")}
	if err := os.MkdirAll(filepath.Dir(w.evidence), 0o755); err != nil {
		t.Fatal(err)
	}
	w.guard = filepath.Join(dir, "guard.sh")
	if err := os.WriteFile(w.guard, []byte(strings.ReplaceAll(string(src), stagedIntentEvidencePath, w.evidence)), 0o755); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *stagedGuardWorld) binary(name string, markers ...string) string {
	w.t.Helper()
	return writeMarkedBinary(w.t, filepath.Join(w.dir, name), markers...)
}

func writeMarkedBinary(t *testing.T, path string, markers ...string) string {
	t.Helper()
	body := "not a real vmd\n"
	for _, m := range markers {
		body += m + "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func (w *stagedGuardWorld) run(bin string) (ok bool, out string) {
	w.t.Helper()
	res, err := exec.Command("sh", w.guard, bin).CombinedOutput()
	return err == nil, string(res)
}

func TestStagedIntentFloorGuard(t *testing.T) {
	t.Run("no_evidence_admits_any_binary", func(t *testing.T) {
		w := newStagedGuardWorld(t)
		if ok, out := w.run(w.binary("vmd")); !ok {
			t.Fatalf("refused with no evidence: %s", out)
		}
	})
	// The build before this one carries the wake protocol, so the wake floor
	// admits it; only this floor tells it from a current build.
	t.Run("evidence_refuses_a_wake_only_binary_and_admits_a_current_one", func(t *testing.T) {
		w := newStagedGuardWorld(t)
		if err := os.WriteFile(w.evidence, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if ok, out := w.run(w.binary("previous-vmd", wakeProtocolMarker)); ok || !strings.Contains(out, "REFUSING") {
			t.Fatalf("wake-only binary admitted over evidence: ok=%v %s", ok, out)
		}
		if ok, out := w.run(w.binary("current-vmd", wakeProtocolMarker, stagedIntentMarker)); !ok {
			t.Fatalf("current binary refused: %s", out)
		}
	})
	t.Run("an_unknowable_marker_refuses_a_wake_only_binary", func(t *testing.T) {
		w := newStagedGuardWorld(t)
		if err := os.Symlink(w.evidence, w.evidence); err != nil { // a loop
			t.Fatal(err)
		}
		if ok, out := w.run(w.binary("previous-vmd", wakeProtocolMarker)); ok || !strings.Contains(out, "cannot look up") {
			t.Fatalf("wake-only binary admitted over an unknowable marker: ok=%v %s", ok, out)
		}
		if ok, out := w.run(w.binary("current-vmd", wakeProtocolMarker, stagedIntentMarker)); !ok {
			t.Fatalf("current binary refused over an unknowable marker: %s", out)
		}
	})
	t.Run("evidence_with_a_missing_binary_refuses", func(t *testing.T) {
		w := newStagedGuardWorld(t)
		if err := os.WriteFile(w.evidence, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if ok, _ := w.run(filepath.Join(w.dir, "no-such-vmd")); ok {
			t.Fatal("a binary that cannot be checked was admitted")
		}
	})
}

// A rollback deploys the revision before this one. Its bundle carries the
// wake floor's guard and drop-in and reinstalls them; it knows nothing of
// this guard. The service then starts through every drop-in, so this guard
// still runs, and a host that journalled a staged intent refuses the binary
// that would misread it.
func TestStagedIntentFloorSurvivesAPredecessorDeploy(t *testing.T) {
	host := t.TempDir()
	bin := filepath.Join(host, "bin")
	dropins := filepath.Join(host, "service.d")
	for _, d := range []string{bin, dropins} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	evidence := map[string]string{
		wakeProtocolEvidencePath: filepath.Join(host, "wake-evidence"),
		stagedIntentEvidencePath: filepath.Join(host, "staged-evidence"),
	}
	repo := filepath.Join("..", "..", "deploy")
	// install places a guard and its drop-in the way the deploy does, with
	// the host's paths rewritten into this world.
	install := func(script, conf, dropin string) {
		t.Helper()
		src, err := os.ReadFile(filepath.Join(repo, script))
		if err != nil {
			t.Fatal(err)
		}
		body := string(src)
		for from, to := range evidence {
			body = strings.ReplaceAll(body, from, to)
		}
		if err := os.WriteFile(filepath.Join(bin, script), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		c, err := os.ReadFile(filepath.Join(repo, conf))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dropins, dropin), []byte(strings.ReplaceAll(string(c), "/usr/local/bin/", bin+"/")), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// start runs every drop-in's ExecStartPre in order against a binary, as
	// the service start does, and reports the first refusal.
	start := func(binary string) (bool, string) {
		t.Helper()
		entries, err := os.ReadDir(dropins)
		if err != nil {
			t.Fatal(err)
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		sort.Strings(names)
		ran := 0
		for _, n := range names {
			c, err := os.ReadFile(filepath.Join(dropins, n))
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range strings.Split(string(c), "\n") {
				if !strings.HasPrefix(line, "ExecStartPre=") {
					continue
				}
				fields := strings.Fields(strings.TrimPrefix(line, "ExecStartPre="))
				fields[len(fields)-1] = binary
				ran++
				if out, err := exec.Command("sh", fields...).CombinedOutput(); err != nil {
					return false, n + ": " + string(out)
				}
			}
		}
		if ran != 2 {
			t.Fatalf("expected the two floor guards to run at start, ran %d", ran)
		}
		return true, ""
	}
	previous := writeMarkedBinary(t, filepath.Join(host, "previous-vmd"), wakeProtocolMarker)
	current := writeMarkedBinary(t, filepath.Join(host, "current-vmd"), wakeProtocolMarker, stagedIntentMarker)

	// This revision's deploy.
	install("vmd-wake-floor-guard", "superserve-vmd-wake-floor-guard.conf", "30-wake-floor-guard.conf")
	install("vmd-staged-intent-floor-guard", "superserve-vmd-staged-intent-floor-guard.conf", "31-staged-intent-floor-guard.conf")
	if ok, out := start(current); !ok {
		t.Fatalf("current build refused: %s", out)
	}
	// The host journals a staged intent.
	if err := os.WriteFile(evidence[stagedIntentEvidencePath], nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// The predecessor's deploy: its preflight is the wake guard, which admits
	// its binary, and it reinstalls that guard and drop-in and nothing else.
	if out, err := exec.Command("sh", filepath.Join(bin, "vmd-wake-floor-guard"), previous).CombinedOutput(); err != nil {
		t.Fatalf("the predecessor's own preflight refused it, so this test no longer models the rollback: %s", out)
	}
	install("vmd-wake-floor-guard", "superserve-vmd-wake-floor-guard.conf", "30-wake-floor-guard.conf")
	// Its service start still meets this guard.
	if ok, out := start(previous); ok || !strings.Contains(out, stagedIntentMarker) {
		t.Fatalf("the predecessor started after its deploy: ok=%v %s", ok, out)
	}
	if ok, out := start(current); !ok {
		t.Fatalf("current build refused after the sequence: %s", out)
	}
	// A host that never journalled one lets the predecessor start.
	if err := os.Remove(evidence[stagedIntentEvidencePath]); err != nil {
		t.Fatal(err)
	}
	if ok, out := start(previous); !ok {
		t.Fatalf("a host with no staged intents refused the predecessor: %s", out)
	}
}
