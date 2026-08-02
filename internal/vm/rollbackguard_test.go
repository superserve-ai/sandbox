package vm

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The host-resident rollback guard is safety-critical shell with no other
// harness: these cases drive deploy/vmd-rollback-guard through every
// allow/block path with the host world (systemctl, cgroupfs, env file,
// state file) stubbed into a temp dir.

type guardWorld struct {
	t     *testing.T
	dir   string
	guard string
}

func newGuardWorld(t *testing.T) *guardWorld {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("..", "..", "deploy", "vmd-rollback-guard"))
	if err != nil {
		t.Fatalf("read guard script: %v", err)
	}
	dir := t.TempDir()
	w := &guardWorld{t: t, dir: dir}
	rewritten := string(src)
	for from, to := range map[string]string{
		"/etc/sandbox/vmd.env": filepath.Join(dir, "vmd.env"),
		"/sys/fs/cgroup":       filepath.Join(dir, "cgfs"),
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
	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	w.systemctl(0, "")
	return w
}

// cgroupRecordJSON is a state-file fixture built from REAL marshal bytes: the
// guard's grep pattern is coupled to VMRecord's json tag and the
// SupervisionCgroup value by nothing else, so hand-written JSON here would
// keep passing after a rename that silently breaks the guard on real hosts.
func cgroupRecordJSON(t *testing.T) string {
	t.Helper()
	b, err := json.Marshal(VMRecord{ID: "vm-1", Supervision: SupervisionCgroup})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// systemctl installs a PATH shim: exit rc, printing out for `show`.
func (w *guardWorld) systemctl(rc int, out string) {
	w.t.Helper()
	shim := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' %q\nexit %d\n", out, rc)
	if err := os.WriteFile(filepath.Join(w.dir, "bin", "systemctl"), []byte(shim), 0o755); err != nil {
		w.t.Fatal(err)
	}
}

func (w *guardWorld) writeFile(rel, content string) {
	w.t.Helper()
	p := filepath.Join(w.dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		w.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		w.t.Fatal(err)
	}
}

func (w *guardWorld) mkdir(rel string) {
	w.t.Helper()
	if err := os.MkdirAll(filepath.Join(w.dir, rel), 0o755); err != nil {
		w.t.Fatal(err)
	}
}

// run executes the guard against the given candidate binary content and
// returns the exit code (0 = allow, non-zero = block).
func (w *guardWorld) run(binContent string) int {
	w.t.Helper()
	bin := filepath.Join(w.dir, "candidate-vmd")
	if err := os.WriteFile(bin, []byte(binContent), 0o755); err != nil {
		w.t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", w.guard, bin)
	cmd.Env = append(os.Environ(), "PATH="+filepath.Join(w.dir, "bin")+":"+os.Getenv("PATH"))
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		w.t.Fatalf("run guard: %v", err)
	}
	return 0
}

const (
	oldBinary     = "binary without the marker"
	capableBinary = "binary carrying the cgroup-supervision marker"
)

func TestRollbackGuard(t *testing.T) {
	t.Run("capable binary allowed even when inspection is broken", func(t *testing.T) {
		w := newGuardWorld(t)
		w.systemctl(1, "")
		if rc := w.run(capableBinary); rc != 0 {
			t.Fatalf("rc=%d, want allow", rc)
		}
	})
	t.Run("systemctl failure blocks an incapable binary", func(t *testing.T) {
		w := newGuardWorld(t)
		w.systemctl(1, "")
		if rc := w.run(oldBinary); rc == 0 {
			t.Fatal("an uninspectable scope must block")
		}
	})
	t.Run("empty scope and no records allows", func(t *testing.T) {
		w := newGuardWorld(t)
		if rc := w.run(oldBinary); rc != 0 {
			t.Fatalf("rc=%d, want allow", rc)
		}
	})
	t.Run("populated scope child blocks", func(t *testing.T) {
		w := newGuardWorld(t)
		w.systemctl(0, "/scope")
		w.mkdir("cgfs/scope/vm-1")
		if rc := w.run(oldBinary); rc == 0 {
			t.Fatal("a live VM cgroup must block")
		}
	})
	t.Run("keeper-only scope allows", func(t *testing.T) {
		w := newGuardWorld(t)
		w.systemctl(0, "/scope")
		w.mkdir("cgfs/scope/keeper")
		if rc := w.run(oldBinary); rc != 0 {
			t.Fatalf("rc=%d, want allow", rc)
		}
	})
	t.Run("cgroup records at the default state path block", func(t *testing.T) {
		w := newGuardWorld(t)
		w.writeFile("vmd.env", "RUN_DIR="+filepath.Join(w.dir, "state", "rundir")+"\n")
		w.writeFile("state/vmd.db", cgroupRecordJSON(t))
		if rc := w.run(oldBinary); rc == 0 {
			t.Fatal("records at the RUN_DIR-derived path must block")
		}
	})
	t.Run("clean record miss allows", func(t *testing.T) {
		w := newGuardWorld(t)
		w.writeFile("vmd.env", "VMD_STATE_PATH="+filepath.Join(w.dir, "plain.db")+"\n")
		w.writeFile("plain.db", "no records here")
		if rc := w.run(oldBinary); rc != 0 {
			t.Fatalf("rc=%d, want allow", rc)
		}
	})
	t.Run("unreadable state file blocks", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads through 0000 modes")
		}
		w := newGuardWorld(t)
		w.writeFile("vmd.env", "VMD_STATE_PATH="+filepath.Join(w.dir, "locked.db")+"\n")
		w.writeFile("locked.db", "whatever")
		if err := os.Chmod(filepath.Join(w.dir, "locked.db"), 0); err != nil {
			t.Fatal(err)
		}
		if rc := w.run(oldBinary); rc == 0 {
			t.Fatal("an unscannable state file must block")
		}
	})
	t.Run("missing state file allows", func(t *testing.T) {
		w := newGuardWorld(t)
		w.writeFile("vmd.env", "VMD_STATE_PATH="+filepath.Join(w.dir, "never-created.db")+"\n")
		if rc := w.run(oldBinary); rc != 0 {
			t.Fatalf("rc=%d, want allow", rc)
		}
	})
	t.Run("double-quoted state path with a space blocks on records", func(t *testing.T) {
		w := newGuardWorld(t)
		w.writeFile("vmd.env", fmt.Sprintf("VMD_STATE_PATH=%q\n", filepath.Join(w.dir, "vm state", "vmd.db")))
		w.writeFile("vm state/vmd.db", cgroupRecordJSON(t))
		if rc := w.run(oldBinary); rc == 0 {
			t.Fatal("a systemd-quoted path must be unquoted before the scan")
		}
	})
	t.Run("single-quoted RUN_DIR derivation blocks on records", func(t *testing.T) {
		w := newGuardWorld(t)
		w.writeFile("vmd.env", "RUN_DIR='"+filepath.Join(w.dir, "vm state", "rundir")+"'\n")
		w.writeFile("vm state/vmd.db", cgroupRecordJSON(t))
		if rc := w.run(oldBinary); rc == 0 {
			t.Fatal("a single-quoted RUN_DIR must derive the real state path")
		}
	})
}
