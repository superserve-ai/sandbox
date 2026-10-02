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
		"/var/lib/sandbox/vmd-state-path": filepath.Join(dir, "state-path"),
		"/var/lib/sandbox/vmd.db":         filepath.Join(dir, "default.db"),
		"/sys/fs/cgroup":                  filepath.Join(dir, "cgfs"),
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
	t.Run("no breadcrumb, records at the default path block", func(t *testing.T) {
		w := newGuardWorld(t)
		w.writeFile("default.db", cgroupRecordJSON(t))
		if rc := w.run(oldBinary); rc == 0 {
			t.Fatal("records at the default path must block")
		}
	})
	t.Run("unknown supervision mode blocks", func(t *testing.T) {
		w := newGuardWorld(t)
		b, err := json.Marshal(VMRecord{ID: "vm-1", Supervision: Supervision("checkpointed")})
		if err != nil {
			t.Fatal(err)
		}
		w.writeFile("default.db", string(b))
		if rc := w.run(oldBinary); rc == 0 {
			t.Fatal("a record in a mode newer than this guard must block the rollback")
		}
	})
	t.Run("clean record miss allows", func(t *testing.T) {
		w := newGuardWorld(t)
		w.writeFile("state-path", filepath.Join(w.dir, "plain.db")+"\n")
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
		w.writeFile("state-path", filepath.Join(w.dir, "locked.db")+"\n")
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
		w.writeFile("state-path", filepath.Join(w.dir, "never-created.db")+"\n")
		if rc := w.run(oldBinary); rc != 0 {
			t.Fatalf("rc=%d, want allow", rc)
		}
	})
	t.Run("breadcrumbed path with a space blocks on records", func(t *testing.T) {
		w := newGuardWorld(t)
		w.writeFile("state-path", filepath.Join(w.dir, "vm state", "vmd.db")+"\n")
		w.writeFile("vm state/vmd.db", cgroupRecordJSON(t))
		if rc := w.run(oldBinary); rc == 0 {
			t.Fatal("records at the breadcrumbed path must block")
		}
	})
	t.Run("empty breadcrumb blocks", func(t *testing.T) {
		w := newGuardWorld(t)
		w.writeFile("state-path", "\n")
		if rc := w.run(oldBinary); rc == 0 {
			t.Fatal("an unreadable recorded state path must block")
		}
	})
}

// Arming must refuse when the host-resident guard is missing: the guard is
// what makes a later rollback safe, so the mode that creates the hazard may
// not activate without it. checkRollbackGuard is the arm precondition's core.
func TestCheckRollbackGuard(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "vmd-rollback-guard")
	dropIn := filepath.Join(dir, "10-rollback-guard.conf")

	if err := checkRollbackGuard(script, dropIn); err == nil {
		t.Fatal("missing guard script must refuse")
	}
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := checkRollbackGuard(script, dropIn); err == nil {
		t.Fatal("non-executable guard script must refuse")
	}
	if err := os.Chmod(script, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checkRollbackGuard(script, dropIn); err == nil {
		t.Fatal("missing drop-in must refuse")
	}
	if err := os.WriteFile(dropIn, []byte("[Service]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := checkRollbackGuard(script, dropIn); err != nil {
		t.Fatalf("complete guard must pass, got %v", err)
	}
}

// The guard's rollback independence rests on one invariant: no deploy script
// revision ever cleans the service.d drop-in directory (old revisions never
// did; this pins that the current one installs the guard and never removes
// drop-ins). A future "cleanup" would strip the protection during the exact
// rollback it exists for.
func TestDeployScriptPreservesGuardDropIns(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "scripts", "deploy-vmd.py"))
	if err != nil {
		t.Fatalf("read deploy script: %v", err)
	}
	s := string(src)
	if !strings.Contains(s, "10-rollback-guard.conf") {
		t.Fatal("deploy script no longer installs the rollback-guard drop-in")
	}
	if !strings.Contains(s, "vmd-rollback-guard") {
		t.Fatal("deploy script no longer installs the rollback-guard script")
	}
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, "service.d") && (strings.Contains(line, "rm ") || strings.Contains(line, "rm -")) {
			t.Fatalf("deploy script removes files under service.d — this strips the rollback guard: %q", line)
		}
	}
}

// The keeper unit's safety rests on two lines: KillMode=process (a keeper
// stop must never signal the VM children) and Restart=no (an auto-restart
// would flap against the no-internal-process rule on older systemd). The
// needrestart fence keeps library upgrades from restarting platform units at
// all. Pin all three so no edit weakens them silently.
func TestKeeperUnitAndFenceInvariants(t *testing.T) {
	unit, err := os.ReadFile(filepath.Join("..", "..", "deploy", "superserve-vms.service"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"KillMode=process", "Restart=no", "Delegate=yes", "DelegateSubgroup=keeper"} {
		if !strings.Contains(string(unit), want) {
			t.Fatalf("superserve-vms.service lost %q", want)
		}
	}
	fence, err := os.ReadFile(filepath.Join("..", "..", "deploy", "needrestart-superserve.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(fence), "qr(^superserve-)") {
		t.Fatal("needrestart fence no longer covers superserve- units")
	}
}
