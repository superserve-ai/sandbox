package vm

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

// The drain guard must count cgroup-supervised records (the paused-VM case has
// no live process, so only the record catches it) and fail closed on a missing
// store rather than read it as drained.
func TestCheckDrainedCountsCgroupRecords(t *testing.T) {
	// CheckDrained resolves the vms unit's scope via dbus/systemctl before
	// counting records; on a host without systemd the lookup fails closed and
	// the count under test is never reached. Shim the definitive absent
	// answer (unit not loaded, no scope) so the test is hermetic everywhere.
	shim := t.TempDir()
	if err := os.WriteFile(filepath.Join(shim, "systemctl"), []byte("#!/bin/sh\necho \"\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shim+string(os.PathListSeparator)+os.Getenv("PATH"))

	dir := t.TempDir()
	path := filepath.Join(dir, "vmd.db")
	store, err := OpenStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range []VMRecord{
		{ID: "a", Supervision: SupervisionCgroup},
		{ID: "b", Supervision: SupervisionCgroup}, // e.g. paused: record only, no process
		{ID: "c", Supervision: SupervisionUnit},
	} {
		if err := store.Put(rec); err != nil {
			t.Fatal(err)
		}
	}
	store.Close()

	rep, err := CheckDrained(context.Background(), path)
	if err != nil {
		t.Fatalf("CheckDrained: %v", err)
	}
	if rep.CgroupRecords != 2 {
		t.Fatalf("cgroup records: got %d want 2", rep.CgroupRecords)
	}
	if rep.Drained() {
		t.Fatal("must not report drained while cgroup records remain")
	}

	// Missing store must fail closed (error), never read as drained.
	if _, err := CheckDrained(context.Background(), filepath.Join(dir, "nope.db")); err == nil {
		t.Fatal("missing store must error, not report drained")
	}
}

// The memory-ceiling check must accept a real reserve (shipped 95%) and reject
// an ineffective cap (100%) or a missing one, so drift can't silently remove
// the OOM protection.
func TestCapLeavesReserve(t *testing.T) {
	const total = uint64(100_000_000_000)
	if !capLeavesReserve(total*95/100, total) {
		t.Fatal("95% cap must pass (leaves a reserve)")
	}
	if capLeavesReserve(total, total) {
		t.Fatal("100% cap must fail (no reserve)")
	}
	if capLeavesReserve(total*99/100, total) {
		t.Fatal("99% cap must fail (no meaningful reserve)")
	}
	if capLeavesReserve(0, total) {
		t.Fatal("zero cap must fail")
	}
}

func TestParseCgroupPopulated(t *testing.T) {
	for body, want := range map[string]bool{
		"populated 1\nfrozen 0\n": true,
		"populated 0\nfrozen 0\n": false,
		"populated 1":             true,
	} {
		got, err := parseCgroupPopulated(body)
		if err != nil || got != want {
			t.Errorf("parseCgroupPopulated(%q) = %v, %v; want %v, nil", body, got, err, want)
		}
	}
	// A body without an exact "populated 0|1" line is inconclusive, never
	// "empty": kill-completion and reap paths consume this, and inconclusive
	// must read as maybe-alive.
	for _, body := range []string{"frozen 0\n", "", "populated x\n", "populated \n"} {
		if _, err := parseCgroupPopulated(body); err == nil {
			t.Errorf("parseCgroupPopulated(%q) = nil error; want inconclusive error", body)
		}
	}
}

// The oracle-level contract: a readable cgroup.events without a conclusive
// populated line must surface an error (maybe-alive), never (false, nil) —
// (false, nil) is "confirmed dead" to kill/reap/drain consumers.
func TestVMCgroupPopulatedMalformedIsInconclusive(t *testing.T) {
	tree := &cgroupTree{vms: t.TempDir()}
	if err := os.Mkdir(tree.vmCgroupDir("vm-1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree.vmCgroupDir("vm-1"), "cgroup.events"),
		[]byte("frozen 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if populated, err := tree.vmCgroupPopulated("vm-1"); err == nil {
		t.Fatalf("malformed cgroup.events read as conclusive (populated=%v); want error", populated)
	}
	// A missing group stays conclusively empty — the legitimate post-rmdir
	// answer the kill wait depends on.
	if populated, err := tree.vmCgroupPopulated("gone"); err != nil || populated {
		t.Fatalf("missing group = (%v, %v); want (false, nil)", populated, err)
	}
}

// The environment allowlist IS the sandbox-boundary contract: nothing from
// vmd's environ (secrets, flags) may reach the Firecracker chain.
func TestDirectSpawnEnvAllowlist(t *testing.T) {
	env := directSpawnEnv()
	if len(env) != 2 {
		t.Fatalf("allowlist grew to %d entries — additions are a security review: %v", len(env), env)
	}
	for _, kv := range env {
		k := strings.SplitN(kv, "=", 2)[0]
		if k != "PATH" && k != "RUN_DIR" {
			t.Errorf("unexpected env var %q in direct-spawn allowlist", k)
		}
	}
}

// spawnDirect owns the cgroup dir fd: it must close it on every return, so no
// caller can leak one directory fd per launch and none needs the fragile
// keep-alive-then-close dance itself. Failure is forced by the cgroup fd (see
// below), exercising the close-on-failure path.
func TestSpawnDirectOwnsCgroupFD(t *testing.T) {
	dir := t.TempDir()
	cgroupDir, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	// A valid script, so the ONLY reason Start fails is the cgroup fd: a plain
	// temp-dir fd is not a valid CLONE_INTO_CGROUP target, so clone3 fails
	// before the exec (no real cgroup or root needed).
	script := filepath.Join(dir, "start.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	console, err := os.CreateTemp(dir, "console")
	if err != nil {
		t.Fatal(err)
	}
	defer console.Close()

	cmd, err := spawnDirect(script, cgroupDir, console)
	if err == nil {
		if cmd != nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		t.Fatal("expected spawnDirect to fail: a plain temp-dir fd is not a valid CLONE_INTO_CGROUP target")
	}
	// Ownership contract: spawnDirect already closed cgroupDir, so a second
	// Close returns an error. If it were still open, a caller retaining it would
	// leak one fd per launch.
	if cerr := cgroupDir.Close(); cerr == nil {
		t.Error("spawnDirect must close cgroupDir on every return; it was left open (fd leak)")
	}
}

// prlimit is prepended to every direct-spawn launch, so ArmDirectSpawn must
// treat it as a mandatory launch tool: present-and-executable on the launch
// PATH passes, missing or non-executable fails (so arming refuses).
func TestToolOnPath(t *testing.T) {
	dir := t.TempDir()
	other := t.TempDir()
	path := other + string(os.PathListSeparator) + dir

	if toolOnPath("prlimit", path) {
		t.Fatal("must not find prlimit before it exists")
	}
	bin := filepath.Join(dir, "prlimit")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !toolOnPath("prlimit", path) {
		t.Fatal("must find an executable prlimit on the path")
	}
	// A non-executable file must not count (it can't exec in the chain).
	if err := os.Chmod(bin, 0o644); err != nil {
		t.Fatal(err)
	}
	if toolOnPath("prlimit", path) {
		t.Fatal("a non-executable prlimit must not count")
	}
	// A directory named prlimit must not count either.
	if err := os.Remove(bin); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if toolOnPath("prlimit", path) {
		t.Fatal("a directory named prlimit must not count")
	}
}

func TestDirectSpawnScriptPinsNofile(t *testing.T) {
	script, err := directSpawnScript("ns-7", "/run/vmd/launcher.mntns",
		"mount --make-rprivate / && mount -t tmpfs tmpfs /d && ln -s /a /b",
		"/usr/local/bin/firecracker", "/run/x/firecracker.sock", "vm-1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(script, "#!/bin/sh\nexec prlimit --nofile=1024:524288 nsenter ") {
		t.Fatalf("prlimit hop missing or misplaced:\n%s", script)
	}
	// The wrapped body must be the unit path's script verbatim.
	base := fcStartScript("ns-7", "/run/vmd/launcher.mntns",
		"mount --make-rprivate / && mount -t tmpfs tmpfs /d && ln -s /a /b",
		"/usr/local/bin/firecracker", "/run/x/firecracker.sock", "vm-1")
	if strings.Replace(script, "prlimit --nofile=1024:524288 ", "", 1) != base {
		t.Fatal("direct-spawn script diverged from the unit script beyond the prlimit hop")
	}
}

// An unknown supervision value (store corruption, or a mode written by a
// newer binary) must read unmanageable/inconclusive at every dispatcher —
// never default to the unit path, whose vacuous probes against a nonexistent
// unit would release a live FC's record and network.
func TestUnknownSupervisionFailsClosed(t *testing.T) {
	// A systemctl shim answering "unit conclusively down" — exactly the
	// vacuous answer a nonexistent unit gives on a real host. Without
	// validation the dispatchers would trust it and release live resources;
	// every assert below must bite on that, not on a missing systemctl.
	shim := t.TempDir()
	script := "#!/bin/sh\ncase \"$1\" in\nshow) echo inactive ;;\nis-active) exit 3 ;;\nesac\nexit 0\n"
	if err := os.WriteFile(filepath.Join(shim, "systemctl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shim+string(os.PathListSeparator)+os.Getenv("PATH"))

	unknown := Supervision("checkpointed")
	m := &Manager{log: zerolog.Nop(), cfg: ManagerConfig{RunDir: t.TempDir()}, vms: map[string]*VMInstance{
		"vm-1": {ID: "vm-1", Status: StatusPaused, Supervision: unknown},
	}}

	if err := m.stopVM(context.Background(), "vm-1", unknown); err == nil || !strings.Contains(err.Error(), "unknown supervision mode") {
		t.Fatalf("stop must refuse an unknown mode outright, got %v", err)
	}
	if m.vmDefinitelyDead(context.Background(), "vm-1", unknown) {
		t.Fatal("an unknown mode must read maybe-alive even when the unit oracle says dead")
	}
	if m.vmConfirmedAtRest(context.Background(), "vm-1") {
		t.Fatal("an unknown mode must never read at-rest even when the unit oracle says down")
	}
	if _, _, err := m.launchFirecracker(context.Background(), "vm-1", "", "", "", "", unknown, false, false); err == nil || !strings.Contains(err.Error(), "unknown supervision mode") {
		t.Fatalf("a launch over an unknown mode must be refused at dispatch, got %v", err)
	}

	// The drain guard must count an unknown-mode record against the rollback:
	// the old binary cannot manage it either.
	path := filepath.Join(t.TempDir(), "vmd.db")
	store, err := OpenStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(VMRecord{ID: "u1", Supervision: unknown}); err != nil {
		t.Fatal(err)
	}
	store.Close()
	rep, err := CheckDrained(context.Background(), path)
	if err != nil {
		t.Fatalf("CheckDrained: %v", err)
	}
	if rep.CgroupRecords != 1 || rep.Drained() {
		t.Fatalf("an unknown-mode record must block the rollback drain, got records=%d drained=%v", rep.CgroupRecords, rep.Drained())
	}
}

// Supervision must survive record round-trips: losing it on a rewrite is
// the likeliest way a cgroup VM silently reverts to unit-mode in the store,
// after which every unit oracle reads it as dead.
func TestSupervisionRoundTrip(t *testing.T) {
	inst := &VMInstance{ID: "vm-1", Supervision: SupervisionCgroup}
	rec := toRecord(inst)
	if rec.Supervision != SupervisionCgroup {
		t.Fatal("toRecord dropped Supervision")
	}
	back := toInstance(rec)
	if back.Supervision != SupervisionCgroup {
		t.Fatal("toInstance dropped Supervision")
	}

	// Legacy record (predates the field) must read as unit-supervised, and
	// unit-mode must serialize WITHOUT the key (rollback binaries read it).
	var legacy VMRecord
	if err := json.Unmarshal([]byte(`{"id":"old"}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if cgroupSupervised(legacy.Supervision) || legacy.Supervision != SupervisionUnit {
		t.Fatal("legacy record must be unit-supervised")
	}
	out, err := json.Marshal(toRecord(&VMInstance{ID: "u", Supervision: SupervisionUnit}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "supervision") {
		t.Fatalf("unit-mode record must omit the supervision key, got %s", out)
	}
}

func TestFirecrackerAdvertisesCap(t *testing.T) {
	// A fake fc binary whose --version prints the capability line.
	dir := t.TempDir()
	fc := filepath.Join(dir, "fc")
	script := "#!/bin/sh\necho 'Firecracker v1.15.0'\necho 'capability: serial-console-cap'\n"
	if err := os.WriteFile(fc, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if !firecrackerAdvertisesCap(context.Background(), fc, "serial-console-cap") {
		t.Error("should detect the advertised capability")
	}
	if firecrackerAdvertisesCap(context.Background(), fc, "some-other-cap") {
		t.Error("must not match an unadvertised capability")
	}
	// A binary that doesn't print it, and a missing binary, both read absent.
	bare := filepath.Join(dir, "bare")
	_ = os.WriteFile(bare, []byte("#!/bin/sh\necho 'Firecracker v1.15.0'\n"), 0o755)
	if firecrackerAdvertisesCap(context.Background(), bare, "serial-console-cap") {
		t.Error("must not match when the capability is absent")
	}
	if firecrackerAdvertisesCap(context.Background(), filepath.Join(dir, "nope"), "serial-console-cap") {
		t.Error("missing binary must read as absent (fail-closed)")
	}
}

// A traversal vmID must never resolve a cgroup path outside vms/ — "../daemon"
// would land on vmd's own group and a kill there would take the daemon down.
func TestSafeVMCgroupDirRejectsTraversal(t *testing.T) {
	tree := &cgroupTree{vms: "/sys/fs/cgroup/x/vms"}
	for _, bad := range []string{"../daemon", "..", "a/b", `a\b`, "", ".", keeperSubdir} {
		if _, err := tree.safeVMCgroupDir(bad); err == nil {
			t.Errorf("safeVMCgroupDir(%q) must be rejected", bad)
		}
	}
	if got, err := tree.safeVMCgroupDir("vm-123"); err != nil || got != "/sys/fs/cgroup/x/vms/vm-123" {
		t.Fatalf("valid id: got %q err %v", got, err)
	}
}

// The keeper-death fallback keys on the scope-gone sentinel surviving
// createVMCgroup's wrapping: a missing parent scope must stay
// errors.Is-detectable, or the unit-supervision fallback silently stops
// firing. Deliberately NOT bare fs.ErrNotExist — later launch stages can
// wrap ENOENT and must not trigger the fallback (a transient socket failure
// would convert a cgroup VM to unit supervision).
func TestCreateVMCgroupMissingScopeIsScopeGone(t *testing.T) {
	tree := &cgroupTree{vms: filepath.Join(t.TempDir(), "gone", "vms")}
	_, err := tree.createVMCgroup("vm-1")
	if err == nil {
		t.Fatal("expected error for a missing parent scope")
	}
	if !errors.Is(err, errScopeGone) {
		t.Fatalf("missing-scope error must be errScopeGone-detectable, got: %v", err)
	}
	// A missing parent must be the ONLY producer: a plain failed mkdir under
	// a present scope stays a non-sentinel error.
	present := &cgroupTree{vms: t.TempDir()}
	blocker := filepath.Join(present.vms, "vm-2")
	if werr := os.WriteFile(blocker, []byte("x"), 0o644); werr != nil {
		t.Fatal(werr)
	}
	if _, err := present.createVMCgroup("vm-2"); err == nil || errors.Is(err, errScopeGone) {
		t.Fatalf("non-scope mkdir failure must not read as scope-gone, got: %v", err)
	}
}

// A pids ceiling passes only as "max" or with real fleet headroom; systemd's
// small-host derived defaults and garbage both fail closed.
func TestPidsCeilingAdequate(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"max", true},
		{"max\n", true},
		{"1048576", true},
		{"65536", true},
		{"65535", false},
		{"4915", false}, // systemd's documented small-host TasksMax default
		{"0", false},
		{"", false},
		{"unlimited", false},
	}
	for _, tc := range cases {
		if got := pidsCeilingAdequate(tc.in); got != tc.want {
			t.Errorf("pidsCeilingAdequate(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
