package vm

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The drain guard must count cgroup-supervised records (the paused-VM case has
// no live process, so only the record catches it) and fail closed on a missing
// store rather than read it as drained.
func TestCheckDrainedCountsCgroupRecords(t *testing.T) {
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
		"frozen 0\n":              false,
		"":                        false,
		"populated 1":             true,
	} {
		if got := parseCgroupPopulated(body); got != want {
			t.Errorf("parseCgroupPopulated(%q) = %v, want %v", body, got, want)
		}
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
