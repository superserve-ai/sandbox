package vm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
)

func TestIsReservedCgroupName(t *testing.T) {
	for name, reserved := range map[string]bool{
		"keeper":    true,
		"spare-0":   true,
		"spare-131": true,
		"spare-":    true, // malformed but still ours — never a vmID
		"keeper2":   false,
		"a1b2c3d4-0000-0000-0000-000000000000": false,
	} {
		if got := isReservedCgroupName(name); got != reserved {
			t.Errorf("isReservedCgroupName(%q) = %v, want %v", name, got, reserved)
		}
	}
}

func TestScanVMCgroupsSkipsReserved(t *testing.T) {
	dir := t.TempDir()
	tree := &cgroupTree{vms: dir}
	for _, d := range []string{"keeper", "spare-1", "spare-9", "vm-uuid-1"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	ids, err := tree.scanVMCgroups()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != "vm-uuid-1" {
		t.Fatalf("scan = %v, want only the VM dir", ids)
	}
}

// newTestSparePool builds a pool over a plain tempdir — mkdir/rename/rmdir
// semantics there match kernfs for everything the pool does, and the
// oom.group attribute becomes a regular file.
func newTestSparePool(t *testing.T, target int) *spareCgroupPool {
	t.Helper()
	return newSpareCgroupPool(&cgroupTree{vms: t.TempDir()}, target, zerolog.Nop())
}

func TestSpareCgroupPoolClaim(t *testing.T) {
	p := newTestSparePool(t, 2)
	for i := 0; i < 2; i++ {
		name, err := p.createSpare()
		if err != nil {
			t.Fatal(err)
		}
		p.free <- name
	}

	f, ok := p.claim("11111111-1111-1111-1111-111111111111")
	if !ok || f == nil {
		t.Fatal("claim from a filled pool must succeed")
	}
	f.Close()
	vmDir := filepath.Join(p.tree.vms, "11111111-1111-1111-1111-111111111111")
	if _, err := os.Stat(vmDir); err != nil {
		t.Fatalf("claimed dir missing: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(vmDir, "memory.oom.group")); err != nil || string(b) != "1" {
		t.Fatalf("oom.group = %q, %v; want \"1\"", b, err)
	}
	if _, err := os.Stat(filepath.Join(p.tree.vms, "spare-0")); !os.IsNotExist(err) {
		t.Fatal("claimed spare must be gone from its old name")
	}

	if _, ok := p.claim("22222222-2222-2222-2222-222222222222"); !ok {
		t.Fatal("second claim must succeed")
	}
	if _, ok := p.claim("33333333-3333-3333-3333-333333333333"); ok {
		t.Fatal("claim from an empty pool must report false (inline fallback)")
	}
	// A reserved or invalid vmID must never claim.
	if _, ok := p.claim("spare-7"); ok {
		t.Fatal("reserved name must not claim a cgroup")
	}
}

func TestSpareCgroupPoolClaimDropsVanishedSpare(t *testing.T) {
	p := newTestSparePool(t, 2)
	p.free <- "spare-404" // in the pool, but no dir behind it

	if _, ok := p.claim("11111111-1111-1111-1111-111111111111"); ok {
		t.Fatal("claim of a vanished spare must fall back")
	}
	// The dead name must NOT return to the pool — a second claim would
	// otherwise pop it again forever.
	select {
	case name := <-p.free:
		t.Fatalf("dead spare %q re-queued", name)
	default:
	}
}

func TestSpareCgroupPoolClaimTargetCollisionKeepsSpare(t *testing.T) {
	p := newTestSparePool(t, 2)
	name, err := p.createSpare()
	if err != nil {
		t.Fatal(err)
	}
	p.free <- name
	// The vmID already has a NON-EMPTY dir (rename onto it fails): the launch
	// preamble handles that case inline, and the intact spare must survive
	// for the next claim.
	vmID := "11111111-1111-1111-1111-111111111111"
	if err := os.MkdirAll(filepath.Join(p.tree.vms, vmID, "occupied"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, ok := p.claim(vmID); ok {
		t.Fatal("claim onto an existing occupied dir must fall back")
	}
	select {
	case back := <-p.free:
		if back != name {
			t.Fatalf("pool returned %q, want the intact spare %q", back, name)
		}
	default:
		t.Fatal("intact spare must be returned to the pool")
	}
}

func TestSpareCgroupPoolAdoptExisting(t *testing.T) {
	p := newTestSparePool(t, 2)
	for _, d := range []string{"spare-3", "spare-7", "spare-bogus", "keeper"} {
		if err := os.Mkdir(filepath.Join(p.tree.vms, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if adopted := p.adoptExisting(); adopted != 2 {
		t.Fatalf("adopted = %d, want 2", adopted)
	}
	if _, err := os.Stat(filepath.Join(p.tree.vms, "spare-bogus")); !os.IsNotExist(err) {
		t.Fatal("unparsable spare must be removed")
	}
	if _, err := os.Stat(filepath.Join(p.tree.vms, "keeper")); err != nil {
		t.Fatal("keeper must never be touched")
	}
	// The counter resumes past the highest adopted index so a new spare
	// can't collide with an adopted one.
	name, err := p.createSpare()
	if err != nil {
		t.Fatal(err)
	}
	if name != "spare-8" {
		t.Fatalf("next spare = %q, want spare-8", name)
	}
}

func TestSpareCgroupPoolAdoptReapsExcess(t *testing.T) {
	p := newTestSparePool(t, 1)
	for _, d := range []string{"spare-1", "spare-2"} {
		if err := os.Mkdir(filepath.Join(p.tree.vms, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if adopted := p.adoptExisting(); adopted != 1 {
		t.Fatalf("adopted = %d, want 1 (target)", adopted)
	}
	left := 0
	entries, _ := os.ReadDir(p.tree.vms)
	for _, e := range entries {
		left++
		_ = e
	}
	if left != 1 {
		t.Fatalf("dirs left = %d, want 1 (excess spare reaped)", left)
	}
}

func TestReapSpareCgroups(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"spare-1", "spare-2", "keeper", "vm-uuid-1"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	reapSpareCgroups(dir, zerolog.Nop())
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if len(names) != 2 {
		t.Fatalf("left %v, want only keeper and the VM dir", names)
	}
}

// The host-resident guard must never read a spare as live-VM evidence — a
// disarmed host with leftover spares would otherwise be unable to roll back.
func TestRollbackGuardIgnoresSpares(t *testing.T) {
	w := newGuardWorld(t)
	w.systemctl(0, "/scope")
	w.mkdir("cgfs/scope/keeper")
	w.mkdir("cgfs/scope/spare-12")
	if rc := w.run(oldBinary); rc != 0 {
		t.Fatalf("rc=%d, want allow — spares are not VM evidence", rc)
	}
	// And a real VM dir alongside them still blocks.
	w.mkdir("cgfs/scope/vm-1")
	if rc := w.run(oldBinary); rc == 0 {
		t.Fatal("a live VM cgroup must still block")
	}
}
