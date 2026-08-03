package vm

import (
	"os"
	"path/filepath"
	"testing"
)

// The destroy path frees a VM's tap only when cgroupStillLive says the group is
// gone — the record's supervision mode can be stale, so a live cgroup must block
// destroy regardless of it. No subtree (plain unit host) never blocks; a
// populated OR unreadable group blocks; an empty or missing group does not.
func TestCgroupStillLive(t *testing.T) {
	if (&Manager{}).cgroupStillLive("vm-1") {
		t.Fatal("no cgroup subtree must read as not-live (a unit VM must not block its own destroy)")
	}

	vms := t.TempDir()
	m := &Manager{cgroups: &cgroupTree{vms: vms}}

	if m.cgroupStillLive("gone") {
		t.Fatal("a missing per-VM group must read as not-live")
	}

	write := func(id, body string) {
		dir := filepath.Join(vms, id)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cgroup.events"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("live", "populated 1\nfrozen 0\n")
	if !m.cgroupStillLive("live") {
		t.Fatal("a populated group must block destroy (still live)")
	}
	write("empty", "populated 0\nfrozen 0\n")
	if m.cgroupStillLive("empty") {
		t.Fatal("an empty group must not block destroy")
	}
}

// cgroupLaunch decides direct vs unit for a launch. A record already in
// cgroup mode always relaunches cgroup (so a flag-off rollback drains rather
// than converts); a fresh/unit record takes cgroup only when armed.
func TestCgroupLaunchDecision(t *testing.T) {
	cases := []struct {
		name     string
		existing Supervision
		armed    bool
		want     bool
	}{
		{"fresh unarmed", SupervisionUnit, false, false},
		{"fresh armed", SupervisionUnit, true, true},
		{"cgroup record unarmed still cgroup", SupervisionCgroup, false, true},
		{"cgroup record armed", SupervisionCgroup, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := &Manager{}
			m.directSpawnArmed.Store(c.armed)
			if got := m.cgroupLaunch(c.existing); got != c.want {
				t.Fatalf("cgroupLaunch(%q, armed=%v) = %v, want %v", c.existing, c.armed, got, c.want)
			}
		})
	}
}

// vmDefinitelyDead must never call a VM dead on an inconclusive answer, in
// either mode — an unarmed manager can't read cgroup state, and that reads
// as alive, not dead.
func TestVmDefinitelyDeadInconclusiveIsAlive(t *testing.T) {
	m := &Manager{} // cgroups nil = cannot prove death
	if m.vmDefinitelyDead(t.Context(), "vm-1", SupervisionCgroup) {
		t.Fatal("cgroup VM with no subtree must read as alive, not dead")
	}
}

// Only a cgroup-supervised instance claims a per-VM dir; a unit-mode instance
// over an empty leftover group must stay reap-eligible (see the empty-cgroup
// reaper in runOnce).
func TestInstanceClaimsCgroup(t *testing.T) {
	m := &Manager{vms: map[string]*VMInstance{
		"cgvm":   {Supervision: SupervisionCgroup},
		"unitvm": {Supervision: SupervisionUnit},
	}}
	if !m.instanceClaimsCgroup("cgvm") {
		t.Fatal("a cgroup-supervised instance must claim its dir (protected from reap)")
	}
	if m.instanceClaimsCgroup("unitvm") {
		t.Fatal("a unit-mode instance must NOT claim a cgroup dir (leftover stays reap-eligible)")
	}
	if m.instanceClaimsCgroup("absent") {
		t.Fatal("no tracked instance must read as no claim")
	}
}
