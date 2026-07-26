package vm

import "testing"

// cgroupLaunch decides direct vs unit for a launch. A record already in
// cgroup mode always relaunches cgroup (so a flag-off rollback drains rather
// than converts); a fresh/unit record takes cgroup only when armed.
func TestCgroupLaunchDecision(t *testing.T) {
	cases := []struct {
		name     string
		existing string
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
