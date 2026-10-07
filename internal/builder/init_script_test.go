package builder

import (
	"strings"
	"testing"
)

// The workload freezer cgroup rides only in images built to freeze their workload.
func TestInitScriptFreezerGated(t *testing.T) {
	off, on := initScriptFor(false), initScriptFor(true)
	if strings.Contains(off, "freezer/workload") {
		t.Error("freezer block present with the switch off")
	}
	if !strings.Contains(on, "mkdir -p /sys/fs/cgroup/freezer/workload") || !strings.Contains(on, "export BOXD_WORKLOAD_FREEZER=/sys/fs/cgroup/freezer/workload") {
		t.Error("freezer block or its announcement to boxd missing with the switch on")
	}
	if strings.Contains(off, "BOXD_WORKLOAD_FREEZER") {
		t.Error("freezer announced with the switch off")
	}
	for _, s := range []string{off, on} {
		if !strings.HasPrefix(s, "#!/bin/sh\n") || !strings.Contains(s, "exec /usr/local/bin/tini -- /usr/bin/boxd") {
			t.Error("init script shape broken")
		}
	}
}

// The controller tree container runtimes need, freezer included, rides in every
// image; the workload cgroup is created inside it rather than before it.
func TestInitScriptMountsCgroupControllers(t *testing.T) {
	for _, s := range []string{initScriptFor(false), initScriptFor(true)} {
		if !strings.Contains(s, "for c in cpu cpuacct cpuset memory devices freezer pids blkio") || !strings.Contains(s, "mount -t cgroup -o $c $c /sys/fs/cgroup/$c") {
			t.Error("cgroup v1 controllers not mounted")
		}
	}
	on := initScriptFor(true)
	if strings.Index(on, "mount -t cgroup -o $c $c") > strings.Index(on, "mkdir -p /sys/fs/cgroup/freezer/workload") {
		t.Error("workload cgroup created before the freezer is mounted")
	}
}
