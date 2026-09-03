package builder

import (
	"strings"
	"testing"
)

// The freezer mount rides only in images built to freeze their workload.
func TestInitScriptFreezerGated(t *testing.T) {
	off, on := initScriptFor(false), initScriptFor(true)
	if strings.Contains(off, "freezer") {
		t.Error("freezer block present with the switch off")
	}
	if !strings.Contains(on, "mount -t cgroup -o freezer") || !strings.Contains(on, "export BOXD_WORKLOAD_FREEZER=/sys/fs/cgroup/freezer/workload") {
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
