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
	if !strings.Contains(on, "mount -t cgroup -o freezer") {
		t.Error("freezer block missing with the switch on")
	}
	for _, s := range []string{off, on} {
		if !strings.HasPrefix(s, "#!/bin/sh\n") || !strings.Contains(s, "exec /usr/local/bin/tini -- /usr/bin/boxd") {
			t.Error("init script shape broken")
		}
	}
}
