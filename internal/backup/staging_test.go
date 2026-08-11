package backup

import "testing"

// The staging tree defaults onto the snapshot filesystem, and the
// retired OS-disk default is reported for removal unless it is the
// configured root itself.
func TestResolveStagingRoot(t *testing.T) {
	root, legacy := ResolveStagingRoot("", "/data/snapshots", "/var/lib/sandbox/rundir")
	if root != "/data/snapshots/.backup-staging" || legacy != "/var/lib/sandbox/backup-staging" {
		t.Fatalf("default = %q legacy %q", root, legacy)
	}
	root, legacy = ResolveStagingRoot("/elsewhere/staging", "/data/snapshots", "/var/lib/sandbox/rundir")
	if root != "/elsewhere/staging" || legacy != "/var/lib/sandbox/backup-staging" {
		t.Fatalf("override = %q legacy %q", root, legacy)
	}
	root, legacy = ResolveStagingRoot("/var/lib/sandbox/backup-staging", "/data/snapshots", "/var/lib/sandbox/rundir")
	if legacy != "" {
		t.Fatalf("legacy = %q, want suppressed when it is the configured root", legacy)
	}
}
