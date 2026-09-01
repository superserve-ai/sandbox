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
	// Aliased and contained spellings must suppress too: treating the
	// configured root's own tree as retired would drain live staging.
	for _, override := range []string{
		"/var/lib/sandbox/backup-staging/",
		"/var/lib/sandbox/backup-staging/sub",
		"/var/lib/sandbox",
	} {
		if _, legacy := ResolveStagingRoot(override, "/data/snapshots", "/var/lib/sandbox/rundir"); legacy != "" {
			t.Fatalf("override %q: legacy = %q, want suppressed", override, legacy)
		}
	}
}

// A BACKUP_STAGING_DIR change between an ancestor and descendant path
// (or the same directory under an aliased spelling) is not a
// retirement: the "old" and "new" roots share a live subtree, and
// treating either as retired would let the background sweep walk
// referenced entries through the other's tree and delete them as
// apparent orphans.
func TestStagingRootsOverlap(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"/mnt/disk/staging", "/mnt/disk/staging", true},
		{"/mnt/disk/staging/", "/mnt/disk/staging", true},
		{"/mnt/disk/staging", "/mnt/disk/staging/sub", true},
		{"/mnt/disk/staging/sub", "/mnt/disk/staging", true},
		{"/mnt/disk/staging", "/mnt/other/staging", false},
		{"/mnt/disk/staging-2", "/mnt/disk/staging", false}, // shares a prefix, not a path component
		{"", "/mnt/disk/staging", false},
		{"/mnt/disk/staging", "", false},
	}
	for _, c := range cases {
		if got := StagingRootsOverlap(c.a, c.b); got != c.want {
			t.Errorf("StagingRootsOverlap(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
