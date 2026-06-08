package network

import "testing"

// Tests here cover the pure-functional bits of mountns.go (paths, link
// list, error guards). Tests that actually mount, unshare, or nsenter
// require root on Linux and live in integration tests (mountns_integ_test.go).

func TestSandboxLinkNames_StableSet(t *testing.T) {
	// CleanupVM unbinds the set unconditionally. Adding a new link layout
	// means updating this list; this test enforces the contract.
	want := []string{"base.ext4", "overlay.ext4", "rootfs.ext4"}
	if len(sandboxLinkNames) != len(want) {
		t.Fatalf("sandboxLinkNames len=%d, want %d", len(sandboxLinkNames), len(want))
	}
	for i, n := range want {
		if sandboxLinkNames[i] != n {
			t.Errorf("sandboxLinkNames[%d] = %q, want %q", i, sandboxLinkNames[i], n)
		}
	}
}

func TestPrepareSlotMountNamespace_RequiresMountPoint(t *testing.T) {
	if _, err := prepareSlotMountNamespace(nil, 0, ""); err == nil {
		t.Fatal("expected error when tmpfsMountPoint is empty")
	}
}

func TestBindSandboxIntoSlot_RequiresBindPath(t *testing.T) {
	err := BindSandboxIntoSlot(nil, "", "/tmp", [][2]string{{"/src", "name"}})
	if err == nil {
		t.Fatal("expected error when bindPath is empty")
	}
}

func TestBindSandboxIntoSlot_RejectsEmptyLinkFields(t *testing.T) {
	cases := []struct {
		name  string
		links [][2]string
	}{
		{"empty target", [][2]string{{"", "name"}}},
		{"empty name", [][2]string{{"/src", ""}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := BindSandboxIntoSlot(nil, "/run/sandbox/ns/mnt-0", "/tmp", tc.links)
			if err == nil {
				t.Fatal("expected error for malformed link")
			}
		})
	}
}

func TestReleaseSlotMountNamespace_NilSafe(t *testing.T) {
	if err := releaseSlotMountNamespace(nil, nil); err != nil {
		t.Errorf("releaseSlotMountNamespace(nil) = %v, want nil", err)
	}
}

func TestUnbindSandboxFromSlot_EmptyBindPathIsNoOp(t *testing.T) {
	// Should not panic, should not call out to nsenter.
	UnbindSandboxFromSlot(nil, "", "/tmp", []string{"x.ext4"})
}
