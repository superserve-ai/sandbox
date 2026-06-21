package main

import (
	"errors"
	"testing"
)

func TestMountStateDiskAt(t *testing.T) {
	present := func(string) error { return nil }
	absent := func(string) error { return errors.New("no such device") }
	unmounted := func(string) (bool, error) { return false, nil }
	mounted := func(string) (bool, error) { return true, nil }

	t.Run("no device → skip, never mounts", func(t *testing.T) {
		called := false
		err := mountStateDiskAt("/dev/vdb", t.TempDir(), absent, unmounted,
			func(string, string, string, uintptr, string) error { called = true; return nil })
		if err != errNoStateDevice {
			t.Fatalf("want errNoStateDevice, got %v", err)
		}
		if called {
			t.Fatal("must not mount when no device is present")
		}
	})

	t.Run("already mounted → skip, never mounts", func(t *testing.T) {
		called := false
		err := mountStateDiskAt("/dev/vdb", t.TempDir(), present, mounted,
			func(string, string, string, uintptr, string) error { called = true; return nil })
		if err != errStateAlreadyMounted {
			t.Fatalf("want errStateAlreadyMounted, got %v", err)
		}
		if called {
			t.Fatal("must not re-mount an already-mounted /state (restore)")
		}
	})

	t.Run("present + unmounted → mounts with the device, ext4, nosuid/nodev", func(t *testing.T) {
		var gotSrc, gotTarget, gotFS string
		var gotFlags uintptr
		err := mountStateDiskAt("/dev/vdb", t.TempDir(), present, unmounted,
			func(src, target, fs string, flags uintptr, _ string) error {
				gotSrc, gotTarget, gotFS, gotFlags = src, target, fs, flags
				return nil
			})
		if err != nil {
			t.Fatalf("expected a successful mount, got %v", err)
		}
		if gotSrc != "/dev/vdb" || gotFS != "ext4" {
			t.Fatalf("mounted %s as %s, want /dev/vdb ext4", gotSrc, gotFS)
		}
		if gotTarget == "" {
			t.Fatal("mount target should be the mountpoint")
		}
		// MS_NOSUID and MS_NODEV must both be set on the durable data disk.
		const wantBits = 0x2 | 0x4 // MS_NOSUID | MS_NODEV
		if gotFlags&wantBits != wantBits {
			t.Fatalf("mount flags %#x missing nosuid/nodev", gotFlags)
		}
	})

	t.Run("mount error propagates", func(t *testing.T) {
		boom := errors.New("mount: wrong fs type")
		err := mountStateDiskAt("/dev/vdb", t.TempDir(), present, unmounted,
			func(string, string, string, uintptr, string) error { return boom })
		if !errors.Is(err, boom) {
			t.Fatalf("want the mount error, got %v", err)
		}
	})
}
