package main

import (
	"log"
	"os"
	"path/filepath"
	"syscall"
)

// The durable /state contract (SPEC §3, §9.1): an Actor's state lives on a
// dedicated block device that the platform (vmd) attaches as the VM's second
// drive and that survives crash, hibernation, and host migration — addressed by
// a stable durable identity, not by VM instance. boxd's job on boot is simply to
// mount it; the device is pre-formatted (ext4) once when the durable identity is
// created, so boxd NEVER mkfs's a disk that may already hold state.
const (
	stateMountpoint    = "/state"
	defaultStateDevice = "/dev/vdb" // second drive (vda is the rootfs)
	stateFSType        = "ext4"
)

// mountStateDisk mounts the durable /state block device at /state. No-op when no
// state device is attached (a sandbox booted without durable state) or when
// /state is already mounted (snapshot restore carries the mount in the restored
// namespace). Failures are logged, not fatal: a sandbox without /state is still
// usable for ephemeral work, and turning a missing/unmountable disk into a boot
// failure would be a worse outcome than a clear log line.
func mountStateDisk() {
	device := os.Getenv("STATE_DEVICE")
	if device == "" {
		device = defaultStateDevice
	}
	switch err := mountStateDiskAt(device, stateMountpoint, osStat, isMountpoint, syscall.Mount); err {
	case errNoStateDevice:
		// No durable state attached to this sandbox; nothing to do.
	case errStateAlreadyMounted:
		log.Printf("state: %s already mounted (restore)", stateMountpoint)
	case nil:
		log.Printf("state: mounted %s at %s (durable)", device, stateMountpoint)
	default:
		log.Printf("state: mount %s at %s failed: %v", device, stateMountpoint, err)
	}
}

// Sentinel outcomes that are not errors the caller should surface.
var (
	errNoStateDevice       = sentinel("no state device")
	errStateAlreadyMounted = sentinel("state already mounted")
)

type sentinel string

func (s sentinel) Error() string { return string(s) }

// mountFunc matches syscall.Mount so the real mount can be swapped for a fake in
// tests (cmd/boxd is linux-only, but the decision logic stays exercisable).
type mountFunc func(source, target, fstype string, flags uintptr, data string) error

// mountStateDiskAt is the testable core: decide whether to mount, then mount.
// Returns errNoStateDevice / errStateAlreadyMounted for the skip cases, nil on a
// successful mount, or the mount error.
func mountStateDiskAt(
	device, mountpoint string,
	statFn func(string) error,
	mountedFn func(string) (bool, error),
	doMount mountFunc,
) error {
	if statFn(device) != nil {
		return errNoStateDevice
	}
	if mounted, _ := mountedFn(mountpoint); mounted {
		return errStateAlreadyMounted
	}
	if err := os.MkdirAll(mountpoint, 0o755); err != nil {
		return err
	}
	// MS_NOSUID|MS_NODEV: /state holds an agent's data, never trusted executables
	// or device nodes, so deny both to keep the durable disk from being a vector.
	return doMount(device, mountpoint, stateFSType, syscall.MS_NOSUID|syscall.MS_NODEV, "")
}

func osStat(path string) error {
	_, err := os.Stat(path)
	return err
}

// isMountpoint reports whether path is a mount point by comparing its device id
// to its parent's: a mounted filesystem has a different st_dev than the directory
// it is mounted onto. Dependency-free (no /proc/mounts parse).
func isMountpoint(path string) (bool, error) {
	var st, parent syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return false, err
	}
	if err := syscall.Stat(filepath.Dir(path), &parent); err != nil {
		return false, err
	}
	return st.Dev != parent.Dev, nil
}
