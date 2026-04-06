package network

import (
	"fmt"
	"runtime"

	"github.com/vishvananda/netns"
)

const netNamespacesDir = "/var/run/netns"

// nsExecGo runs fn inside the given network namespace using vishvananda/netns.
// The current OS thread is locked and the original namespace is restored afterward.
//
// This is required for nftables operations because the Go nftables library
// creates netlink sockets that are bound to the current thread's namespace.
func nsExecGo(nsName string, fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save current (host) namespace.
	hostNS, err := netns.Get()
	if err != nil {
		return fmt.Errorf("get current netns: %w", err)
	}
	defer hostNS.Close()

	// Open target namespace.
	targetNS, err := netns.GetFromName(nsName)
	if err != nil {
		return fmt.Errorf("get netns %q: %w", nsName, err)
	}
	defer targetNS.Close()

	// Switch to target namespace.
	if err := netns.Set(targetNS); err != nil {
		return fmt.Errorf("set netns to %q: %w", nsName, err)
	}

	// Run the function inside the namespace.
	fnErr := fn()

	// Always restore original namespace.
	if err := netns.Set(hostNS); err != nil {
		return fmt.Errorf("restore host netns: %w (fn error: %v)", err, fnErr)
	}

	return fnErr
}
