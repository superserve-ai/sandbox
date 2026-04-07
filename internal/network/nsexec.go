package network

import (
	"fmt"
	"runtime"

	"github.com/vishvananda/netns"
)

// nsExecGo runs fn inside the given network namespace using vishvananda/netns.
//
// This is required for nftables operations because the Go nftables library
// creates netlink sockets that are bound to the current thread's namespace —
// so the Firewall constructor must run while the thread is in the sandbox's
// namespace.
//
// The function is run in a dedicated goroutine pinned to a single OS thread.
// On success, the goroutine restores the host namespace and exits normally,
// which releases the thread back to the pool in a clean state.
//
// On restore-failure, the goroutine exits WITHOUT calling UnlockOSThread.
// Go's runtime contract in that case: "If the calling goroutine exits without
// unlocking the thread, the thread will be terminated." Terminating a tainted
// thread is safer than returning it to the pool pointing at the sandbox's
// namespace, where a future goroutine could unknowingly run inside it.
func nsExecGo(nsName string, fn func() error) error {
	errCh := make(chan error, 1)

	go func() {
		runtime.LockOSThread()

		hostNS, err := netns.Get()
		if err != nil {
			runtime.UnlockOSThread()
			errCh <- fmt.Errorf("get current netns: %w", err)
			return
		}
		defer hostNS.Close()

		targetNS, err := netns.GetFromName(nsName)
		if err != nil {
			runtime.UnlockOSThread()
			errCh <- fmt.Errorf("get netns %q: %w", nsName, err)
			return
		}
		defer targetNS.Close()

		if err := netns.Set(targetNS); err != nil {
			// We never moved away from the host namespace, so it is
			// still safe to release the thread.
			runtime.UnlockOSThread()
			errCh <- fmt.Errorf("set netns to %q: %w", nsName, err)
			return
		}

		fnErr := fn()

		// Attempt to restore the host namespace.
		if err := netns.Set(hostNS); err != nil {
			// CRITICAL: the thread is still inside the sandbox's
			// namespace. Do NOT call UnlockOSThread — returning
			// from the goroutine with the thread still locked
			// causes Go to terminate the thread, which is safe.
			// Releasing it back to the pool would taint future
			// goroutines that happen to be scheduled on it.
			errCh <- fmt.Errorf("restore host netns: %w (fn error: %v)", err, fnErr)
			return
		}

		runtime.UnlockOSThread()
		errCh <- fnErr
	}()

	return <-errCh
}
