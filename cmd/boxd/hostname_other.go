//go:build !linux

package main

import "errors"

// setHostname is a stub for non-Linux platforms. boxd only runs inside a Linux
// microVM in production; this exists so the package builds and its tests run on
// dev machines (e.g. macOS), where syscall.Sethostname is unavailable.
func setHostname(name string) error {
	return errors.New("setHostname is unsupported on this platform")
}
