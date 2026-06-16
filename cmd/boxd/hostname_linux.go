//go:build linux

package main

import (
	"fmt"
	"os"
	"syscall"
)

// setHostname sets the kernel hostname and writes /etc/hostname.
func setHostname(name string) error {
	if err := syscall.Sethostname([]byte(name)); err != nil {
		return fmt.Errorf("sethostname: %w", err)
	}
	if err := os.WriteFile("/etc/hostname", []byte(name+"\n"), 0o644); err != nil {
		return fmt.Errorf("write /etc/hostname: %w", err)
	}
	return nil
}
