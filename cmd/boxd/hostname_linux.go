//go:build linux

package main

import (
	"fmt"
	"log"
	"os"
	"syscall"
	"time"
)

// slowHostnameThreshold flags hostname operations that should be
// near-instant but can stall right after a snapshot restore (e.g. the
// guest's first disk write). The split timings tell the two apart.
const slowHostnameThreshold = 500 * time.Millisecond

// setHostname sets the kernel hostname and writes /etc/hostname.
func setHostname(name string) error {
	t0 := time.Now()
	if err := syscall.Sethostname([]byte(name)); err != nil {
		return fmt.Errorf("sethostname: %w", err)
	}
	sysDur := time.Since(t0)
	t1 := time.Now()
	if err := os.WriteFile("/etc/hostname", []byte(name+"\n"), 0o644); err != nil {
		return fmt.Errorf("write /etc/hostname: %w", err)
	}
	if writeDur := time.Since(t1); sysDur > slowHostnameThreshold || writeDur > slowHostnameThreshold {
		log.Printf("init: slow hostname set: sethostname=%s write_etc_hostname=%s", sysDur, writeDur)
	}
	return nil
}
