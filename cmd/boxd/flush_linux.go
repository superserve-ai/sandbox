//go:build linux

package main

import "golang.org/x/sys/unix"

// flushFilesystems writes every dirty page out, from this process.
func flushFilesystems() { unix.Sync() }
