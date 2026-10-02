//go:build !linux

package main

import "golang.org/x/sys/unix"

func flushFilesystems() { _ = unix.Sync() }
