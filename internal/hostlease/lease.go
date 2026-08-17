// Package hostlease provides the single-writer ownership lease that guards
// mutation of host state — the BoltDB store, the backup journal, the network
// slot allocator, and the reconciler — so that at most one process ever owns
// the writer role on a host.
//
// The lease is an exclusive advisory flock held for the LIFETIME of the owning
// process: it is dropped only when the process exits and the kernel releases
// the lock. There is deliberately no "unlock but keep running" path — a process
// that gives up ownership must exit, so a stray goroutine or a writable file
// descriptor can never mutate host state after the next process acquires the
// lease. BoltDB's own file lock is only a secondary fence: it does not protect
// network namespaces, cgroups, nftables, or the slot allocator, which this
// lease does.
package hostlease

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// ErrHeld is returned by Acquire when another process already owns the lease.
var ErrHeld = errors.New("host writer lease held by another process")

// WriterLease is an exclusive, process-lifetime hold on the host writer role.
type WriterLease struct {
	f    *os.File
	path string
}

// Capability is proof that its holder owns the host writer role. Code that
// mutates host state requires one, so mutating without the lease is not
// representable. It is non-copyable — go vet's copylocks check flags any copy —
// because write ownership is unique and must not be duplicated or outlive its
// lease.
type Capability struct {
	noCopy noCopy
	lease  *WriterLease
}

// Acquire opens (creating if absent, mode 0600) the lockfile at path and takes
// an exclusive, non-blocking flock. Returns ErrHeld if another process
// currently owns the lease, so the caller — not this primitive — owns the
// retry/timeout policy.
//
// The lockfile is never renamed or replaced; only its flock state matters. The
// fd is close-on-exec (Go opens all descriptors O_CLOEXEC), so a fork+exec'd
// subprocess such as a builder releases its copy on exec and cannot keep the
// lock alive past this process.
func Acquire(path string) (*WriterLease, *Capability, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open lockfile %s: %w", path, err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, nil, ErrHeld
		}
		return nil, nil, fmt.Errorf("flock %s: %w", path, err)
	}
	l := &WriterLease{f: f, path: path}
	return l, &Capability{lease: l}, nil
}

// Path returns the lockfile path.
func (l *WriterLease) Path() string { return l.path }

// Owns reports whether cap is the capability minted by this lease. A defensive
// check for code paths that accept a Capability and want to confirm it belongs
// to the lease they hold.
func (l *WriterLease) Owns(cap *Capability) bool {
	return cap != nil && cap.lease == l
}

// Close drops the lease by closing the fd; the kernel releases the flock.
//
// This exists for process teardown and tests only. The handoff design never
// releases the lease to then keep running as a non-writer — a process that
// yields ownership EXITS — so do not call Close and then continue mutating host
// state.
func (l *WriterLease) Close() error {
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}

// noCopy triggers `go vet -copylocks` on any value copy of a struct that
// embeds it. It has no runtime effect.
type noCopy struct{}

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}
