// Package vmruntime splits a vmd generation into two structurally distinct
// phases so that owning host state is not merely a runtime flag but a
// constructor precondition.
//
//   - PreflightRuntime validates configuration and binds its private serving
//     socket while owning NO host state: no Manager, no writable DB, no
//     nftables, no cgroup, no network, no background workers. It is safe to run
//     alongside the active generation during a handoff.
//   - ActiveRuntime owns the host writer role. It can only be constructed by
//     Activate, which requires a writer Capability from the host lease — so
//     mutating host state without holding the lease is not representable.
//
// A generation preflights first, then (once the previous generation has exited
// and released the lease) acquires the lease and promotes its PreflightRuntime
// to an ActiveRuntime. Because standby inventory is only advisory — it can
// change while the previous generation is still active — the caller MUST
// revalidate authoritative host state after Activate, before serving writes.
package vmruntime

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/superserve-ai/sandbox/internal/hostlease"
)

// ErrNoCapability is returned by Activate when no writer Capability is
// supplied. Holding a Capability is the sole proof of write ownership; it
// cannot be fabricated, only obtained from hostlease.Acquire.
var ErrNoCapability = errors.New("vmruntime: ActiveRuntime requires a host writer capability")

// Config is the mutation-free input a generation needs before it owns anything:
// where its private serving socket binds and which host files must already
// exist for it to run at all.
type Config struct {
	// SocketPath is this generation's private unix socket. The gateway dials
	// it; it is never a shared public port.
	SocketPath string
	// RequiredFiles must all exist for the generation to be viable (e.g. the
	// firecracker binary, guest kernel, base rootfs). Validated read-only.
	RequiredFiles []string
}

// PreflightRuntime is a generation that has validated its config and bound its
// private socket but owns no host state.
type PreflightRuntime struct {
	cfg Config
	lis net.Listener
}

// Preflight validates cfg without mutating any host state and binds the
// generation's private socket. It never touches the writer lease.
func Preflight(cfg Config) (*PreflightRuntime, error) {
	if cfg.SocketPath == "" {
		return nil, errors.New("vmruntime: SocketPath is required")
	}
	for _, f := range cfg.RequiredFiles {
		if _, err := os.Stat(f); err != nil {
			return nil, fmt.Errorf("vmruntime: required file %s: %w", f, err)
		}
	}
	// The socket path is this generation's own private address, so clearing a
	// stale file left by a crashed predecessor is safe (it is not a shared
	// resource and not the writer lock).
	if err := os.Remove(cfg.SocketPath); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("vmruntime: clear stale socket %s: %w", cfg.SocketPath, err)
	}
	lis, err := net.Listen("unix", cfg.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("vmruntime: bind %s: %w", cfg.SocketPath, err)
	}
	return &PreflightRuntime{cfg: cfg, lis: lis}, nil
}

// Listener is the bound private socket. ActiveRuntime serves on it; a preflight
// that never activates closes it via Close.
func (p *PreflightRuntime) Listener() net.Listener { return p.lis }

// Close releases a preflighted generation that never activated (its socket).
// It does not run ActiveRuntime teardown — a preflight owns nothing else.
func (p *PreflightRuntime) Close() error {
	if p.lis == nil {
		return nil
	}
	err := p.lis.Close()
	p.lis = nil
	return err
}

// ActiveRuntime is a generation that owns the host writer role. Construct it
// only via Activate. Its Close tears down everything it built, in reverse
// order, before ownership is released by process exit.
type ActiveRuntime struct {
	pre *PreflightRuntime
	cap *hostlease.Capability

	mu      sync.Mutex
	closers []namedCloser
	closed  bool
}

type namedCloser struct {
	name  string
	close func() error
}

// Activate promotes a preflighted generation to the active writer. It requires
// a Capability obtained from the host lease; a nil capability is refused with
// ErrNoCapability. The returned ActiveRuntime holds the capability for the rest
// of its life — the generation must exit to release ownership, never hand the
// capability back and keep running.
//
// The caller must revalidate authoritative host state (network reservations,
// reconciliation, cgroup/disk inventory) after Activate returns, because the
// preflight's view is only advisory.
func Activate(pre *PreflightRuntime, cap *hostlease.Capability) (*ActiveRuntime, error) {
	if pre == nil {
		return nil, errors.New("vmruntime: Activate requires a preflighted runtime")
	}
	if cap == nil {
		return nil, ErrNoCapability
	}
	return &ActiveRuntime{pre: pre, cap: cap}, nil
}

// Listener is the private socket inherited from preflight.
func (a *ActiveRuntime) Listener() net.Listener { return a.pre.lis }

// AddCloser registers a teardown step. Steps run in reverse registration order
// on Close — register the writer stores last so they close first. Registering
// after Close runs the closer immediately (teardown is already underway).
func (a *ActiveRuntime) AddCloser(name string, fn func() error) {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		_ = fn()
		return
	}
	a.closers = append(a.closers, namedCloser{name: name, close: fn})
	a.mu.Unlock()
}

// Close destroys the ActiveRuntime completely: it runs every registered closer
// in reverse order, then closes the private socket. It is idempotent and
// returns the first teardown error (after running the rest). Ownership of the
// host writer role is dropped by the subsequent process exit, not by Close.
func (a *ActiveRuntime) Close() error {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil
	}
	a.closed = true
	closers := a.closers
	a.closers = nil
	a.mu.Unlock()

	var firstErr error
	for i := len(closers) - 1; i >= 0; i-- {
		if err := closers[i].close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("close %s: %w", closers[i].name, err)
		}
	}
	if err := a.pre.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}
