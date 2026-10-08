package network

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/superserve-ai/sandbox/internal/sentrylog"
	"github.com/superserve-ai/sandbox/internal/telemetry"
)

const DefaultEgressMaxConnections = 4096

// EgressCapacity is immutable after Start. Enforcement defaults off for rollout;
// the finite limit is still exported while observing existing traffic.
type EgressCapacity struct {
	MaxConnections int
	Enforce        bool
}

func (c EgressCapacity) Validate() error {
	if c.MaxConnections <= 0 {
		return fmt.Errorf("egress max connections must be positive")
	}
	return nil
}

// ConfigureCapacity must be called before Start.
func (p *EgressProxy) ConfigureCapacity(c EgressCapacity, metrics *telemetry.EgressRecorder) error {
	if err := c.Validate(); err != nil {
		return err
	}
	p.capacity = c
	p.metrics = metrics
	return nil
}

func (p *EgressProxy) acquireHost() bool {
	for {
		n := p.active.Load()
		if p.capacity.Enforce && n >= int64(p.capacity.MaxConnections) {
			return false
		}
		if p.active.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

// dispatch owns the accepted socket. At most one unadmitted socket per accept
// loop exists, in addition to the admitted budget and the kernel listen backlog.
func (p *EgressProxy) dispatch(ctx context.Context, conn net.Conn, handler func(context.Context, net.Conn)) bool {
	if ctx.Err() != nil {
		conn.Close()
		return false
	}
	if !p.acquireHost() {
		conn.Close()
		p.metrics.Reject("host")
		return false
	}
	p.metrics.Connection(1)
	p.workers.Add(1)
	go func() {
		defer p.workers.Done()
		defer sentrylog.Recover("net-conn")
		defer func() { conn.Close(); p.active.Add(-1); p.metrics.Connection(-1) }()
		// Join cancellation before releasing admission: no outstanding callback may
		// outlive its permit, including when shutdown races normal completion.
		stopped := make(chan struct{})
		stop := context.AfterFunc(ctx, func() { conn.Close(); close(stopped) })
		defer func() {
			if !stop() {
				<-stopped
			}
		}()
		handler(ctx, conn)
	}()
	return true
}

// acquireSandbox snapshots policy and accounting under the registration lock.
// Policy edits keep their registration; removal/reassignment retires it.
func (p *EgressProxy) acquireSandbox(ip string) (*EgressRules, *EgressRules, func(), bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	registration := p.rules[ip]
	var rules *EgressRules
	if registration != nil {
		copy := *registration
		rules = &copy
	}
	release, ok := p.limiter.TryAcquire(ip, p.maxConnsPerSandbox)
	return rules, registration, release, ok
}

// closeOnCancel also joins a concurrently running callback before returning.
func closeOnCancel(ctx context.Context, conn net.Conn) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { conn.Close(); close(done) })
	return func() {
		if !stop() {
			<-done
		}
		conn.Close()
	}
}

// Keep these fields separate from registration state: host occupancy survives
// individual sandbox removal and is shared by all three listeners.
type egressConnections struct {
	active  atomic.Int64
	workers sync.WaitGroup
}

func acceptBackoff(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
