// Package handoff is the host-local controller that orchestrates a blue-green
// vmd generation cutover. It lives in the stable gateway process (not the
// deployment script), so a deploy that loses its connection midway does not
// abandon a half-finished handoff: the controller owns the sequence, serializes
// deploys, and makes each command idempotent and compare-and-swap guarded.
//
// The side effects — starting a generation, draining one, switching the gateway
// — are injected through Actions so the sequence is testable without systemd or
// real processes.
package handoff

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// Generation identifies one vmd generation: an opaque id and its two private
// sockets (control-plane gRPC and resolver HTTP), which the gateway routes to.
type Generation struct {
	ID             string
	GRPCSocket     string
	ResolverSocket string
}

// Actions are the effects the controller drives, in the order the handoff
// requires them. Real implementations talk to systemd, the generation's drain
// RPC, and the gateway.
type Actions interface {
	// StartStandby starts the next generation in mutation-free preflight.
	StartStandby(ctx context.Context, next Generation) error
	// AwaitReady blocks until the next generation reports ready-to-activate.
	AwaitReady(ctx context.Context, next Generation) error
	// Quiesce turns the gateway admission hold on or off.
	Quiesce(on bool)
	// DrainAndStop drains the previous generation and waits for it to exit,
	// which releases the writer lease. A no-op prev (empty id) is never passed.
	DrainAndStop(ctx context.Context, prev Generation) error
	// Activate tells the next generation to acquire the lease, construct its
	// active runtime, revalidate authoritative host state, and become ready.
	Activate(ctx context.Context, next Generation) error
	// SetActive atomically points the gateway at the generation.
	SetActive(gen Generation)
	// Stabilize watches the newly active generation for a settling period and
	// errors if it does not stay healthy.
	Stabilize(ctx context.Context, gen Generation) error
	// Rollback restores the previous lease-aware generation as a fresh process
	// and points the gateway back at it. Used when the new generation fails to
	// come up; the old one has already exited by then.
	Rollback(ctx context.Context, prev Generation) error
}

var (
	// ErrDeployInProgress is returned when a deploy is already running.
	ErrDeployInProgress = errors.New("handoff: a deploy is already in progress")
	// ErrCASMismatch is returned when expectedCurrent does not match the live
	// active generation — a stale or concurrent deploy.
	ErrCASMismatch = errors.New("handoff: current generation does not match expected")
)

// Controller serializes and orchestrates generation cutovers on one host.
type Controller struct {
	act Actions

	mu        sync.Mutex
	deploying bool
	current   Generation
}

// New returns a Controller whose live generation is `current` (empty on first
// bringup).
func New(act Actions, current Generation) *Controller {
	return &Controller{act: act, current: current}
}

// Current returns the live active generation.
func (c *Controller) Current() Generation {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.current
}

// Deploy performs one cutover from expectedCurrent to next. It is:
//   - serialized: a second concurrent Deploy returns ErrDeployInProgress;
//   - idempotent: if next is already live, it returns nil without acting;
//   - CAS-guarded: if the live generation is not expectedCurrent, it returns
//     ErrCASMismatch and does nothing.
//
// On any failure to bring up next, it rolls back to the previous generation and
// returns the error; the previous generation stays live.
func (c *Controller) Deploy(ctx context.Context, expectedCurrent, next Generation) error {
	c.mu.Lock()
	if c.deploying {
		c.mu.Unlock()
		return ErrDeployInProgress
	}
	if c.current.ID == next.ID {
		c.mu.Unlock()
		return nil // already live; idempotent
	}
	if c.current.ID != expectedCurrent.ID {
		c.mu.Unlock()
		return ErrCASMismatch
	}
	prev := c.current
	c.deploying = true
	c.mu.Unlock()

	err := c.run(ctx, prev, next)

	c.mu.Lock()
	c.deploying = false
	c.mu.Unlock()
	return err
}

func (c *Controller) run(ctx context.Context, prev, next Generation) error {
	// 1. Bring the next generation up in mutation-free preflight. The old one
	//    is still serving, so a failure here has zero customer impact.
	if err := c.act.StartStandby(ctx, next); err != nil {
		return fmt.Errorf("start standby %s: %w", next.ID, err)
	}
	if err := c.act.AwaitReady(ctx, next); err != nil {
		return fmt.Errorf("await ready %s: %w", next.ID, err)
	}

	// 2. Gateway begins the bounded admission hold.
	c.act.Quiesce(true)

	// 3. Old generation drains and exits, releasing the writer lease. Skipped
	//    on first bringup (no prev).
	if prev.ID != "" {
		if err := c.act.DrainAndStop(ctx, prev); err != nil {
			c.act.Quiesce(false)
			return fmt.Errorf("drain %s: %w", prev.ID, err)
		}
	}

	// 4. New generation acquires the lease, builds its active runtime,
	//    revalidates host state, and becomes ready. On failure, roll back.
	if err := c.act.Activate(ctx, next); err != nil {
		c.rollback(ctx, prev)
		c.act.Quiesce(false) // resume onto the rolled-back generation
		return fmt.Errorf("activate %s: %w", next.ID, err)
	}

	// 5. Gateway atomically switches and releases the held requests.
	c.act.SetActive(next)
	c.act.Quiesce(false)

	c.mu.Lock()
	c.current = next
	c.mu.Unlock()

	// 6. Watch the new generation settle; a post-cutover failure rolls back.
	if err := c.act.Stabilize(ctx, next); err != nil {
		c.act.Quiesce(true)
		c.rollback(ctx, prev)
		c.act.Quiesce(false)
		return fmt.Errorf("stabilize %s: %w", next.ID, err)
	}
	return nil
}

// rollback restores the previous generation and repoints the gateway. Best
// effort: the previous generation has already exited, so this restarts it.
func (c *Controller) rollback(ctx context.Context, prev Generation) {
	if prev.ID == "" {
		return
	}
	if err := c.act.Rollback(ctx, prev); err == nil {
		c.act.SetActive(prev)
		c.mu.Lock()
		c.current = prev
		c.mu.Unlock()
	}
}
