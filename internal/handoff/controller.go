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
	"time"
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
	// QuiesceGRPC turns the control-plane admission hold on or off (held across
	// the whole cutover; the control plane retries Unavailable).
	QuiesceGRPC(on bool)
	// QuiesceResolver turns the resolver admission hold on or off (held only for
	// the brief activation window, since the old generation answers read-only
	// lookups while it drains).
	QuiesceResolver(on bool)
	// Drain asks a generation to stop admitting new mutating RPCs and wait for
	// its in-flight ones to finish, within budget. Returns (true, nil) if fully
	// drained; (false, nil) if the budget elapsed with operations still in
	// flight — the caller must then Undrain and postpone, never force-cut.
	Drain(ctx context.Context, gen Generation, budget time.Duration) (bool, error)
	// Undrain clears a generation's draining state so it resumes serving as the
	// writer — used when a drain is aborted.
	Undrain(ctx context.Context, gen Generation) error
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
	// ErrDeployPostponed is returned when the old generation could not drain its
	// in-flight operations within budget. The deploy is aborted with the old
	// generation still serving — the operation completes; retry when quieter.
	ErrDeployPostponed = errors.New("handoff: deploy postponed — in-flight operations did not drain in budget")
)

const (
	// totalGRPCHold bounds the whole control-plane hold across a cutover, sized
	// under the control plane's Unavailable retry window so held callers still
	// retry onto the new generation successfully.
	totalGRPCHold = 12 * time.Second
	// rollbackReserve is kept at the end of the budget so a late failure can roll
	// back to the old generation without blowing the total.
	rollbackReserve = 3 * time.Second
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

// Deploying reports whether a deploy or recovery is in progress, so a health
// monitor does not mistake a generation intentionally stopped mid-cutover for a
// crash.
func (c *Controller) Deploying() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deploying
}

// Reactivate re-activates a generation that crashed and was auto-restarted into
// preflight — bringing it back to serving as the writer without a full deploy.
// Serialized against deploys by the same single-deploy lock.
func (c *Controller) Reactivate(ctx context.Context, gen Generation) error {
	c.mu.Lock()
	if c.deploying {
		c.mu.Unlock()
		return ErrDeployInProgress
	}
	c.deploying = true
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.deploying = false
		c.mu.Unlock()
	}()

	c.act.QuiesceGRPC(true)
	c.act.QuiesceResolver(true)
	if err := c.act.Activate(ctx, gen); err != nil {
		c.act.QuiesceResolver(false)
		c.act.QuiesceGRPC(false)
		return fmt.Errorf("reactivate %s: %w", gen.ID, err)
	}
	c.act.SetActive(gen)
	c.act.QuiesceResolver(false)
	c.act.QuiesceGRPC(false)
	c.mu.Lock()
	c.current = gen
	c.mu.Unlock()
	return nil
}

// SetCurrent overrides the controller's notion of the live generation. The
// operator-facing set-active escape hatch calls this so a later deploy's
// compare-and-swap and its drain target reflect the generation actually routed
// to, rather than a stale one.
func (c *Controller) SetCurrent(gen Generation) {
	c.mu.Lock()
	c.current = gen
	c.mu.Unlock()
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

	// 2. Hold gRPC BEFORE touching the old generation: new calls are refused
	//    with retryable Unavailable (the control plane retries). The resolver is
	//    NOT held here — it is read-only, so the old generation keeps answering
	//    lookups while it drains. The hold has a hard total budget with time
	//    reserved for rollback, so it never outlasts the caller's retry window.
	c.act.QuiesceGRPC(true)
	rollbackBy := time.Now().Add(totalGRPCHold - rollbackReserve)

	// 3. Abortable drain: ask the old generation to finish its in-flight
	//    operations within budget. If they DON'T drain in time, abort the deploy
	//    — resume the old generation and postpone. The customer operation
	//    completes normally; the deploy loses to availability, never the reverse.
	if prev.ID != "" {
		drained, err := c.act.Drain(ctx, prev, time.Until(rollbackBy))
		if err != nil {
			c.abortDrain(ctx, prev, next)
			return fmt.Errorf("drain %s: %w", prev.ID, err)
		}
		if !drained {
			c.abortDrain(ctx, prev, next)
			return fmt.Errorf("%w: %s", ErrDeployPostponed, prev.ID)
		}
		// Drained: stop the old generation (releasing the writer lease).
		if err := c.act.DrainAndStop(ctx, prev); err != nil {
			c.act.QuiesceGRPC(false)
			_ = c.act.DrainAndStop(ctx, next)
			return fmt.Errorf("stop drained %s: %w", prev.ID, err)
		}
	}

	// 4. Now hold the resolver too — only for the brief activation window.
	c.act.QuiesceResolver(true)

	// 5. New generation acquires the lease and becomes ready, bounded by the
	//    remaining budget before the rollback reserve. On failure, roll back —
	//    and stay fail-closed (holds ON) if the rollback itself fails, rather
	//    than releasing traffic onto a dead upstream.
	actCtx, cancel := context.WithDeadline(ctx, rollbackBy)
	err := c.act.Activate(actCtx, next)
	cancel()
	if err != nil {
		if rbErr := c.rollback(ctx, next, prev); rbErr != nil {
			return fmt.Errorf("activate %s failed; rollback failed, holding traffic: %v; %w", next.ID, rbErr, err)
		}
		c.act.QuiesceResolver(false)
		c.act.QuiesceGRPC(false)
		return fmt.Errorf("activate %s: %w", next.ID, err)
	}

	// 6. Gateway atomically switches and releases the held requests.
	c.act.SetActive(next)
	c.act.QuiesceResolver(false)
	c.act.QuiesceGRPC(false)

	// 7. Watch the new generation settle BEFORE committing it as current, so a
	//    poller sees the deploy land only once it is stably serving.
	if err := c.act.Stabilize(ctx, next); err != nil {
		c.act.QuiesceGRPC(true)
		c.act.QuiesceResolver(true)
		if rbErr := c.rollback(ctx, next, prev); rbErr != nil {
			return fmt.Errorf("stabilize %s failed; rollback failed, holding traffic: %v; %w", next.ID, rbErr, err)
		}
		c.act.QuiesceResolver(false)
		c.act.QuiesceGRPC(false)
		return fmt.Errorf("stabilize %s: %w", next.ID, err)
	}

	c.mu.Lock()
	c.current = next
	c.mu.Unlock()
	return nil
}

// abortDrain undoes an in-progress cutover when the old generation could not
// drain in budget: the old generation resumes as writer (its lease was never
// released), the gateway hold is lifted, and the unused standby is stopped. No
// customer operation is cut.
func (c *Controller) abortDrain(ctx context.Context, prev, next Generation) {
	_ = c.act.Undrain(ctx, prev)
	c.act.QuiesceGRPC(false)
	_ = c.act.DrainAndStop(ctx, next)
}

// rollback recovers to the previous generation and returns an error if it could
// not — the caller then stays fail-closed (traffic held) rather than releasing
// onto a dead upstream. The failed new generation may still hold the writer
// lease, so it is stopped FIRST (releasing the lease) before the previous
// generation is restarted and the gateway repointed at it.
func (c *Controller) rollback(ctx context.Context, next, prev Generation) error {
	if err := c.act.DrainAndStop(ctx, next); err != nil {
		return fmt.Errorf("stop failed generation %s: %w", next.ID, err)
	}
	if prev.ID == "" {
		return errors.New("no previous generation to restore")
	}
	if err := c.act.Rollback(ctx, prev); err != nil {
		return fmt.Errorf("restore %s: %w", prev.ID, err)
	}
	c.act.SetActive(prev)
	c.mu.Lock()
	c.current = prev
	c.mu.Unlock()
	return nil
}
