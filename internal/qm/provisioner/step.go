// Package provisioner runs the ordered plan that turns a qm.tenants row
// into a live QM stack, and the reverse plan that tears one down. It owns
// the run bookkeeping (events, status, per-tenant exclusivity); the steps
// that touch GCP live in the steps subpackage behind narrow interfaces.
package provisioner

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Step is one unit of a plan. Run and Rollback must both be idempotent: a
// re-run after a crash calls every step again, so each checks for the
// resource it owns before creating (or deleting) it. Run may return Skip to
// have the runner record the step as skipped rather than ok.
type Step interface {
	// Name is the step's stable identifier, recorded in qm.tenant_events.
	Name() string
	Run(ctx context.Context, t *Tenant) error
	Rollback(ctx context.Context, t *Tenant) error
}

// ReadyChecker is an optional Step interface: a step that cannot run in the
// current environment says so here rather than at Run time.
type ReadyChecker interface {
	Ready(env Env) error
}

// PlanReady reports every step that cannot run in env. Binaries call it
// once at startup and refuse to serve when it fails: a run that would stop
// at an unimplemented step must never be accepted, because by then the
// tenant already has a model key in Secret Manager and a half-built stack
// behind it.
func PlanReady(steps []Step, env Env) error {
	var notReady []string
	for _, s := range steps {
		rc, ok := s.(ReadyChecker)
		if !ok {
			continue
		}
		if err := rc.Ready(env); err != nil {
			notReady = append(notReady, s.Name()+": "+err.Error())
		}
	}
	if len(notReady) == 0 {
		return nil
	}
	return fmt.Errorf("provisioning plan cannot run (%s)", strings.Join(notReady, "; "))
}

// NotImplementedError is returned by a step whose real implementation has
// not landed yet when the runner is not in stub mode. It is a typed error
// so callers can tell "engine works, step missing" from a step failure.
type NotImplementedError struct {
	Step string
}

func (e *NotImplementedError) Error() string {
	return fmt.Sprintf("step %s is not implemented (set QM_PROVISIONER_STUB=1 to stub it)", e.Step)
}

// ErrNotImplemented matches any NotImplementedError via errors.Is.
var ErrNotImplemented = &NotImplementedError{}

func (e *NotImplementedError) Is(target error) bool {
	_, ok := target.(*NotImplementedError)
	return ok
}

// NotImplemented builds the typed error for step.
func NotImplemented(step string) error {
	return &NotImplementedError{Step: step}
}

// SkipError tells the runner a step had nothing to do (its resource already
// exists, or it does not apply to this tenant). Recorded as skipped.
type SkipError struct {
	Reason string
}

func (e *SkipError) Error() string { return "skipped: " + e.Reason }

// Skip returns a SkipError with reason.
func Skip(reason string) error {
	return &SkipError{Reason: reason}
}

// ErrTenantDeleted is returned when a run is asked to operate on a tenant
// that has already been retired.
var ErrTenantDeleted = errors.New("tenant is deleted")

// ErrStaleRun is returned when a run starts for a mode the tenant is no
// longer queued for; the run does nothing.
var ErrStaleRun = errors.New("stale run")
