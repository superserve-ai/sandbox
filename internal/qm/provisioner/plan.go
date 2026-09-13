package provisioner

import "context"

// Mode selects which plan a run executes.
type Mode string

const (
	ModeProvision   Mode = "provision"
	ModeDeprovision Mode = "deprovision"
)

// ParseMode accepts the wire form used by the Cloud Run Job arguments.
func ParseMode(s string) (Mode, bool) {
	switch Mode(s) {
	case ModeProvision, ModeDeprovision:
		return Mode(s), true
	}
	return "", false
}

// Plan is an ordered list of steps for one mode.
type Plan struct {
	Mode  Mode
	Steps []Step
}

// ProvisionPlan runs steps in the given order.
func ProvisionPlan(steps []Step) Plan {
	return Plan{Mode: ModeProvision, Steps: append([]Step(nil), steps...)}
}

// DeprovisionPlan is the provision order reversed, each step running its
// Rollback, so teardown is expressed once per step rather than twice.
func DeprovisionPlan(steps []Step) Plan {
	out := make([]Step, 0, len(steps))
	for i := len(steps) - 1; i >= 0; i-- {
		out = append(out, rollbackStep{inner: steps[i]})
	}
	return Plan{Mode: ModeDeprovision, Steps: out}
}

// rollbackStep presents a step's Rollback as its Run so the runner treats
// provision and deprovision plans identically.
type rollbackStep struct {
	inner Step
}

func (s rollbackStep) Name() string                                  { return s.inner.Name() }
func (s rollbackStep) Run(ctx context.Context, t *Tenant) error      { return s.inner.Rollback(ctx, t) }
func (s rollbackStep) Rollback(ctx context.Context, t *Tenant) error { return s.inner.Run(ctx, t) }
