package provisioner

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/qm/tenantstore"
)

// RunStep is the pseudo-step under which a whole run is recorded, so the
// event log shows where each attempt began and how it ended.
const RunStep = "run"

// bookkeepingTimeout bounds the status and event writes that must land
// even when the run's own context has been cancelled (job SIGTERM, or a
// step that failed by timing out).
const bookkeepingTimeout = 30 * time.Second

// Runner executes a plan against one tenant with exclusive access.
type Runner struct {
	Store tenantstore.Store
	Env   Env
	// Steps in provision order; the deprovision plan is derived from them.
	Steps []Step
	Log   zerolog.Logger
}

// Run executes mode's plan for the tenant and returns the first step error,
// ErrLocked when another run holds the tenant, or ErrTenantDeleted. The
// tenant ends up ready (provision), deleted (deprovision) or failed.
//
// A failed provision is left as-is for a retry to converge rather than
// rolled back: every step is idempotent, and rolling back a half-built
// stack on a transient error would turn one retry into a full rebuild.
func (r *Runner) Run(ctx context.Context, teamID, tenantID uuid.UUID, mode Mode) error {
	log := r.Log.With().Str("tenant_id", tenantID.String()).Str("mode", string(mode)).Logger()

	release, err := r.Store.Lock(ctx, teamID, tenantID)
	if err != nil {
		if errors.Is(err, tenantstore.ErrLocked) {
			log.Info().Msg("another run holds the tenant lock; exiting")
		}
		return err
	}
	defer release()

	row, err := r.Store.GetTenant(ctx, teamID, tenantID)
	if err != nil {
		return err
	}
	if row.Status == tenantstore.StatusDeleted {
		return ErrTenantDeleted
	}

	var plan Plan
	var inFlight string
	switch mode {
	case ModeProvision:
		plan, inFlight = ProvisionPlan(r.Steps), tenantstore.StatusProvisioning
	case ModeDeprovision:
		plan, inFlight = DeprovisionPlan(r.Steps), tenantstore.StatusDeprovisioning
	default:
		return fmt.Errorf("unknown mode %q", mode)
	}
	// The API moves the tenant into the mode's in-flight status before it
	// queues the run, so that is the only status a run may start from. A
	// queued execution that arrives after the intent changed (a delete
	// requested while a provision was still queued) finds a different
	// status and exits without touching anything.
	row, err = r.Store.TransitionStatus(ctx, teamID, tenantID, []string{inFlight}, inFlight)
	if errors.Is(err, tenantstore.ErrStatusConflict) {
		log.Info().Str("status", row.Status).Msg("tenant is no longer queued for this mode; exiting")
		return fmt.Errorf("%w: tenant is not %s", ErrStaleRun, inFlight)
	}
	if err != nil {
		return err
	}
	tenant := NewTenant(row, r.Env, r.Store)

	r.record(ctx, tenant, RunStep, tenantstore.EventStarted, string(mode)+" started", map[string]any{"mode": string(mode)})

	for i, step := range plan.Steps {
		r.record(ctx, tenant, step.Name(), tenantstore.EventStarted, "", nil)
		err := step.Run(ctx, tenant)
		var skip *SkipError
		switch {
		case err == nil:
			r.record(ctx, tenant, step.Name(), tenantstore.EventOK, "", nil)
		case errors.As(err, &skip):
			r.record(ctx, tenant, step.Name(), tenantstore.EventSkipped, skip.Reason, nil)
		default:
			// Logged scrubbed, like the event: a cloud error can echo a
			// connection string or key it was handed.
			log.Warn().Str("error", ScrubString(err.Error())).Str("step", step.Name()).Msg("step failed")
			r.record(ctx, tenant, step.Name(), tenantstore.EventFailed, step.Name()+" failed", map[string]any{"error": err.Error()})
			for _, rest := range plan.Steps[i+1:] {
				r.record(ctx, tenant, rest.Name(), tenantstore.EventSkipped, "not run: "+step.Name()+" failed", nil)
			}
			r.fail(ctx, tenant, failureMessage(mode, step.Name()))
			return err
		}
	}

	// The terminal transition is written detached from ctx: every step
	// succeeded, and a cancellation now must not strand the tenant in an
	// in-flight status. If the write still fails, fall back to failed so a
	// retry (which re-runs the now-idempotent plan) can record it.
	dctx, cancel := detached(ctx)
	defer cancel()
	if mode == ModeDeprovision {
		// Last words first: a deleted tenant's event log is frozen, so the
		// completion event has to land before the status flips.
		r.record(dctx, tenant, RunStep, tenantstore.EventOK, "deprovision complete; tenant deleted", nil)
		if _, err := r.Store.SoftDelete(dctx, teamID, tenantID); err != nil {
			log.Error().Err(err).Msg("record tenant deleted")
			r.fail(dctx, tenant, "Deprovisioning finished but the tenant could not be marked deleted. Retry to record it.")
			return fmt.Errorf("mark tenant deleted: %w", err)
		}
		return nil
	}
	if _, err := r.Store.SetStatus(dctx, teamID, tenantID, tenantstore.StatusReady); err != nil {
		log.Error().Err(err).Msg("record tenant ready")
		r.fail(dctx, tenant, "Provisioning finished but the tenant could not be marked ready. Retry to record it.")
		return fmt.Errorf("mark tenant ready: %w", err)
	}
	r.record(dctx, tenant, RunStep, tenantstore.EventOK, "provision complete; tenant ready", nil)
	return nil
}

func failureMessage(mode Mode, step string) string {
	if mode == ModeDeprovision {
		return "Deprovisioning stopped at " + step + ". Retry to continue the teardown."
	}
	return "Provisioning stopped at " + step + ". Retry to continue from where it left off, or delete the tenant."
}

// fail marks the tenant failed with a user-safe run event. A failure to
// write even that is logged; the run's error is what the caller returns.
func (r *Runner) fail(ctx context.Context, t *Tenant, message string) {
	dctx, cancel := detached(ctx)
	defer cancel()
	if _, err := r.Store.SetStatus(dctx, t.Row.TeamID, t.Row.ID, tenantstore.StatusFailed); err != nil {
		r.Log.Error().Err(err).Str("tenant_id", t.Row.ID.String()).Msg("mark tenant failed")
	}
	r.record(dctx, t, RunStep, tenantstore.EventFailed, message, nil)
}

// record appends an event; detail is scrubbed before it is stored. A
// failure to write bookkeeping is logged, not fatal: the step outcome has
// already happened and a retry will re-derive it.
func (r *Runner) record(ctx context.Context, t *Tenant, step, status, message string, detail map[string]any) {
	p := tenantstore.EventParams{TenantID: t.Row.ID, Step: step, Status: status, Message: message}
	if detail != nil {
		p.Detail = ScrubDetail(detail)
	}
	dctx, cancel := detached(ctx)
	defer cancel()
	if _, err := r.Store.InsertEvent(dctx, t.Row.TeamID, p); err != nil {
		r.Log.Error().Err(err).Str("tenant_id", t.Row.ID.String()).Str("step", step).Str("status", status).Msg("record tenant event")
	}
}

// detached keeps ctx's values but not its cancellation, bounded so a dead
// database cannot hang a run forever.
func detached(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), bookkeepingTimeout)
}

// RecordSetupFailure is for the job entrypoint: the run never started
// because a dependency could not be built, so the tenant the API queued is
// moved back to failed (with the mode, so a retry resumes the same plan).
func RecordSetupFailure(ctx context.Context, store tenantstore.Store, log zerolog.Logger, teamID, tenantID uuid.UUID, mode Mode, cause error) {
	dctx, cancel := detached(ctx)
	defer cancel()
	// Under the tenant lock, like a run: if a replacement run already holds
	// it, it owns the status now and this failure is moot.
	release, err := store.Lock(dctx, teamID, tenantID)
	if err != nil {
		if !errors.Is(err, tenantstore.ErrLocked) {
			log.Error().Str("error", ScrubString(err.Error())).Str("tenant_id", tenantID.String()).Msg("lock tenant to record setup failure")
		}
		return
	}
	defer release()
	inFlight := tenantstore.StatusProvisioning
	if mode == ModeDeprovision {
		inFlight = tenantstore.StatusDeprovisioning
	}
	row, err := store.TransitionStatus(dctx, teamID, tenantID, []string{inFlight}, tenantstore.StatusFailed)
	if err != nil {
		log.Error().Str("error", ScrubString(err.Error())).Str("tenant_id", tenantID.String()).Msg("record setup failure")
		return
	}
	t := NewTenant(row, Env{}, store)
	r := &Runner{Store: store, Log: log}
	r.record(dctx, t, RunStep, tenantstore.EventFailed, failureMessage(mode, "startup"), map[string]any{"mode": string(mode), "error": cause.Error()})
}
