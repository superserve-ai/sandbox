// Package supervisor runs background goroutines that drive state machines
// stored in the database. Today: template build supervisor. Future: could
// host sandbox-timeout reaper, snapshot janitor, etc., all unified here.
//
// The build supervisor connects the HTTP API (which only writes template_build
// rows in 'pending') to the vmd daemon (which actually runs builds). A 30s
// ticker scans pending rows, dispatches to vmd, polls in-flight builds via
// GetBuildStatus, finalizes terminal outcomes, and enforces wall-clock
// timeouts.
//
// Restart-safe: supervisor state lives entirely in the DB. A crash mid-cycle
// resumes cleanly on the next tick.
package supervisor

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/builder"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

// BuildSupervisorConfig controls the supervisor's ticker cadence and bounds.
type BuildSupervisorConfig struct {
	// Interval is the poll period. 30s matches the sandbox timeout reaper
	// and trades "a bit of dispatch latency" for "low DB/vmd chatter."
	Interval time.Duration

	// BatchSize caps how many pending rows we evaluate per tick. Bounds the
	// worst-case DB + vmd work per tick under a burst of submissions.
	BatchSize int32

	// GlobalMaxConcurrentBuilds is the host-wide ceiling across all teams.
	// Stops a pathological flood from exhausting host capacity even when
	// per-team limits would allow it.
	GlobalMaxConcurrentBuilds int32

	// HostID is the vmd host the supervisor dispatches to.
	HostID string

	// PendingTimeout is how long a build can wait in 'pending' before it's
	// reaped as failed. Pending now only covers "waiting for the next
	// supervisor tick to dispatch" — concurrency limits are enforced at
	// submit time, so rows that linger are genuinely stuck.
	PendingTimeout time.Duration

	// BuildTimeout is the wall-clock cap on a single build from 'building'
	// (supervisor dispatched) to any terminal state. Beyond this, we call
	// vmd.CancelBuild and mark failed.
	BuildTimeout time.Duration

	// ReapBatchSize caps how many stale rows ReapStaleBuilds touches per
	// tick. Mirrors BatchSize's bounding rationale.
	ReapBatchSize int32
}

// DefaultBuildSupervisorConfig returns sensible defaults.
func DefaultBuildSupervisorConfig(hostID string) BuildSupervisorConfig {
	return BuildSupervisorConfig{
		Interval:                  30 * time.Second,
		BatchSize:                 20,
		GlobalMaxConcurrentBuilds: 10,
		HostID:                    hostID,
		PendingTimeout:            2 * time.Minute,
		BuildTimeout:              30 * time.Minute,
		ReapBatchSize:             20,
	}
}

// Resolver returns the VMD client for a host ID.
type Resolver func(ctx context.Context, hostID string) (vmdclient.Client, error)

// BuildSupervisor wraps the per-tick logic. Stateless across ticks — all
// state lives in the DB. Safe to instantiate once at controlplane boot and
// Start() with the process-lifetime context.
type BuildSupervisor struct {
	cfg     BuildSupervisorConfig
	q       *db.Queries
	resolve Resolver
	log     zerolog.Logger
}

// NewBuildSupervisor constructs a supervisor.
func NewBuildSupervisor(cfg BuildSupervisorConfig, q *db.Queries, resolve Resolver) *BuildSupervisor {
	return &BuildSupervisor{
		cfg:     cfg,
		q:       q,
		resolve: resolve,
		log:     log.With().Str("component", "build_supervisor").Logger(),
	}
}

// Start launches the ticker goroutine. Exits cleanly when ctx is cancelled.
// Runs one cycle immediately so a control plane restart doesn't delay
// dispatch by up to Interval seconds.
func (s *BuildSupervisor) Start(ctx context.Context) {
	go s.loop(ctx)
}

func (s *BuildSupervisor) loop(ctx context.Context) {
	s.log.Info().
		Dur("interval", s.cfg.Interval).
		Int32("batch_size", s.cfg.BatchSize).
		Int32("global_max_concurrent", s.cfg.GlobalMaxConcurrentBuilds).
		Str("host_id", s.cfg.HostID).
		Msg("build supervisor started")

	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()

	s.tick(ctx)

	for {
		select {
		case <-ctx.Done():
			s.log.Info().Msg("build supervisor exiting")
			return
		case <-ticker.C:
			s.tick(ctx)
		}
	}
}

// tick runs one full cycle: reap stale, dispatch pending, poll active. Order
// matters: reap first so the dispatch phase sees an accurate in-flight
// count and doesn't over-commit capacity.
func (s *BuildSupervisor) tick(ctx context.Context) {
	s.reapStale(ctx)
	s.dispatchPending(ctx)
	s.pollActive(ctx)
}

// reapStale marks overdue pending / in-flight builds as failed. For builds
// that had made it past 'pending', also asks vmd to cancel so the build VM
// doesn't linger.
func (s *BuildSupervisor) reapStale(ctx context.Context) {
	queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	reaped, err := s.q.ReapStaleBuilds(queryCtx, db.ReapStaleBuildsParams{
		Limit:                 s.cfg.ReapBatchSize,
		PendingTimeoutSeconds: int32(s.cfg.PendingTimeout / time.Second),
		BuildTimeoutSeconds:   int32(s.cfg.BuildTimeout / time.Second),
	})
	if err != nil {
		s.log.Error().Err(err).Msg("reap stale builds failed")
		return
	}
	for _, r := range reaped {
		s.log.Warn().Str("build_id", r.ID.String()).Msg("build timed out; marked failed")
		// Tell vmd to cancel so the build VM doesn't linger. Best-effort —
		// if vmd already finished or the build was only in 'pending', the
		// cancel is a no-op on the vmd side.
		if r.VmdBuildVmID != nil && *r.VmdBuildVmID != "" {
			cancelCtx, cancelCancel := context.WithTimeout(ctx, 10*time.Second)
			hostID := ""
			if r.VmdHostID != nil {
				hostID = *r.VmdHostID
			}
			if vmd, err := s.resolve(cancelCtx, hostID); err == nil {
				_ = vmd.CancelBuild(cancelCtx, *r.VmdBuildVmID)
			} else {
				s.log.Warn().Err(err).Str("build_id", r.ID.String()).Str("host_id", hostID).Msg("resolve VMD for cancel failed")
			}
			cancelCancel()
		}
	}
}

// dispatchPending scans pending rows in FIFO order and dispatches each that
// passes admission (per-team concurrency + global cap) to vmd. Per-row work
// is bounded by the total in-flight count; once the global cap is reached,
// we stop scanning for this tick.
func (s *BuildSupervisor) dispatchPending(ctx context.Context) {
	queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Count current in-flight at the start of the tick. Approximate budget
	// — new rows may land during the tick, but that's fine: they'll be
	// picked up next tick and the budget cap keeps us bounded.
	inflightGlobal, err := s.countInflightGlobal(queryCtx)
	if err != nil {
		s.log.Error().Err(err).Msg("count in-flight builds failed")
		return
	}
	if inflightGlobal >= int64(s.cfg.GlobalMaxConcurrentBuilds) {
		s.log.Debug().Int64("inflight", inflightGlobal).Msg("global build cap reached; skipping dispatch")
		return
	}
	budget := int64(s.cfg.GlobalMaxConcurrentBuilds) - inflightGlobal

	pending, err := s.q.ListPendingBuildsOrdered(queryCtx, s.cfg.BatchSize)
	if err != nil {
		s.log.Error().Err(err).Msg("list pending builds failed")
		return
	}

	for _, row := range pending {
		if budget <= 0 {
			break
		}
		if err := s.tryDispatchOne(ctx, row); err != nil {
			// Already logged with context in tryDispatchOne.
			continue
		}
		budget--
	}
}

// tryDispatchOne evaluates admission for a single pending row and, on pass,
// atomically claims it, dispatches to vmd, and stamps the vmd_build_vm_id.
// On admission fail, leaves the row in pending for a future tick. On
// dispatch fail, marks the build failed so the user sees it and retries.
func (s *BuildSupervisor) tryDispatchOne(ctx context.Context, row db.TemplateBuild) error {
	rowLog := s.log.With().Str("build_id", row.ID.String()).Str("template_id", row.TemplateID.String()).Logger()

	// Per-team concurrency is enforced at submit time (CreateTemplate /
	// CreateTemplateBuild return 429 when the team is at its cap). The
	// supervisor dispatches pending rows FIFO without re-checking so a
	// pending row is never blocked by the count of its own siblings.

	// Look up the template to get its vcpu/mem/disk and persisted build_spec.
	tplCtx, tplCancel := context.WithTimeout(ctx, 5*time.Second)
	tpl, err := s.q.GetTemplateForOwner(tplCtx, db.GetTemplateForOwnerParams{
		ID:     row.TemplateID,
		TeamID: row.TeamID,
	})
	tplCancel()
	if err != nil {
		// Template deleted between submission and dispatch — fail the
		// build cleanly rather than leave it stuck.
		rowLog.Warn().Err(err).Msg("template missing at dispatch time; failing build")
		s.failBuild(ctx, row.ID, "template not found (deleted after build submitted)")
		return err
	}

	var spec builder.BuildSpec
	if err := json.Unmarshal(tpl.BuildSpec, &spec); err != nil {
		rowLog.Error().Err(err).Msg("decode template build_spec")
		s.failBuild(ctx, row.ID, "invalid build_spec in template row")
		return err
	}

	// Attach the id before dispatch so a timed-out RPC can be reconciled.
	hostID := s.cfg.HostID
	buildVMID := "build-" + row.ID.String()

	claimCtx, claimCancel := context.WithTimeout(ctx, 5*time.Second)
	affected, err := s.q.TryDispatchBuild(claimCtx, db.TryDispatchBuildParams{
		ID:             row.ID,
		VmdHostID:      &hostID,
		VmdBuildVmID:   &buildVMID,
	})
	claimCancel()
	if err != nil {
		rowLog.Error().Err(err).Msg("try dispatch build")
		return err
	}
	if affected == 0 {
		rowLog.Debug().Msg("row already claimed by another tick; skipping")
		return nil
	}

	dispatchCtx, dispatchCancel := context.WithTimeout(ctx, 30*time.Second)
	defer dispatchCancel()
	vmd, err := s.resolve(dispatchCtx, hostID)
	if err != nil {
		rowLog.Error().Err(err).Str("host_id", hostID).Msg("resolve VMD for dispatch failed")
		s.failBuild(ctx, row.ID, fmt.Sprintf("resolve VMD for host %q: %v", hostID, err))
		return err
	}
	_, err = vmd.BuildTemplate(dispatchCtx, vmdclient.BuildTemplateInput{
		TemplateID: row.TemplateID.String(),
		From:       spec.From,
		Steps:      specStepsToVMD(spec.Steps),
		StartCmd:   spec.StartCmd,
		ReadyCmd:   spec.ReadyCmd,
		VCPU:       uint32(tpl.Vcpu),
		MemoryMiB:  uint32(tpl.MemoryMib),
		DiskMiB:    uint32(tpl.DiskMib),
		BuildVMID:  buildVMID,
	})
	if err != nil {
		// vmd may have accepted the request; let pollActive reconcile via
		// GetBuildStatus rather than failing here and orphaning the VM.
		rowLog.Warn().Err(err).Str("build_vm_id", buildVMID).Msg("vmd.BuildTemplate dispatch errored; next poll will reconcile")
		return err
	}

	rowLog.Info().Str("build_vm_id", buildVMID).Msg("build dispatched to vmd")
	return nil
}

// pollActive walks every in-flight build and pulls status from vmd. Drives
// transitions toward terminal states.
func (s *BuildSupervisor) pollActive(ctx context.Context) {
	queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	active, err := s.q.ListActiveBuilds(queryCtx)
	cancel()
	if err != nil {
		s.log.Error().Err(err).Msg("list active builds failed")
		return
	}

	for _, row := range active {
		if row.VmdBuildVmID == nil || *row.VmdBuildVmID == "" {
			// Dispatched but we failed to attach the vmd_build_vm_id.
			// Next reap cycle will time it out; nothing we can do
			// without the build id.
			continue
		}
		s.pollOne(ctx, row)
	}
}

// pollOne queries vmd for one build's status and transitions the DB row
// accordingly. Best-effort — transient gRPC errors are logged and retried
// on the next tick.
func (s *BuildSupervisor) pollOne(ctx context.Context, row db.TemplateBuild) {
	rowLog := s.log.With().Str("build_id", row.ID.String()).Str("build_vm_id", *row.VmdBuildVmID).Logger()

	statusCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	hostID := ""
	if row.VmdHostID != nil {
		hostID = *row.VmdHostID
	}
	vmd, err := s.resolve(statusCtx, hostID)
	if err != nil {
		cancel()
		rowLog.Warn().Err(err).Str("host_id", hostID).Msg("resolve VMD for poll failed; will retry next tick")
		return
	}
	res, err := vmd.GetBuildStatus(statusCtx, *row.VmdBuildVmID)
	cancel()
	if err != nil {
		rowLog.Warn().Err(err).Msg("GetBuildStatus failed")
		return
	}
	if res.NotFound {
		// vmd lost this build (restart, or never dispatched). Mark failed
		// so the user can retry rather than waiting indefinitely.
		rowLog.Warn().Msg("vmd has no record of build; marking failed")
		s.failBuild(ctx, row.ID, "vmd has no record of this build (likely vmd restarted)")
		return
	}

	switch res.Status {
	case "running":
		// No transition needed; we're already 'building' in DB.
		return
	case "snapshotting":
		if string(row.Status) != "snapshotting" {
			advCtx, adv := context.WithTimeout(ctx, 5*time.Second)
			_ = s.q.AdvanceBuildStatus(advCtx, db.AdvanceBuildStatusParams{
				ID:     row.ID,
				Status: db.TemplateBuildStatusSnapshotting,
			})
			adv()
			rowLog.Info().Msg("build entered snapshotting phase")
		}
	case "ready":
		finCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		rootfs := res.RootfsPath
		snapPath := res.SnapshotPath
		memPath := res.MemFilePath
		size := res.SizeBytes
		_, err := s.q.FinalizeBuild(finCtx, db.FinalizeBuildParams{
			ID:           row.ID,
			RootfsPath:   &rootfs,
			SnapshotPath: &snapPath,
			MemPath:      &memPath,
			SizeBytes:    &size,
		})
		cancel()
		if err != nil {
			rowLog.Error().Err(err).Msg("finalize build")
			return
		}
		rowLog.Info().Str("digest", res.ResolvedDigest).Int64("size", size).Msg("build ready")
	case "failed", "cancelled":
		s.failBuild(ctx, row.ID, res.ErrorMessage)
		rowLog.Info().Str("status", res.Status).Str("error", res.ErrorMessage).Msg("build terminal")
	}
}

// failBuild transitions a build to 'failed' with the given error message.
// Uses a detached context so client disconnect doesn't race the terminal
// write — losing this would leave the row stuck in 'building' forever.
func (s *BuildSupervisor) failBuild(ctx context.Context, buildID uuid.UUID, msg string) {
	failCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	errMsg := msg
	if _, err := s.q.FailBuild(failCtx, db.FailBuildParams{
		ID:           buildID,
		ErrorMessage: &errMsg,
	}); err != nil {
		s.log.Error().Err(err).Str("build_id", buildID.String()).Msg("fail build")
	}
}

// countInflightGlobal returns the total number of in-flight builds across
// all teams on this host. Cheap COUNT; single DB call per tick.
func (s *BuildSupervisor) countInflightGlobal(ctx context.Context) (int64, error) {
	active, err := s.q.ListActiveBuilds(ctx)
	if err != nil {
		return 0, err
	}
	// pending isn't counted — those haven't been dispatched yet and don't
	// consume vmd resources.
	return int64(len(active)), nil
}

// specStepsToVMD converts internal builder.BuildStep slices to the
// vmdclient wire shape. Declared here rather than on the types so the
// builder package stays free of a vmdclient dependency.
func specStepsToVMD(steps []builder.BuildStep) []vmdclient.BuildStep {
	out := make([]vmdclient.BuildStep, 0, len(steps))
	for _, s := range steps {
		var vs vmdclient.BuildStep
		switch {
		case s.Run != nil:
			vs.Run = s.Run
		case s.Env != nil:
			vs.Env = &vmdclient.BuildEnvOp{Key: s.Env.Key, Value: s.Env.Value}
		case s.Workdir != nil:
			vs.Workdir = s.Workdir
		case s.User != nil:
			vs.User = &vmdclient.BuildUserOp{Name: s.User.Name, Sudo: s.User.Sudo}
		}
		out = append(out, vs)
	}
	return out
}
