package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/backup"
	"github.com/superserve-ai/sandbox/internal/builder"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/sentrylog"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func (s *BuildSupervisor) tickExecutions(ctx context.Context) {
	ids, err := s.q.ListResilientBuildIDs(ctx, s.cfg.BatchSize)
	if err != nil {
		s.logTickErr(err, "list fenced builds")
		return
	}
	var wg sync.WaitGroup
	slots := make(chan struct{}, 4)
	for _, id := range ids {
		slots <- struct{}{}
		wg.Add(1)
		go func(id uuid.UUID) {
			defer sentrylog.Recover("build-reconcile")
			defer wg.Done()
			defer func() { <-slots }()
			workCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
			defer cancel()
			if err := s.reconcileExecution(workCtx, id); err != nil {
				s.log.Warn().Err(err).Str("build_id", id.String()).Msg("build reconciliation will retry")
			}
		}(id)
	}
	wg.Wait()
}

func (s *BuildSupervisor) reconcileExecution(ctx context.Context, id uuid.UUID) error {
	e, err := s.q.GetBuildExecution(ctx, id)
	if err != nil {
		return err
	}
	tpl, created, now, err := s.q.GetBuildSubmission(ctx, id)
	if err != nil {
		return err
	}
	// A ready template owes only its upload, which drains on its own schedule.
	// The producer may also have finished inside the budget without having been
	// observed yet, so the deadline is applied only where this pass found no
	// completion evidence, never on the strength of our own polling cadence.
	expired := ""
	if !e.Finalized && !e.Publication {
		expired = executionExpired(e, created, now)
	}
	if e.CurrentAttempt == nil {
		if expired != "" {
			return s.failExecution(ctx, id, nil, expired)
		}
		if e.Attempts >= 3 {
			return s.failExecution(ctx, id, nil, "infrastructure retries exhausted (three total attempts)")
		}
		aid, err := s.q.ClaimBuildAttempt(ctx, id, s.cfg.Cell, s.cfg.GlobalMaxConcurrentBuilds)
		if err != nil || aid == nil {
			return err
		}
		a, err := s.q.GetBuildAttempt(ctx, *aid)
		if err != nil {
			return err
		}
		input, err := s.q.GetTemplateBuildInput(ctx, id)
		if err != nil {
			return err
		}
		var spec builder.BuildSpec
		if err = json.Unmarshal(input.BuildSpec, &spec); err != nil {
			return s.failExecution(ctx, id, aid, "invalid immutable build specification")
		}
		client, err := s.resolve(ctx, a.HostID)
		if err != nil {
			return err
		}
		// Only a capability-attested daemon receives this versioned admission
		// metadata. It checks the incarnation and calls back before starting work.
		dispatch := metadata.AppendToOutgoingContext(ctx, "template-build-attempt", a.ID.String(), "template-build-incarnation", a.IncarnationID.String())
		_, err = client.BuildTemplate(dispatch, vmdclient.BuildTemplateInput{TemplateID: tpl.String(), From: spec.From,
			Steps: specStepsToVMD(spec.Steps), StartCmd: spec.StartCmd, ReadyCmd: spec.ReadyCmd, VCPU: uint32(input.Vcpu),
			MemoryMiB: uint32(input.MemoryMib), DiskMiB: uint32(input.DiskMib), BuildVMID: a.VMID})
		switch status.Code(err) {
		case codes.ResourceExhausted, codes.FailedPrecondition:
			_, transitionErr := s.q.TransitionBuildAttempt(ctx, id, aid, "reject", "host admission rejected; waiting for capacity")
			return transitionErr
		case codes.InvalidArgument:
			return s.failExecution(ctx, id, aid, "invalid build request")
		}
		s.log.Info().Err(err).Str("build_id", id.String()).Str("attempt_id", a.ID.String()).Str("host_id", a.HostID).
			Int("attempt_count", e.Attempts+1).Msg("build dispatch persisted; uncertain RPC outcomes reconcile on owner")
		return nil
	}
	a, err := s.q.GetBuildAttempt(ctx, *e.CurrentAttempt)
	if err != nil {
		return err
	}
	// Publication is independent of a producer's continued availability.
	if e.Publication {
		if s.publishedLate(ctx, e, a) {
			return s.failExecution(ctx, id, &a.ID, "build execution deadline exceeded; producer completed outside the budget")
		}
		accepted, err := s.q.AcceptBuildPublication(ctx, id, a.ID)
		if accepted {
			if s.onFinalize != nil {
				s.onFinalize(tpl)
			}
			s.log.Info().Str("build_id", id.String()).Str("attempt_id", a.ID.String()).Str("host_id", a.HostID).
				Str("publication_state", "accepted").Msg("build durably ready")
			s.logExecutionCompleted(ctx, id, "success", "", "")
		}
		return err
	}
	// Only the upload is outstanding. A lost owner is the one thing that can
	// strand it, so look for a manifest the producer may already have written.
	if e.Finalized {
		lost, err := s.q.BuildAttemptHostLost(ctx, a)
		if err != nil || !lost {
			return err
		}
		_, err = s.reconcileDurablePublication(ctx, a)
		return err
	}
	lost, err := s.q.BuildAttemptHostLost(ctx, a)
	if err != nil {
		return err
	}
	if lost {
		found, err := s.reconcileDurablePublication(ctx, a)
		if err != nil || found {
			return err
		}
		return s.retryExecution(ctx, e, a, "host heartbeat lost or incarnation replaced")
	}
	client, err := s.resolve(ctx, a.HostID)
	if err != nil {
		if errors.Is(err, ErrBuildHostGone) {
			found, reconcileErr := s.reconcileDurablePublication(ctx, a)
			if reconcileErr != nil || found {
				return reconcileErr
			}
			return s.retryExecution(ctx, e, a, "host registration missing")
		}
		if expired != "" {
			return s.failExecution(ctx, id, &a.ID, expired)
		}
		return err
	}
	result, err := client.GetBuildStatus(metadata.AppendToOutgoingContext(ctx, "template-build-incarnation", a.IncarnationID.String()), a.VMID)
	if err != nil {
		if expired != "" {
			return s.failExecution(ctx, id, &a.ID, expired)
		}
		return err
	}
	if result.NotFound {
		if now.Sub(a.ClaimedAt) >= 60*time.Second {
			found, err := s.reconcileDurablePublication(ctx, a)
			if err != nil || found {
				return err
			}
			return s.retryExecution(ctx, e, a, "execution missing after registration grace")
		}
		if expired != "" {
			return s.failExecution(ctx, id, &a.ID, expired)
		}
		return nil
	}
	switch result.Status {
	case "ready":
		if completedLate(e, result) {
			err = s.failExecution(ctx, id, &a.ID, "build execution deadline exceeded; producer completed outside the budget")
			break
		}
		err = s.finalizeExecution(ctx, id, a, result)
	case "failed", "cancelled":
		// No transport heuristic turns user-step or unclassified failures into retries.
		err = s.failExecution(ctx, id, &a.ID, result.ErrorMessage)
	default:
		if expired != "" {
			return s.failExecution(ctx, id, &a.ID, expired)
		}
	}
	return err
}

// finalizeExecution promotes the producer's reported artifacts. The upload is
// recorded separately, so a loaded uploader delays the backup, not the build.
func (s *BuildSupervisor) finalizeExecution(ctx context.Context, id uuid.UUID, a db.BuildAttempt, result vmdclient.BuildStatusResult) error {
	if !result.AllocatedBytesSupported {
		s.log.Info().Str("build_id", id.String()).Str("host_id", a.HostID).
			Msg("build status lacks allocation-field support; waiting for an upgraded host before finalizing")
		return nil
	}
	runtime, err := json.Marshal(backup.TemplateRuntime{RootfsPath: result.RootfsPath, SnapshotPath: result.SnapshotPath,
		MemPath: result.MemFilePath, BasePath: result.BasePath, DeltaPath: result.DeltaPath, SizeBytes: result.SizeBytes})
	if err != nil {
		return err
	}
	finalized, err := s.q.FinalizeTemplateBuild(ctx, id, a.ID, runtime,
		result.RootfsAllocatedBytes, result.BaseAllocatedBytes, result.DeltaAllocatedBytes)
	if err != nil || !finalized {
		return err
	}
	if s.onFinalize != nil {
		s.onFinalize(a.TemplateID)
	}
	s.log.Info().Str("build_id", id.String()).Str("attempt_id", a.ID.String()).Str("host_id", a.HostID).
		Str("digest", result.ResolvedDigest).Int64("size", result.SizeBytes).Msg("build ready")
	s.logExecutionCompleted(ctx, id, "success", "", result.ResolvedDigest)
	return nil
}

// publishedLate judges a publication on the same producer budget as a status
// report, so promotion does not depend on which path observes a build first.
// An unreachable owner yields no evidence, and evidence is what condemns a
// build: acceptance must never require the producer to still be alive.
func (s *BuildSupervisor) publishedLate(ctx context.Context, e db.BuildExecution, a db.BuildAttempt) bool {
	client, err := s.resolve(ctx, a.HostID)
	if err != nil {
		return false
	}
	result, err := client.GetBuildStatus(
		metadata.AppendToOutgoingContext(ctx, "template-build-incarnation", a.IncarnationID.String()), a.VMID)
	if err != nil || result.NotFound {
		return false
	}
	return completedLate(e, result)
}

func (s *BuildSupervisor) failExecution(ctx context.Context, id uuid.UUID, attempt *uuid.UUID, reason string) error {
	changed, err := s.q.TransitionBuildAttempt(ctx, id, attempt, "fail", reason)
	if err == nil && changed {
		s.logExecutionCompleted(ctx, id, "error", reason, "")
	}
	return err
}

func (s *BuildSupervisor) logExecutionCompleted(ctx context.Context, id uuid.UUID, status, reason, digest string) {
	templateID, teamID, err := s.q.GetBuildAuditOwner(ctx, id)
	if err != nil {
		s.log.Error().Err(err).Str("build_id", id.String()).Msg("load build audit owner")
		return
	}
	s.logBuildCompleted(ctx, db.TemplateBuild{ID: id, TemplateID: templateID, TeamID: teamID}, status, reason, digest)
}

func (s *BuildSupervisor) reconcileDurablePublication(ctx context.Context, a db.BuildAttempt) (bool, error) {
	if s.publicationStore == nil || s.cfg.PublicationBucket == "" {
		return false, errors.New("template publication storage is not configured")
	}
	manifest, files, object, err := backup.FindTemplatePublication(ctx, s.publicationStore, a.TemplateID.String(), a.VMID)
	if err != nil || manifest == nil {
		return false, err
	}
	fileJSON, err := json.Marshal(files)
	if err != nil {
		return false, err
	}
	runtimeJSON, err := json.Marshal(manifest.TemplateRuntime)
	if err != nil {
		return false, err
	}
	accepted, err := s.q.RecordBuildPublication(ctx, a.ID, a.HostID, s.cfg.PublicationBucket,
		manifest.Generation, object, fileJSON, runtimeJSON, time.Now().UTC())
	if err != nil {
		return false, err
	}
	s.log.Info().Str("build_id", a.BuildID.String()).Str("attempt_id", a.ID.String()).
		Str("host_id", a.HostID).Bool("recorded", accepted).Msg("reconciled durable template manifest before host retry")
	return true, nil
}

// executionBudget bounds the producer, measured from its first dispatch.
const executionBudget = 30 * time.Minute

// completedLate reports a completion the producer itself timestamps outside the
// budget, which is late however early or late we observe it. An unreported
// timestamp carries no evidence either way, so it does not condemn the build.
func completedLate(e db.BuildExecution, result vmdclient.BuildStatusResult) bool {
	if e.FirstStartedAt == nil || result.EndedAtUnix <= 0 {
		return false
	}
	return !time.Unix(result.EndedAtUnix, 0).Before(e.FirstStartedAt.Add(executionBudget))
}

func executionExpired(e db.BuildExecution, created, now time.Time) string {
	if e.FirstStartedAt == nil {
		if !now.Before(created.Add(2 * time.Minute)) {
			return "no eligible host/capacity before initial queue deadline"
		}
	} else if !now.Before(e.FirstStartedAt.Add(executionBudget)) {
		return "build execution deadline exceeded; no eligible replacement within budget"
	}
	return ""
}
func (s *BuildSupervisor) retryExecution(ctx context.Context, e db.BuildExecution, a db.BuildAttempt, reason string) error {
	changed, err := s.q.TransitionBuildAttempt(ctx, e.BuildID, &a.ID, "retry", reason)
	if changed {
		s.log.Warn().Str("build_id", e.BuildID.String()).Str("attempt_id", a.ID.String()).Str("host_id", a.HostID).
			Int("attempt_count", e.Attempts).Str("retry_reason", reason).Msg("attempt fenced; waiting for unused eligible host")
	}
	return err
}
func (s *BuildSupervisor) cleanupAttempts(ctx context.Context) {
	// Bound the entire cleanup pass so unreachable owners cannot hold up the
	// next dispatch tick for one timeout per attempt.
	cleanupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	checked := make([]uuid.UUID, 0, 20)
	for len(checked) < cap(checked) {
		if cleanupCtx.Err() != nil {
			return
		}
		attempts, err := s.q.ListBuildAttemptCleanup(cleanupCtx, 1, checked)
		if err != nil {
			s.logTickErr(err, "list attempt cleanup")
			return
		}
		if len(attempts) == 0 {
			return
		}
		a := attempts[0]
		checked = append(checked, a.ID)
		func() {
			cleanup, cancel := context.WithTimeout(cleanupCtx, 10*time.Second)
			defer cancel()
			host, err := s.q.GetHost(cleanup, a.HostID)
			if err != nil || !host.IncarnationID.Valid || uuid.UUID(host.IncarnationID.Bytes) != a.IncarnationID {
				return
			}
			client, err := s.resolve(cleanup, a.HostID)
			if err != nil {
				return
			}
			if err = client.CancelBuild(metadata.AppendToOutgoingContext(cleanup, "template-build-incarnation", a.IncarnationID.String()), a.VMID); err != nil {
				return
			}
			protected, err := s.q.BuildAttemptReferenced(cleanup, a.ID)
			if err != nil {
				return
			}
			if protected {
				_ = s.q.MarkBuildAttemptCleaned(cleanup, a.ID)
				return
			}
			if err = client.DeleteBuildArtifacts(metadata.AppendToOutgoingContext(cleanup, "template-build-incarnation", a.IncarnationID.String()), a.TemplateID.String(), a.VMID); err != nil {
				return
			}
			_ = s.q.MarkBuildAttemptCleaned(cleanup, a.ID)
		}()
	}
}
