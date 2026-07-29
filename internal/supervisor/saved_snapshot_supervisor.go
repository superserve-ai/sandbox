package supervisor

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/securitypolicy"
	"github.com/superserve-ai/sandbox/internal/sentrylog"
	"github.com/superserve-ai/sandbox/internal/telemetry"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

// SavedSnapshotSupervisorConfig bounds reconciliation work and keeps the
// background worker outside the window of an ordinary API request.
type SavedSnapshotSupervisorConfig struct {
	Interval          time.Duration
	StaleCaptureAfter time.Duration
	StaleDeleteAfter  time.Duration
	OperationTimeout  time.Duration
	BatchSize         int32
}

func DefaultSavedSnapshotSupervisorConfig() SavedSnapshotSupervisorConfig {
	return SavedSnapshotSupervisorConfig{
		Interval:          30 * time.Second,
		StaleCaptureAfter: 5 * time.Minute,
		StaleDeleteAfter:  1 * time.Minute,
		OperationTimeout:  2 * time.Minute,
		BatchSize:         20,
	}
}

// SavedSnapshotStore is the durable state used by the reconciler. *db.Queries
// implements it directly; the interface keeps transition tests independent of
// a running PostgreSQL instance.
type SavedSnapshotStore interface {
	ListStaleCreatingSavedSnapshots(context.Context, db.ListStaleCreatingSavedSnapshotsParams) ([]db.Snapshot, error)
	ListDeletingSavedSnapshots(context.Context, db.ListDeletingSavedSnapshotsParams) ([]db.Snapshot, error)
	DeferSavedSnapshotReconciliation(context.Context, db.DeferSavedSnapshotReconciliationParams) (int64, error)
	GetSavedSnapshot(context.Context, db.GetSavedSnapshotParams) (db.Snapshot, error)
	FinalizeSavedSnapshot(context.Context, db.FinalizeSavedSnapshotParams) (db.FinalizeSavedSnapshotRow, error)
	QueueSavedSnapshotCleanup(context.Context, db.QueueSavedSnapshotCleanupParams) (db.QueueSavedSnapshotCleanupRow, error)
	FailSavedSnapshot(context.Context, db.FailSavedSnapshotParams) (db.FailSavedSnapshotRow, error)
	FailSavedSnapshotAndSource(context.Context, db.FailSavedSnapshotAndSourceParams) (db.FailSavedSnapshotAndSourceRow, error)
	FailSavedSnapshotSourceAfterRevocation(context.Context, db.FailSavedSnapshotSourceAfterRevocationParams) (uuid.UUID, error)
	UpsertSandboxRevocation(context.Context, db.UpsertSandboxRevocationParams) error
	FinalizeSavedSnapshotDelete(context.Context, db.FinalizeSavedSnapshotDeleteParams) (db.Snapshot, error)
}

// SavedSnapshotResolver must resolve the exact host recorded on the snapshot.
// Callers must not fall back to another host: V1 snapshot paths are host-local.
type SavedSnapshotResolver func(context.Context, string) (vmdclient.SavedSnapshotClient, error)

type savedSnapshotSourceContainmentClient interface {
	RevokeSandbox(context.Context, string) error
	DestroyInstance(context.Context, string, bool) error
}

// SavedSnapshotSupervisor repairs the two crash-sensitive transitions:
// creating -> ready/failed and deleting -> soft-deleted. VMD capture and delete
// are idempotent for the (source sandbox, snapshot) identity, making every tick
// safe to repeat after a control-plane restart.
type SavedSnapshotSupervisor struct {
	cfg     SavedSnapshotSupervisorConfig
	store   SavedSnapshotStore
	resolve SavedSnapshotResolver
	// cleanupResolve is status-agnostic but still exact-host. A draining or
	// unhealthy host must not accept new captures, yet cleanup must remain able
	// to converge there. When nil, resolve is used for backward compatibility.
	cleanupResolve SavedSnapshotResolver
	log            zerolog.Logger
	recorder       telemetry.Recorder
}

func (s *SavedSnapshotSupervisor) WithCleanupResolver(resolve SavedSnapshotResolver) *SavedSnapshotSupervisor {
	s.cleanupResolve = resolve
	return s
}

// WithTelemetry makes restart reconciliation outcomes visible through the
// same bounded recorder as request paths. A nil recorder remains a no-op.
func (s *SavedSnapshotSupervisor) WithTelemetry(recorder telemetry.Recorder) *SavedSnapshotSupervisor {
	if recorder == nil {
		recorder = telemetry.NewNoopRecorder()
	}
	s.recorder = recorder
	return s
}

func NewSavedSnapshotSupervisor(
	cfg SavedSnapshotSupervisorConfig,
	store SavedSnapshotStore,
	resolve SavedSnapshotResolver,
) *SavedSnapshotSupervisor {
	return &SavedSnapshotSupervisor{
		cfg:      cfg,
		store:    store,
		resolve:  resolve,
		log:      log.With().Str("component", "saved_snapshot_supervisor").Logger(),
		recorder: telemetry.NewNoopRecorder(),
	}
}

func (s *SavedSnapshotSupervisor) recordOutcome(ctx context.Context, snapshot db.Snapshot, operation, outcome string) {
	hostID := ""
	if snapshot.HostID != nil {
		hostID = *snapshot.HostID
	}
	s.recorder.RecordSavedSnapshotOutcome(ctx, telemetry.SavedSnapshotOutcome{
		Operation: operation,
		Outcome:   outcome,
		HostID:    hostID,
	})
}

// Start launches one restart-safe reconciliation loop. It runs immediately so
// a process restart does not add another full interval to stale operations.
func (s *SavedSnapshotSupervisor) Start(ctx context.Context) {
	go s.loop(ctx)
}

func (s *SavedSnapshotSupervisor) loop(ctx context.Context) {
	s.log.Info().
		Dur("interval", s.cfg.Interval).
		Dur("stale_capture_after", s.cfg.StaleCaptureAfter).
		Dur("stale_delete_after", s.cfg.StaleDeleteAfter).
		Int32("batch_size", s.cfg.BatchSize).
		Msg("saved snapshot supervisor started")

	sentrylog.RunSafe("saved-snapshot-supervisor", func() { s.tick(ctx) })
	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			s.log.Info().Msg("saved snapshot supervisor exiting")
			return
		case <-ticker.C:
			sentrylog.RunSafe("saved-snapshot-supervisor", func() { s.tick(ctx) })
		}
	}
}

func (s *SavedSnapshotSupervisor) tick(ctx context.Context) {
	if s.store == nil || s.resolve == nil || s.cfg.BatchSize <= 0 {
		return
	}
	now := time.Now()

	// Finish deletes first so storage accounting can converge before captures
	// blocked on the same team's storage quota are retried.
	deleting, err := s.store.ListDeletingSavedSnapshots(ctx, db.ListDeletingSavedSnapshotsParams{
		StaleBefore: now.Add(-s.cfg.StaleDeleteAfter),
		RowLimit:    s.cfg.BatchSize,
	})
	if err != nil {
		s.logStoreError(err, "list stale deleting saved snapshots")
	} else {
		for _, snapshot := range deleting {
			if ctx.Err() != nil {
				return
			}
			s.reconcileDeleting(ctx, snapshot)
		}
	}

	creating, err := s.store.ListStaleCreatingSavedSnapshots(ctx, db.ListStaleCreatingSavedSnapshotsParams{
		StaleBefore: now.Add(-s.cfg.StaleCaptureAfter),
		RowLimit:    s.cfg.BatchSize,
	})
	if err != nil {
		s.logStoreError(err, "list stale creating saved snapshots")
		return
	}
	for _, snapshot := range creating {
		if ctx.Err() != nil {
			return
		}
		s.reconcileCreating(ctx, snapshot)
	}
}

func (s *SavedSnapshotSupervisor) reconcileCreating(ctx context.Context, snapshot db.Snapshot) {
	rowLog := s.log.With().
		Str("snapshot_id", snapshot.ID.String()).
		Str("sandbox_id", snapshot.SandboxID.String()).
		Logger()
	if snapshot.HostID == nil || *snapshot.HostID == "" {
		rowLog.Error().Msg("stale saved snapshot capture has no owning host; marking failed")
		s.failCreating(ctx, snapshot, "source_host_missing")
		return
	}

	client, err := s.resolve(ctx, *snapshot.HostID)
	if err != nil {
		rowLog.Warn().Err(vmdclient.SanitizeSavedSnapshotError(vmdclient.SavedSnapshotOperationHostResolution, err)).Str("host_id", *snapshot.HostID).Msg("resolve saved snapshot host")
		s.deferReconciliation(ctx, snapshot, db.SnapshotStatusCreating, "resolve capture host")
		return
	}
	if client == nil {
		rowLog.Warn().Str("host_id", *snapshot.HostID).Msg("saved snapshot host returned no compatible client")
		s.deferReconciliation(ctx, snapshot, db.SnapshotStatusCreating, "resolve compatible capture client")
		return
	}
	capabilityCtx, cancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	err = client.CheckSavedSnapshotSupport(capabilityCtx)
	cancel()
	if err != nil {
		rowLog.Warn().Err(vmdclient.SanitizeSavedSnapshotError(vmdclient.SavedSnapshotOperationCapabilityCheck, err)).Str("host_id", *snapshot.HostID).Msg("saved snapshot capability check failed")
		s.deferReconciliation(ctx, snapshot, db.SnapshotStatusCreating, "check capture capability")
		return
	}

	opCtx, cancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	artifacts, err := client.CreateSavedSnapshot(opCtx, snapshot.SandboxID.String(), snapshot.ID.String())
	cancel()
	if err != nil {
		if code := status.Code(err); code == codes.NotFound || code == codes.DataLoss {
			s.recordOutcome(ctx, snapshot, telemetry.SavedSnapshotOperationCapture, telemetry.SavedSnapshotOutcomeArtifactCorrupt)
		}
		pausedSourceDataLoss := status.Code(err) == codes.DataLoss &&
			snapshot.SourceStatus.Valid && snapshot.SourceStatus.SandboxStatus == db.SandboxStatusPaused
		if vmdclient.GRPCErrorHasReason(err, vmdclient.SavedSnapshotSourceResumeFailureReason) || pausedSourceDataLoss {
			rowLog.Error().Err(vmdclient.SanitizeSavedSnapshotError(vmdclient.SavedSnapshotOperationCapture, err)).Msg("saved snapshot source failed to resume; terminalizing source")
			reason := "source_resume_failed"
			if pausedSourceDataLoss {
				reason = "source_artifacts_missing"
			}
			expiresAt := time.Now().Add(securitypolicy.SandboxCredentialLifetime)
			_, failErr := s.store.FailSavedSnapshotAndSource(ctx, db.FailSavedSnapshotAndSourceParams{
				SnapshotID: snapshot.ID, TeamID: snapshot.TeamID, RevocationExpiresAt: expiresAt, FailureReason: &reason,
			})
			sourceFailureDurable := failErr == nil
			if failErr != nil {
				if !errors.Is(failErr, pgx.ErrNoRows) {
					s.logStoreError(failErr, "atomically fail saved snapshot and source after resume failure")
				}
				if revokeErr := s.store.UpsertSandboxRevocation(ctx, db.UpsertSandboxRevocationParams{
					SandboxID: snapshot.SandboxID, ExpiresAt: expiresAt,
				}); revokeErr != nil {
					s.logStoreError(revokeErr, "persist saved snapshot source revocation fallback")
				} else {
					_, fallbackErr := s.store.FailSavedSnapshotSourceAfterRevocation(ctx, db.FailSavedSnapshotSourceAfterRevocationParams{
						SnapshotID: snapshot.ID, TeamID: snapshot.TeamID, FailureReason: &reason,
					})
					if fallbackErr != nil {
						s.logStoreError(fallbackErr, "fail saved snapshot source after durable revocation")
					} else {
						sourceFailureDurable = true
					}
				}
			}
			if !sourceFailureDurable {
				s.deferReconciliation(ctx, snapshot, db.SnapshotStatusCreating, "persist failed source transition")
			}
			s.containFailedSource(ctx, rowLog, client, snapshot, sourceFailureDurable)
			return
		}
		if transientSavedSnapshotError(err) {
			rowLog.Warn().Err(vmdclient.SanitizeSavedSnapshotError(vmdclient.SavedSnapshotOperationCapture, err)).Msg("retry saved snapshot capture")
			s.deferReconciliation(ctx, snapshot, db.SnapshotStatusCreating, "capture transient failure")
			return
		}
		rowLog.Error().Err(vmdclient.SanitizeSavedSnapshotError(vmdclient.SavedSnapshotOperationCapture, err)).Msg("saved snapshot capture cannot be reconciled")
		s.cleanupFailedCapture(ctx, rowLog, client, snapshot, artifacts, nil, captureFailureReason(err))
		return
	}

	metadata, err := marshalReconciledArtifactMetadata(artifacts)
	if err != nil {
		rowLog.Error().Err(err).Msg("marshal reconciled saved snapshot artifacts")
		s.cleanupFailedCapture(ctx, rowLog, client, snapshot, artifacts, nil, "artifact_metadata_invalid")
		return
	}
	if err := validateReconciledArtifacts(snapshot, artifacts); err != nil {
		rowLog.Error().Err(err).Msg("reconciled saved snapshot artifacts failed validation")
		s.recordOutcome(ctx, snapshot, telemetry.SavedSnapshotOperationCapture, telemetry.SavedSnapshotOutcomeArtifactCorrupt)
		s.cleanupFailedCapture(ctx, rowLog, client, snapshot, artifacts, metadata, "artifact_validation_failed")
		return
	}

	_, err = s.store.FinalizeSavedSnapshot(ctx, db.FinalizeSavedSnapshotParams{
		SnapshotID:         snapshot.ID,
		TeamID:             snapshot.TeamID,
		Path:               artifacts.SnapshotPath,
		MemPath:            artifacts.MemPath,
		LogicalSizeBytes:   artifacts.LogicalSizeBytes,
		ManifestPath:       artifacts.ManifestPath,
		ManifestDigest:     &artifacts.ManifestDigest,
		ArtifactMetadata:   metadata,
		ExclusiveSizeBytes: artifacts.ExclusiveSizeBytes,
	})
	if err == nil {
		rowLog.Info().Msg("stale saved snapshot capture finalized")
		return
	}
	if reason := savedSnapshotQuotaFailure(err); reason != "" {
		rowLog.Warn().Err(err).Msg("reconciled saved snapshot exceeds quota; releasing capture claim")
		s.cleanupFailedCapture(ctx, rowLog, client, snapshot, artifacts, metadata, reason)
		return
	}
	if errors.Is(err, pgx.ErrNoRows) {
		rowLog.Warn().Msg("saved snapshot finalize precondition no longer holds")
		s.reconcileLostFinalize(ctx, rowLog, client, snapshot, artifacts, metadata)
		return
	}
	// Preserve both the committed artifact and creating row after a transient
	// DB failure; the next idempotent VMD call will rediscover the manifest.
	s.logStoreError(err, "finalize stale saved snapshot capture")
	s.deferReconciliation(ctx, snapshot, db.SnapshotStatusCreating, "finalize capture")
}

func (s *SavedSnapshotSupervisor) containFailedSource(ctx context.Context, rowLog zerolog.Logger, client vmdclient.SavedSnapshotClient, snapshot db.Snapshot, sourceFailureDurable bool) {
	containment, ok := client.(savedSnapshotSourceContainmentClient)
	if !ok {
		rowLog.Error().Msg("saved snapshot client cannot contain failed source; exact-host reconciler must retry")
		return
	}
	revokeCtx, revokeCancel := context.WithTimeout(context.WithoutCancel(ctx), s.cfg.OperationTimeout)
	if err := containment.RevokeSandbox(revokeCtx, snapshot.SandboxID.String()); err != nil {
		rowLog.Warn().Err(vmdclient.SanitizeSavedSnapshotError(vmdclient.SavedSnapshotOperationCapture, err)).Msg("directly revoke failed saved-snapshot source")
	}
	revokeCancel()
	if !sourceFailureDurable {
		rowLog.Error().Msg("retain failed source because its durable failure transition was not proven")
		return
	}
	destroyCtx, destroyCancel := context.WithTimeout(context.WithoutCancel(ctx), s.cfg.OperationTimeout)
	if err := containment.DestroyInstance(destroyCtx, snapshot.SandboxID.String(), true); err != nil && status.Code(err) != codes.NotFound {
		rowLog.Error().Err(vmdclient.SanitizeSavedSnapshotError(vmdclient.SavedSnapshotOperationCapture, err)).Msg("destroy failed saved-snapshot source; exact-host reconciler will retry")
	}
	destroyCancel()
}

func (s *SavedSnapshotSupervisor) reconcileDeleting(ctx context.Context, snapshot db.Snapshot) {
	rowLog := s.log.With().
		Str("snapshot_id", snapshot.ID.String()).
		Str("sandbox_id", snapshot.SandboxID.String()).
		Logger()
	if snapshot.HostID == nil || *snapshot.HostID == "" {
		// Do not finalize a hostless delete: without knowing where the V1-local
		// artifact lived, doing so could silently leak storage forever.
		rowLog.Error().Msg("stale saved snapshot delete has no owning host")
		s.recordOutcome(ctx, snapshot, telemetry.SavedSnapshotOperationCleanup, telemetry.SavedSnapshotOutcomeError)
		s.deferReconciliation(ctx, snapshot, db.SnapshotStatusDeleting, "resolve hostless delete")
		return
	}
	resolver := s.cleanupResolve
	if resolver == nil {
		resolver = s.resolve
	}
	client, err := resolver(ctx, *snapshot.HostID)
	if err != nil {
		rowLog.Warn().Err(vmdclient.SanitizeSavedSnapshotError(vmdclient.SavedSnapshotOperationHostResolution, err)).Str("host_id", *snapshot.HostID).Msg("resolve saved snapshot host for delete")
		s.recordOutcome(ctx, snapshot, telemetry.SavedSnapshotOperationCleanup, telemetry.SavedSnapshotOutcomeRetry)
		s.deferReconciliation(ctx, snapshot, db.SnapshotStatusDeleting, "resolve delete host")
		return
	}
	if client == nil {
		rowLog.Warn().Str("host_id", *snapshot.HostID).Msg("saved snapshot host returned no compatible client for delete")
		s.recordOutcome(ctx, snapshot, telemetry.SavedSnapshotOperationCleanup, telemetry.SavedSnapshotOutcomeRetry)
		s.deferReconciliation(ctx, snapshot, db.SnapshotStatusDeleting, "resolve compatible delete client")
		return
	}
	// Cleanup must remain available when writer prerequisites or feature flags
	// are rolled back. Resolver compatibility proves this client knows the
	// delete RPC; requiring the full capture/restore capability here could
	// strand already-committed artifacts indefinitely.
	opCtx, cancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	err = client.DeleteSavedSnapshot(opCtx, snapshot.SandboxID.String(), snapshot.ID.String())
	cancel()
	if err != nil && status.Code(err) != codes.NotFound {
		logErr := vmdclient.SanitizeSavedSnapshotError(vmdclient.SavedSnapshotOperationDelete, err)
		if transientSavedSnapshotError(err) {
			rowLog.Warn().Err(logErr).Msg("retry saved snapshot artifact delete")
			s.recordOutcome(ctx, snapshot, telemetry.SavedSnapshotOperationCleanup, telemetry.SavedSnapshotOutcomeRetry)
		} else {
			rowLog.Error().Err(logErr).Msg("saved snapshot artifact delete failed")
			s.recordOutcome(ctx, snapshot, telemetry.SavedSnapshotOperationCleanup, telemetry.SavedSnapshotOutcomeError)
		}
		s.deferReconciliation(ctx, snapshot, db.SnapshotStatusDeleting, "delete artifacts")
		return
	}

	_, err = s.store.FinalizeSavedSnapshotDelete(ctx, db.FinalizeSavedSnapshotDeleteParams{
		SnapshotID: snapshot.ID,
		TeamID:     snapshot.TeamID,
	})
	if err == nil {
		rowLog.Info().Msg("stale saved snapshot delete finalized")
		s.recordOutcome(ctx, snapshot, telemetry.SavedSnapshotOperationCleanup, telemetry.SavedSnapshotOutcomeSuccess)
		return
	}
	if errors.Is(err, pgx.ErrNoRows) {
		rowLog.Debug().Msg("saved snapshot delete already finalized")
		s.recordOutcome(ctx, snapshot, telemetry.SavedSnapshotOperationCleanup, telemetry.SavedSnapshotOutcomeSuccess)
		return
	}
	s.recordOutcome(ctx, snapshot, telemetry.SavedSnapshotOperationCleanup, telemetry.SavedSnapshotOutcomeRetry)
	s.logStoreError(err, "finalize stale saved snapshot delete")
	s.deferReconciliation(ctx, snapshot, db.SnapshotStatusDeleting, "finalize delete")
}

func (s *SavedSnapshotSupervisor) failCreating(ctx context.Context, snapshot db.Snapshot, reason string) {
	_, err := s.store.FailSavedSnapshot(ctx, db.FailSavedSnapshotParams{
		FailureReason: &reason,
		SnapshotID:    snapshot.ID,
		TeamID:        snapshot.TeamID,
	})
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			s.logStoreError(err, "fail stale saved snapshot capture")
		}
		s.deferReconciliation(ctx, snapshot, db.SnapshotStatusCreating, "terminalize failed capture")
	}
}

func (s *SavedSnapshotSupervisor) deleteArtifactsBestEffort(
	ctx context.Context,
	client vmdclient.SavedSnapshotClient,
	snapshot db.Snapshot,
) error {
	deleteCtx, cancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	defer cancel()
	err := client.DeleteSavedSnapshot(deleteCtx, snapshot.SandboxID.String(), snapshot.ID.String())
	if err == nil || status.Code(err) == codes.NotFound {
		s.recordOutcome(ctx, snapshot, telemetry.SavedSnapshotOperationCleanup, telemetry.SavedSnapshotOutcomeSuccess)
		return nil
	}
	outcome := telemetry.SavedSnapshotOutcomeError
	if transientSavedSnapshotError(err) {
		outcome = telemetry.SavedSnapshotOutcomeRetry
	}
	s.recordOutcome(ctx, snapshot, telemetry.SavedSnapshotOperationCleanup, outcome)
	return err
}

// cleanupFailedCapture makes artifact deletion and durable state agree. A
// failed row is written only after the host confirms that the artifact is
// gone. If host cleanup cannot complete now, the captured paths and sizes are
// moved to the deleting queue so the ordinary delete reconciler owns the
// retry and the source capture claim can be released safely.
func (s *SavedSnapshotSupervisor) cleanupFailedCapture(
	ctx context.Context,
	rowLog zerolog.Logger,
	client vmdclient.SavedSnapshotClient,
	snapshot db.Snapshot,
	artifacts vmdclient.SavedSnapshotArtifacts,
	metadata []byte,
	reason string,
) {
	if err := s.deleteArtifactsBestEffort(ctx, client, snapshot); err == nil {
		s.failCreating(ctx, snapshot, reason)
		return
	} else {
		rowLog.Warn().Err(vmdclient.SanitizeSavedSnapshotError(vmdclient.SavedSnapshotOperationDelete, err)).Msg("immediate cleanup of failed saved snapshot capture did not complete")
	}

	s.queueFailedCaptureCleanup(ctx, rowLog, snapshot, artifacts, metadata, reason)
}

// reconcileLostFinalize distinguishes a harmless multi-worker winner from a
// cancelled or otherwise invalidated capture. In particular, the artifact for
// a row another worker already made ready must never be deleted: idempotent
// capture means both workers are referring to the same files.
func (s *SavedSnapshotSupervisor) reconcileLostFinalize(
	ctx context.Context,
	rowLog zerolog.Logger,
	client vmdclient.SavedSnapshotClient,
	snapshot db.Snapshot,
	artifacts vmdclient.SavedSnapshotArtifacts,
	metadata []byte,
) {
	current, err := s.store.GetSavedSnapshot(ctx, db.GetSavedSnapshotParams{
		SnapshotID: snapshot.ID,
		TeamID:     snapshot.TeamID,
	})
	// unavailable is reachable only from ready, so it also proves that another
	// worker committed this shared artifact before a later health check changed
	// its availability. Preserve both states.
	if err == nil && (current.Status == db.SnapshotStatusReady || current.Status == db.SnapshotStatusUnavailable) {
		rowLog.Info().Msg("saved snapshot was finalized by another supervisor")
		return
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		// A read failure makes it impossible to distinguish a winning ready row
		// from a cancelled capture. Preserve the artifact until the next tick.
		s.logStoreError(err, "read saved snapshot after finalize race")
		s.deferReconciliation(ctx, snapshot, db.SnapshotStatusCreating, "read finalize winner")
		return
	}

	cleanupErr := s.deleteArtifactsBestEffort(ctx, client, snapshot)
	if cleanupErr != nil {
		rowLog.Warn().Err(vmdclient.SanitizeSavedSnapshotError(vmdclient.SavedSnapshotOperationDelete, cleanupErr)).Msg("cleanup after lost saved snapshot finalize did not complete")
		if err == nil && current.Status == db.SnapshotStatusCreating {
			s.queueFailedCaptureCleanup(ctx, rowLog, current, artifacts, metadata, "finalize_precondition_failed")
		} else if err == nil && current.Status == db.SnapshotStatusDeleting {
			s.deferReconciliation(ctx, current, db.SnapshotStatusDeleting, "cleanup concurrent delete")
		}
		// A deleting row is already a durable retry queue. A missing or other
		// terminal row cannot be transitioned by QueueSavedSnapshotCleanup.
		return
	}

	if err == nil && current.Status == db.SnapshotStatusCreating {
		s.failCreating(ctx, current, "finalize_precondition_failed")
	}
}

func (s *SavedSnapshotSupervisor) queueFailedCaptureCleanup(
	ctx context.Context,
	rowLog zerolog.Logger,
	snapshot db.Snapshot,
	artifacts vmdclient.SavedSnapshotArtifacts,
	metadata []byte,
	reason string,
) {
	if len(metadata) == 0 {
		var err error
		metadata, err = marshalReconciledArtifactMetadata(artifacts)
		if err != nil {
			rowLog.Error().Err(err).Msg("marshal failed saved snapshot artifacts for cleanup queue")
			s.recordOutcome(ctx, snapshot, telemetry.SavedSnapshotOperationCleanup, telemetry.SavedSnapshotOutcomeError)
			s.deferReconciliation(ctx, snapshot, db.SnapshotStatusCreating, "marshal cleanup metadata")
			return
		}
	}
	failureReason := reason
	logicalSize := artifacts.LogicalSizeBytes
	if logicalSize < 0 {
		logicalSize = 0
	}
	exclusiveSize := artifacts.ExclusiveSizeBytes
	if exclusiveSize < 0 {
		exclusiveSize = 0
	}
	_, err := s.store.QueueSavedSnapshotCleanup(ctx, db.QueueSavedSnapshotCleanupParams{
		SnapshotID:         snapshot.ID,
		TeamID:             snapshot.TeamID,
		Path:               artifacts.SnapshotPath,
		MemPath:            artifacts.MemPath,
		LogicalSizeBytes:   logicalSize,
		ManifestPath:       artifacts.ManifestPath,
		ArtifactMetadata:   metadata,
		ExclusiveSizeBytes: exclusiveSize,
		FailureReason:      &failureReason,
	})
	if err == nil {
		rowLog.Warn().Str("failure_reason", reason).Msg("queued failed saved snapshot artifacts for durable cleanup")
		s.recordOutcome(ctx, snapshot, telemetry.SavedSnapshotOperationCleanup, telemetry.SavedSnapshotOutcomeQueued)
		return
	}
	if errors.Is(err, pgx.ErrNoRows) {
		rowLog.Warn().Msg("failed saved snapshot changed state before cleanup could be queued")
		s.recordOutcome(ctx, snapshot, telemetry.SavedSnapshotOperationCleanup, telemetry.SavedSnapshotOutcomeRetry)
		s.deferReconciliation(ctx, snapshot, db.SnapshotStatusCreating, "queue failed capture cleanup")
		return
	}
	s.recordOutcome(ctx, snapshot, telemetry.SavedSnapshotOperationCleanup, telemetry.SavedSnapshotOutcomeError)
	s.logStoreError(err, "queue failed saved snapshot artifact cleanup")
	s.deferReconciliation(ctx, snapshot, db.SnapshotStatusCreating, "queue failed capture cleanup")
}

// deferReconciliation moves a failed attempt behind other stale work without
// creating a separate retry table. The SQL guard includes the observed
// timestamp, so a delayed worker cannot overwrite a newer worker's backoff or
// a concurrent lifecycle transition.
func (s *SavedSnapshotSupervisor) deferReconciliation(
	ctx context.Context,
	snapshot db.Snapshot,
	expectedStatus db.SnapshotStatus,
	operation string,
) {
	_, err := s.store.DeferSavedSnapshotReconciliation(ctx, db.DeferSavedSnapshotReconciliationParams{
		SnapshotID:        snapshot.ID,
		TeamID:            snapshot.TeamID,
		ExpectedStatus:    expectedStatus,
		ObservedUpdatedAt: snapshot.UpdatedAt,
	})
	if err != nil {
		s.logStoreError(err, "defer saved snapshot reconciliation after "+operation)
	}
}

func (s *SavedSnapshotSupervisor) logStoreError(err error, msg string) {
	if errors.Is(err, context.Canceled) {
		s.log.Debug().Err(err).Msg(msg)
		return
	}
	s.log.Error().Err(err).Msg(msg)
}

type reconciledArtifactMetadata struct {
	SchemaVersion            uint32 `json:"schema_version"`
	MemoryBasePath           string `json:"memory_base_path,omitempty"`
	DiskBasePath             string `json:"disk_base_path,omitempty"`
	DiskDeltaPath            string `json:"disk_delta_path,omitempty"`
	DiskOverlayPath          string `json:"disk_overlay_path,omitempty"`
	DiskFullPath             string `json:"disk_full_path,omitempty"`
	SourceLogicalSizeBytes   int64  `json:"source_logical_size_bytes"`
	SourceExclusiveSizeBytes int64  `json:"source_exclusive_size_bytes"`
}

func marshalReconciledArtifactMetadata(artifacts vmdclient.SavedSnapshotArtifacts) ([]byte, error) {
	return json.Marshal(reconciledArtifactMetadata{
		SchemaVersion:            artifacts.SchemaVersion,
		MemoryBasePath:           artifacts.MemoryBasePath,
		DiskBasePath:             artifacts.DiskBasePath,
		DiskDeltaPath:            artifacts.DiskDeltaPath,
		DiskOverlayPath:          artifacts.DiskOverlayPath,
		DiskFullPath:             artifacts.DiskFullPath,
		SourceLogicalSizeBytes:   artifacts.SourceLogicalSizeBytes,
		SourceExclusiveSizeBytes: artifacts.SourceExclusiveSizeBytes,
	})
}

func validateReconciledArtifacts(snapshot db.Snapshot, artifacts vmdclient.SavedSnapshotArtifacts) error {
	if artifacts.SchemaVersion == 0 || artifacts.ManifestPath == "" || artifacts.SnapshotPath == "" || artifacts.MemPath == "" {
		return errors.New("committed artifact paths are incomplete")
	}
	if len(artifacts.ManifestDigest) != 64 {
		return errors.New("manifest digest is missing or malformed")
	}
	if _, err := hex.DecodeString(artifacts.ManifestDigest); err != nil {
		return errors.New("manifest digest is not hex encoded")
	}
	if artifacts.ManifestDigest != strings.ToLower(artifacts.ManifestDigest) {
		return errors.New("manifest digest is not canonical lowercase hex")
	}
	if artifacts.LogicalSizeBytes < 0 || artifacts.ExclusiveSizeBytes < 0 ||
		artifacts.SourceLogicalSizeBytes < 0 || artifacts.SourceExclusiveSizeBytes < 0 {
		return errors.New("artifact sizes must be non-negative")
	}
	if artifacts.DiskDeltaPath == "" && artifacts.DiskOverlayPath == "" && artifacts.DiskFullPath == "" {
		return errors.New("disk artifact is missing")
	}
	if snapshot.VcpuCount == nil || snapshot.MemoryMib == nil || snapshot.DiskMib == nil {
		return errors.New("persisted resource shape is incomplete")
	}
	if artifacts.VCPU != uint32(*snapshot.VcpuCount) || artifacts.MemoryMiB != uint32(*snapshot.MemoryMib) || artifacts.DiskMiB != uint32(*snapshot.DiskMib) {
		return errors.New("resource shape mismatch")
	}
	expectedState := "running"
	if snapshot.SourceStatus.Valid && snapshot.SourceStatus.SandboxStatus == db.SandboxStatusPaused {
		expectedState = "paused"
	}
	if artifacts.SourceState != expectedState {
		return errors.New("source state mismatch")
	}
	return nil
}

func transientSavedSnapshotError(err error) bool {
	switch status.Code(err) {
	case codes.Canceled, codes.DeadlineExceeded, codes.Unavailable, codes.Aborted, codes.ResourceExhausted, codes.Unimplemented:
		return true
	default:
		return false
	}
}

func captureFailureReason(err error) string {
	switch status.Code(err) {
	case codes.NotFound, codes.DataLoss:
		return "source_artifacts_missing"
	case codes.FailedPrecondition:
		return "source_state_invalid"
	default:
		return "capture_failed"
	}
}

func savedSnapshotQuotaFailure(err error) string {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return ""
	}
	switch pgErr.Code {
	case "SS002", "SS003":
		return "too_many_snapshots"
	case "SS004", "SS005":
		return "snapshot_storage_quota_exceeded"
	default:
		return ""
	}
}
