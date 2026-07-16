package api

import (
	"context"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

// recordSandboxWritableLayerUsage reconciles the full persisted source after a
// VM has paused. The database atomically retires sealed generations whose only
// remaining reference is this source before recording the full-inode result,
// so extents made exclusive by final-clone deletion are not counted twice. It
// is deliberately best-effort and shadow-only: lifecycle correctness must not
// be rolled back because accounting telemetry is unavailable during a rolling
// VMD deployment.
func (h *Handlers) recordSandboxWritableLayerUsage(ctx context.Context, vmd vmdclient.Client, sandboxID, teamID uuid.UUID) {
	usageClient, ok := vmd.(vmdclient.SavedSnapshotClient)
	if !ok {
		return
	}
	// Use a self-contained deadline. Callers deliberately create a fresh DB
	// finalize context after this returns, so a slow shadow-only RPC cannot
	// consume the lifecycle transition's commit budget.
	measureCtx, cancel := context.WithTimeout(ctx, asyncTimeout)
	defer cancel()
	logical, exclusive, err := usageClient.MeasureSandboxWritableLayer(measureCtx, sandboxID.String())
	if err != nil {
		if status.Code(err) != codes.Unimplemented {
			log.Warn().Err(vmdclient.SanitizeSavedSnapshotError(vmdclient.SavedSnapshotOperationWritableLayerMeasurement, err)).Str("sandbox_id", sandboxID.String()).Msg("measure sandbox writable layer for shadow accounting")
		}
		return
	}
	if logical < 0 || exclusive < 0 {
		log.Error().Int64("logical_bytes", logical).Int64("exclusive_bytes", exclusive).
			Str("sandbox_id", sandboxID.String()).Msg("VMD returned invalid writable-layer usage")
		return
	}
	if _, err := h.DB.RecordSandboxWritableLayerUsage(measureCtx, db.RecordSandboxWritableLayerUsageParams{
		LogicalSizeBytes:   logical,
		ExclusiveSizeBytes: exclusive,
		SandboxID:          sandboxID,
		TeamID:             teamID,
	}); err != nil {
		log.Warn().Err(err).Str("sandbox_id", sandboxID.String()).Msg("persist sandbox writable-layer shadow usage")
	}
}
