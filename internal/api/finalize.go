package api

import (
	"context"

	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/db"
)

// finalizePause routes a pause finalize to whichever mode the schema is in.
// While the legacy one-snapshot-per-sandbox unique index exists, rolling
// writers must keep upserting against it (with the generation counter
// advancing in place); once the contract phase drops the index, finalizes
// insert real generation rows and history begins, with no deploy needed.
// The probe is one cheap catalog lookup per finalize, and pauses are
// low-rate, so probing per call keeps the flip race-free.
func (h *Handlers) finalizePause(ctx context.Context, params db.FinalizePauseParams) (uuid.UUID, error) {
	legacy, err := h.DB.HasLegacySnapshotUnique(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	if legacy {
		return h.DB.FinalizePause(ctx, params)
	}
	return h.DB.FinalizePauseGeneration(ctx, db.FinalizePauseGenerationParams{
		ID:                params.ID,
		TeamID:            params.TeamID,
		Path:              params.Path,
		MemPath:           params.MemPath,
		SizeBytes:         params.SizeBytes,
		Trigger:           params.Trigger,
		ManifestFileNames: params.ManifestFileNames,
		ManifestPaths:     params.ManifestPaths,
		ManifestSizes:     params.ManifestSizes,
		ManifestDigests:   params.ManifestDigests,
		ManifestBasePaths: params.ManifestBasePaths,
	})
}
