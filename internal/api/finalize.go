package api

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/superserve-ai/sandbox/internal/db"
)

// isNoConflictTarget reports SQLSTATE 42P10, PostgreSQL's "there is no
// unique or exclusion constraint matching the ON CONFLICT specification".
func isNoConflictTarget(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42P10"
}

// finalizePause routes a pause finalize to whichever mode the schema is in.
// While the legacy one-snapshot-per-sandbox unique index exists, rolling
// writers must keep upserting against it (with the generation counter
// advancing in place); once the contract phase drops the index, finalizes
// insert real generation rows and history begins, with no deploy needed.
//
// The probe and the statement are not atomic: the contract migration can
// drop the index between them, in which case the legacy upsert fails with
// SQLSTATE 42P10 (no constraint matching the ON CONFLICT specification).
// That exact error means "the flip happened under us" and falls through to
// the generation insert, so no finalize is lost to the transition.
//
// Contract-phase precondition, enforced by rollout order not by this code:
// dropping the index is only safe once vmd stages every pause's artifacts
// under per-generation paths. Until then, history rows would share the
// per-VM vmstate/mem paths that each pause overwrites in place, and every
// generation but the newest would describe bytes that no longer exist.
func (h *Handlers) finalizePause(ctx context.Context, params db.FinalizePauseParams) (uuid.UUID, error) {
	legacy, err := h.DB.HasLegacySnapshotUnique(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	if legacy {
		snapID, err := h.DB.FinalizePause(ctx, params)
		if err == nil || !isNoConflictTarget(err) {
			return snapID, err
		}
		// The index dropped between the probe and the statement.
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
