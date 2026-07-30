package api

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

// recordSnapshotManifest upserts a pause's per-file integrity manifest for a
// snapshot row. Best-effort: the pause's durability does not depend on the
// manifest landing (an entry that fails to write is surfaced by coverage
// monitoring as a snapshot with an incomplete manifest), so failures are
// logged, never propagated to the pause path.
func recordSnapshotManifest(ctx context.Context, q *db.Queries, snapshotID uuid.UUID, manifest []vmdclient.ManifestEntry) {
	for _, e := range manifest {
		var basePath *string
		if e.BasePath != "" {
			bp := e.BasePath
			basePath = &bp
		}
		if err := q.ReplaceSnapshotManifestEntry(ctx, db.ReplaceSnapshotManifestEntryParams{
			SnapshotID: pgtype.UUID{Bytes: snapshotID, Valid: true},
			FileName:   e.FileName,
			Path:       e.Path,
			SizeBytes:  e.SizeBytes,
			Sha256:     e.SHA256,
			BasePath:   basePath,
		}); err != nil {
			log.Error().Err(err).
				Str("snapshot_id", snapshotID.String()).
				Str("file", e.FileName).
				Msg("record snapshot manifest entry failed")
		}
	}
}

// manifestTotalBytes sums entry sizes; recorded as snapshot.size_bytes so the
// DB finally carries real sizes instead of zeros.
func manifestTotalBytes(manifest []vmdclient.ManifestEntry) int64 {
	var total int64
	for _, e := range manifest {
		total += e.SizeBytes
	}
	return total
}
