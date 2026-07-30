package api

import (
	"context"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

// pauseManifestFiles is the complete artifact set a pause is expected to
// hash. A manifest missing any of these is partial: usable for per-file
// verification, but not a trustworthy total for snapshot.size_bytes.
var pauseManifestFiles = []string{"vmstate.snap", "rootfs.ext4"}

// recordSnapshotManifest replaces a snapshot row's per-file integrity
// manifest with this pause's set, atomically: stale rows from a previous
// pause never survive a partial re-hash looking current. Best-effort: the
// pause's durability does not depend on the manifest landing (a missing or
// partial manifest is surfaced by coverage monitoring), so failures are
// logged, never propagated to the pause path.
func recordSnapshotManifest(ctx context.Context, q *db.Queries, snapshotID uuid.UUID, manifest []vmdclient.ManifestEntry) {
	params := db.ReplaceSnapshotManifestParams{
		SnapshotID: snapshotID,
	}
	for _, e := range manifest {
		params.FileNames = append(params.FileNames, e.FileName)
		params.Paths = append(params.Paths, e.Path)
		params.Sizes = append(params.Sizes, e.SizeBytes)
		params.Digests = append(params.Digests, e.SHA256)
		params.BasePaths = append(params.BasePaths, e.BasePath)
	}
	if err := q.ReplaceSnapshotManifest(ctx, params); err != nil {
		log.Error().Err(err).
			Str("snapshot_id", snapshotID.String()).
			Int("files", len(manifest)).
			Msg("replace snapshot manifest failed")
	}
}

// manifestCompleteBytes sums entry sizes only when the manifest covers the
// full expected pause set. A partial manifest returns 0 so FinalizePause
// keeps the previously recorded size (its upsert ignores non-positive
// sizes) instead of publishing a partial sum as the snapshot's footprint.
func manifestCompleteBytes(manifest []vmdclient.ManifestEntry) int64 {
	var total int64
	seen := make(map[string]bool, len(manifest))
	for _, e := range manifest {
		seen[e.FileName] = true
		total += e.SizeBytes
	}
	for _, name := range pauseManifestFiles {
		if !seen[name] {
			return 0
		}
	}
	return total
}
