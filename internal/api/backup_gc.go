package api

import (
	"context"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/backup"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/sentrylog"
)

const (
	backupGCInterval     = time.Hour
	backupGCBatch        = 200
	backupGCLeaseSeconds = 15 * 60
	// Generations with no database row (older than the records, or whose
	// report never landed) are found by walking the bucket, which is worth
	// doing far less often than the leased pass, and by one replica only.
	bucketWalkInterval = 24 * time.Hour
)

// StartBackupGC removes deleted sandboxes' and saved snapshots' backups
// from the bucket on a schedule. Every replica runs it; the database leases each generation,
// and the daily walk, to one of them. A nil BackupGC leaves the job off.
// Shared base images are never deleted here: a base is content-addressed
// and may be in use by a build the database has no record of.
func (h *Handlers) StartBackupGC(ctx context.Context) {
	if h.BackupGC == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(backupGCInterval)
		defer ticker.Stop()
		log.Info().Str("bucket", h.BackupGC.Identity()).Msg("backup gc started")
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sentrylog.RunSafe("backup-gc", func() {
					h.PurgeDeletedSandboxBackups(ctx)
					h.PurgeDeletedSnapshotBackups(ctx)
					h.WalkBucketBackups(ctx)
				})
			}
		}
	}()
}

// PurgeDeletedSandboxBackups deletes the objects of every generation that
// belongs to a deleted sandbox, in leased batches. A generation whose
// deletion fails keeps its lease until it expires and is retried then.
func (h *Handlers) PurgeDeletedSandboxBackups(ctx context.Context) int {
	bucket := h.BackupGC.Identity()
	return h.purgeClaimedGenerations(ctx, "sandbox_id", func() ([]claimedGeneration, error) {
		rows, err := h.DB.ClaimBackupGenerationsToPurge(ctx, db.ClaimBackupGenerationsToPurgeParams{
			Bucket: bucket, LeaseSeconds: backupGCLeaseSeconds, BatchSize: backupGCBatch,
		})
		claimed := make([]claimedGeneration, len(rows))
		for i, r := range rows {
			claimed[i] = claimedGeneration{r.ID, uuid.UUID(r.SandboxID.Bytes).String(), r.Generation, r.ClaimedAt}
		}
		return claimed, err
	}, func(owner, generation string) (int, error) {
		return backup.PurgeGeneration(ctx, h.BackupGC, owner, generation)
	})
}

// PurgeDeletedSnapshotBackups is PurgeDeletedSandboxBackups for the
// generations of deleted saved snapshots.
func (h *Handlers) PurgeDeletedSnapshotBackups(ctx context.Context) int {
	bucket := h.BackupGC.Identity()
	return h.purgeClaimedGenerations(ctx, "snapshot_id", func() ([]claimedGeneration, error) {
		rows, err := h.DB.ClaimSnapshotBackupGenerationsToPurge(ctx, db.ClaimSnapshotBackupGenerationsToPurgeParams{
			Bucket: bucket, LeaseSeconds: backupGCLeaseSeconds, BatchSize: backupGCBatch,
		})
		claimed := make([]claimedGeneration, len(rows))
		for i, r := range rows {
			claimed[i] = claimedGeneration{r.ID, uuid.UUID(r.SnapshotID.Bytes).String(), r.Generation, r.ClaimedAt}
		}
		return claimed, err
	}, func(owner, generation string) (int, error) {
		return backup.PurgeSnapshotGeneration(ctx, h.BackupGC, owner, generation)
	})
}

// claimedGeneration is one leased backup_generation row, whichever owner.
type claimedGeneration struct {
	id         uuid.UUID
	owner      string
	generation string
	claimedAt  pgtype.Timestamptz
}

// purgeClaimedGenerations claims batches, deletes each generation's objects
// and marks its row purged under the claim token, until a batch comes back
// short or makes no progress.
func (h *Handlers) purgeClaimedGenerations(ctx context.Context, ownerKey string,
	claim func() ([]claimedGeneration, error), purge func(owner, generation string) (int, error)) (purged int) {
	for ctx.Err() == nil {
		rows, err := claim()
		if err != nil {
			log.Warn().Err(err).Msg("backup gc: claim failed")
			return purged
		}
		done := 0
		for _, row := range rows {
			deleted, err := purge(row.owner, row.generation)
			if err != nil {
				log.Warn().Err(err).Str(ownerKey, row.owner).Str("generation", row.generation).
					Msg("backup gc: purge failed; will retry")
				continue
			}
			marked, err := h.DB.MarkBackupGenerationPurged(ctx, db.MarkBackupGenerationPurgedParams{ID: row.id, ClaimedAt: row.claimedAt})
			if err != nil {
				log.Warn().Err(err).Str("generation", row.generation).Msg("backup gc: mark purged failed")
				continue
			}
			if marked == 0 {
				// A report landed during the purge: the generation was uploaded
				// again and the next pass takes it.
				log.Info().Str(ownerKey, row.owner).Str("generation", row.generation).
					Msg("backup gc: generation re-uploaded during purge; left for the next pass")
				continue
			}
			done++
			log.Info().Str(ownerKey, row.owner).Str("generation", row.generation).
				Int("objects", deleted).Msg("backup gc: generation purged")
		}
		purged += done
		// A batch with no progress means the bucket or database is unwell;
		// the leases expire and the next pass retries.
		if len(rows) < backupGCBatch || done == 0 {
			return purged
		}
	}
	return purged
}

// WalkBucketBackups walks the bucket once a day, on whichever replica
// claims the walk, from one listing, and purges every generation of a
// sandbox the database says is deleted, row or no row. Ids the database
// does not know are left alone.
func (h *Handlers) WalkBucketBackups(ctx context.Context) (purged int) {
	bucket := h.BackupGC.Identity()
	claimed, err := h.DB.ClaimBackupWalk(ctx, db.ClaimBackupWalkParams{Bucket: bucket, IntervalSeconds: bucketWalkInterval.Seconds()})
	if err != nil {
		log.Warn().Err(err).Msg("backup gc: walk claim failed")
		return 0
	}
	if claimed == 0 {
		return 0
	}
	stored, err := backup.SandboxGenerations(ctx, h.BackupGC)
	if err != nil {
		log.Warn().Err(err).Msg("backup gc: bucket listing failed")
		return 0
	}
	ids := make([]uuid.UUID, 0, len(stored))
	for id := range stored {
		if parsed, err := uuid.Parse(id); err == nil {
			ids = append(ids, parsed)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	const batch = 1000
	for start := 0; start < len(ids); start += batch {
		if ctx.Err() != nil {
			return purged
		}
		deleted, err := h.DB.DeletedSandboxIDs(ctx, ids[start:min(start+batch, len(ids))])
		if err != nil {
			log.Warn().Err(err).Msg("backup gc: deleted sandbox lookup failed")
			return purged
		}
		for _, id := range deleted {
			sandboxID := id.String()
			for generation := range stored[sandboxID] {
				objects, err := backup.PurgeGeneration(ctx, h.BackupGC, sandboxID, generation)
				if err != nil {
					log.Warn().Err(err).Str("sandbox_id", sandboxID).Str("generation", generation).Msg("backup gc: orphan purge failed")
					return purged
				}
				purged++
				log.Info().Str("sandbox_id", sandboxID).Str("generation", generation).Int("objects", objects).
					Msg("backup gc: orphan generation purged")
			}
		}
	}
	log.Info().Int("sandboxes", len(ids)).Int("orphans_purged", purged).Msg("backup gc: bucket walk complete")
	return purged
}
