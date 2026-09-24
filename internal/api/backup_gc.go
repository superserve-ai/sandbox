package api

import (
	"context"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/backup"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/sentrylog"
)

const (
	backupGCInterval     = time.Hour
	backupGCBatch        = 200
	backupGCLeaseSeconds = 15 * 60
	// Hosts keep a base's verification for 14 days and skip re-uploading it
	// within that window, so a base must outlive its last reference by as
	// much, with a day on top for host clocks that run behind.
	sharedBaseGrace = 15 * 24 * time.Hour
	// Generations with no database row (older than the records, or whose
	// report never landed) are found by walking the bucket, which is worth
	// doing far less often than the leased pass, and by one replica only.
	bucketWalkInterval = 24 * time.Hour
)

// StartBackupGC removes deleted sandboxes' backups from the bucket on a
// schedule. Every replica runs it; the database leases each generation to
// one of them. A nil BackupGC leaves the job off.
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
					// Bases are only reaped against a listing taken just now: a
					// generation that lands unreported later is unknown until
					// the next walk, and must not meet a reaper working from an
					// older picture.
					if unrecorded, walked := h.WalkBucketBackups(ctx); walked {
						h.ReapUnreferencedBases(ctx, unrecorded)
					}
				})
			}
		}
	}()
}

// PurgeDeletedSandboxBackups deletes the objects of every generation that
// belongs to a deleted sandbox, in leased batches. A generation whose
// deletion fails keeps its lease until it expires and is retried then.
func (h *Handlers) PurgeDeletedSandboxBackups(ctx context.Context) (purged int) {
	bucket := h.BackupGC.Identity()
	for ctx.Err() == nil {
		rows, err := h.DB.ClaimBackupGenerationsToPurge(ctx, db.ClaimBackupGenerationsToPurgeParams{
			Bucket: bucket, LeaseSeconds: backupGCLeaseSeconds, BatchSize: backupGCBatch,
		})
		if err != nil {
			log.Warn().Err(err).Msg("backup gc: claim failed")
			return purged
		}
		done := 0
		for _, row := range rows {
			sandboxID := uuid.UUID(row.SandboxID.Bytes).String()
			deleted, err := backup.PurgeGeneration(ctx, h.BackupGC, sandboxID, row.Generation)
			if err != nil {
				log.Warn().Err(err).Str("sandbox_id", sandboxID).Str("generation", row.Generation).
					Msg("backup gc: purge failed; will retry")
				continue
			}
			marked, err := h.DB.MarkBackupGenerationPurged(ctx, db.MarkBackupGenerationPurgedParams{ID: row.ID, ClaimedAt: row.ClaimedAt})
			if err != nil {
				log.Warn().Err(err).Str("generation", row.Generation).Msg("backup gc: mark purged failed")
				continue
			}
			if marked == 0 {
				// A report landed during the purge: the generation was uploaded
				// again and the next pass takes it.
				log.Info().Str("sandbox_id", sandboxID).Str("generation", row.Generation).
					Msg("backup gc: generation re-uploaded during purge; left for the next pass")
				continue
			}
			done++
			log.Info().Str("sandbox_id", sandboxID).Str("generation", row.Generation).
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
// claims the walk, from one listing. Every generation of a sandbox the
// database says is deleted is purged, row or no row. For any other
// sandbox, a complete generation the database has no row for (its host was
// lost before the report landed) still restores, so the bases its manifest
// names are returned for the reaper. Ids the database does not know are
// left alone. walked is false when the walk was not this replica's to take
// or did not complete.
func (h *Handlers) WalkBucketBackups(ctx context.Context) (unrecordedBases map[string]bool, walked bool) {
	bucket := h.BackupGC.Identity()
	claimed, err := h.DB.ClaimBackupWalk(ctx, db.ClaimBackupWalkParams{Bucket: bucket, IntervalSeconds: bucketWalkInterval.Seconds()})
	if err != nil {
		log.Warn().Err(err).Msg("backup gc: walk claim failed")
		return nil, false
	}
	if claimed == 0 {
		return nil, false
	}
	recorded, err := h.DB.RecordedGenerations(ctx, bucket)
	if err != nil {
		log.Warn().Err(err).Msg("backup gc: recorded generations query failed")
		return nil, false
	}
	known := make(map[string]bool, len(recorded))
	for _, r := range recorded {
		known[uuid.UUID(r.SandboxID.Bytes).String()+"/"+r.Generation] = true
	}
	stored, err := backup.SandboxGenerations(ctx, h.BackupGC)
	if err != nil {
		log.Warn().Err(err).Msg("backup gc: bucket listing failed")
		return nil, false
	}
	ids := make([]uuid.UUID, 0, len(stored))
	for id := range stored {
		if parsed, err := uuid.Parse(id); err == nil {
			ids = append(ids, parsed)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	unrecordedBases = map[string]bool{}
	purged := 0
	const batch = 1000
	for start := 0; start < len(ids); start += batch {
		if ctx.Err() != nil {
			return nil, false
		}
		candidates := ids[start:min(start+batch, len(ids))]
		deletedRows, err := h.DB.DeletedSandboxIDs(ctx, candidates)
		if err != nil {
			log.Warn().Err(err).Msg("backup gc: deleted sandbox lookup failed")
			return nil, false
		}
		deleted := make(map[uuid.UUID]bool, len(deletedRows))
		for _, id := range deletedRows {
			deleted[id] = true
		}
		for _, id := range candidates {
			sandboxID := id.String()
			for generation, complete := range stored[sandboxID] {
				if deleted[id] {
					objects, err := backup.PurgeGeneration(ctx, h.BackupGC, sandboxID, generation)
					if err != nil {
						log.Warn().Err(err).Str("sandbox_id", sandboxID).Str("generation", generation).Msg("backup gc: orphan purge failed")
						return nil, false
					}
					purged++
					log.Info().Str("sandbox_id", sandboxID).Str("generation", generation).Int("objects", objects).
						Msg("backup gc: orphan generation purged")
					continue
				}
				if !complete || known[sandboxID+"/"+generation] {
					continue
				}
				digests, err := backup.ManifestBaseDigests(ctx, h.BackupGC, sandboxID, generation)
				if err != nil {
					log.Warn().Err(err).Str("sandbox_id", sandboxID).Str("generation", generation).Msg("backup gc: unrecorded manifest read failed")
					return nil, false
				}
				for _, sha := range digests {
					unrecordedBases[sha] = true
				}
			}
		}
	}
	log.Info().Int("sandboxes", len(ids)).Int("unrecorded_bases", len(unrecordedBases)).Int("orphans_purged", purged).
		Msg("backup gc: bucket walk complete")
	return unrecordedBases, true
}

// ReapUnreferencedBases deletes shared base objects nothing can need any
// more. A base is kept while a restorable or recently reported generation
// names it, while an unrecorded complete generation seen by the walk just
// taken names it, while the base image it was recorded for is still used
// by a live sandbox or an existing template build (their next pause names
// it, possibly before any row does), when the database has no record of
// which base image it belongs to, when any of its objects is younger than
// the grace period, and when it predates the database's records.
func (h *Handlers) ReapUnreferencedBases(ctx context.Context, unrecorded map[string]bool) (reaped int) {
	bucket := h.BackupGC.Identity()
	recordedSince, err := h.DB.OldestRecordedBackup(ctx, bucket)
	if err != nil {
		return 0
	}
	referenced, err := h.DB.ReferencedSharedBases(ctx, db.ReferencedSharedBasesParams{Bucket: bucket, GraceSeconds: sharedBaseGrace.Seconds()})
	if err != nil {
		log.Warn().Err(err).Msg("backup gc: referenced bases query failed")
		return 0
	}
	needed := make(map[string]bool, len(referenced)+len(unrecorded))
	for _, sha := range referenced {
		needed[sha] = true
	}
	for sha := range unrecorded {
		needed[sha] = true
	}
	provenance, err := h.DB.RecordedSharedBasePaths(ctx, bucket)
	if err != nil {
		log.Warn().Err(err).Msg("backup gc: base provenance query failed")
		return 0
	}
	imageOf := map[string][]string{}
	for _, row := range provenance {
		imageOf[row.Sha256] = append(imageOf[row.Sha256], row.BasePath)
	}
	inUsePaths, err := h.DB.InUseBasePaths(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("backup gc: in-use base paths query failed")
		return 0
	}
	inUse := make(map[string]bool, len(inUsePaths))
	for _, path := range inUsePaths {
		inUse[path] = true
	}
	bases, err := backup.SharedBases(ctx, h.BackupGC)
	if err != nil {
		log.Warn().Err(err).Msg("backup gc: list shared bases failed")
		return 0
	}
	youngestAllowed := time.Now().Add(-sharedBaseGrace)
	for sha, objects := range bases {
		if needed[sha] || len(imageOf[sha]) == 0 {
			continue
		}
		stillUsed := false
		for _, path := range imageOf[sha] {
			stillUsed = stillUsed || inUse[path]
		}
		if stillUsed {
			continue
		}
		oldest, newest := objects[0].Created, objects[0].Created
		for _, obj := range objects[1:] {
			if obj.Created.Before(oldest) {
				oldest = obj.Created
			}
			if obj.Created.After(newest) {
				newest = obj.Created
			}
		}
		if oldest.Before(recordedSince) || newest.After(youngestAllowed) {
			continue
		}
		for _, object := range objects {
			if err := h.BackupGC.Delete(ctx, object.Name); err != nil {
				log.Warn().Err(err).Str("object", object.Name).Msg("backup gc: base delete failed")
				return reaped
			}
			reaped++
			log.Info().Str("object", object.Name).Msg("backup gc: shared base reaped")
		}
	}
	return reaped
}
