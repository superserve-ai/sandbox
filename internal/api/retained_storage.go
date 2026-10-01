package api

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/retainedstorage"
)

// applyRetainedStorage runs within the durable report's cursor transaction.
// A complete physical-address epoch is indivisible: splitting owners across
// chunks could deduplicate a recycled address against an earlier allocation.
func retainedStorageIncompleteError(reason string) error {
	// Keep the historical invalid-payload identity for direct receiver callers,
	// while the retained-specific marker takes precedence in processor
	// terminalization so the durable evidence remains settlement-blocking.
	return fmt.Errorf("%w: %w: %s", errStorageReportRetainedIncomplete, errStorageReportInvalidPayload, reason)
}

func applyRetainedStorage(ctx context.Context, tx pgx.Tx, hostID string, at time.Time, inv *retainedstorage.Inventory, reportIDs ...uuid.UUID) error {
	if err := inv.Validate(); err != nil {
		return retainedStorageIncompleteError(err.Error())
	}
	payload, err := json.Marshal(inv.Owners)
	if err != nil {
		return err
	}
	// Owner.Baseline is an additive nested envelope field. The SQL projections
	// below extract it explicitly so nullable legacy owners remain compatible
	// without dropping verified provenance from new reports.
	// A full-copy template owner has a required shared baseline.  Without the
	// verified path/generation object the observation is incomplete, not zero;
	// keep the durable report retryable so settlement retains its fence.
	var missingBaseline bool
	if err := tx.QueryRow(ctx, `WITH supplied AS (
  SELECT o.kind,o.id,o.baseline->>'path' AS baseline_path
  FROM jsonb_to_recordset($1::jsonb) AS o(kind text,id uuid,baseline jsonb)
)
SELECT EXISTS (
  SELECT 1 FROM supplied o JOIN sandbox s ON o.kind='sandbox' AND s.id=o.id
  WHERE s.template_id IS NOT NULL AND s.base_path IS NULL AND o.baseline_path IS NULL
)`, payload).Scan(&missingBaseline); err != nil {
		return err
	}
	if missingBaseline {
		return retainedStorageIncompleteError("full-copy baseline provenance is unavailable")
	}
	// Lock only owners whose contribution is new or changed. A host-wide lock
	// (or locking an unchanged fleet) would make a periodic inventory contend
	// with unrelated pause/resume/destroy writes.
	if _, err := tx.Exec(ctx, `WITH supplied AS (SELECT kind,id FROM jsonb_to_recordset($3::jsonb) AS o(kind text,id uuid))
 SELECT s.id FROM sandbox s JOIN supplied o ON o.kind='sandbox' AND o.id=s.id
			 WHERE s.host_id=$1 AND s.created_at<=$2 AND (s.destroyed_at IS NULL OR s.destroyed_at>$2)
			   AND NOT EXISTS (
				 SELECT 1 FROM retained_storage_interval i
				 JOIN jsonb_to_recordset($3::jsonb) AS current(kind text,id uuid,generation text,extents jsonb)
				   ON current.kind='sandbox' AND current.id=s.id
				 WHERE i.host_id=$1 AND i.owner_kind='sandbox' AND i.owner_id=s.id
				   AND i.started_at<=$2 AND (i.ended_at IS NULL OR i.ended_at>$2)
				   AND i.generation=current.generation AND i.extents=current.extents)
 FOR NO KEY UPDATE`, hostID, at, payload); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `WITH supplied AS (SELECT kind,id FROM jsonb_to_recordset($3::jsonb) AS o(kind text,id uuid))
	 SELECT s.id FROM sandbox_snapshot s JOIN supplied o ON o.kind='snapshot' AND o.id=s.id
			 WHERE s.host_id=$1 AND (s.status IN ('ready','creating','deleting') OR s.retention_ended_at>$2)
			   AND s.created_at<=$2 AND (LEAST(s.deleted_at,s.retention_ended_at) IS NULL OR LEAST(s.deleted_at,s.retention_ended_at)>$2)
			   AND NOT EXISTS (
				 SELECT 1 FROM retained_storage_interval i
				 JOIN jsonb_to_recordset($3::jsonb) AS current(kind text,id uuid,generation text,extents jsonb)
				   ON current.kind='snapshot' AND current.id=s.id
				 WHERE i.host_id=$1 AND i.owner_kind='snapshot' AND i.owner_id=s.id
				   AND i.started_at<=$2 AND (i.ended_at IS NULL OR i.ended_at>$2)
				   AND i.generation=current.generation AND i.extents=current.extents)
 FOR NO KEY UPDATE`, hostID, at, payload); err != nil {
		return err
	}
	// Try only after owner row locks: snapshot/fork creation may already hold
	// a source row shared. Keep this fence for creators using the older trigger.
	var creationFenced bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended('retained-storage-owner:' || $1, 0))`, hostID).Scan(&creationFenced); err != nil {
		return err
	}
	if !creationFenced {
		return fmt.Errorf("retained owner creation is in progress")
	}
	// Inserts bypassing an earlier report's exclusive fence still hold a pending
	// marker until commit/rollback. Inspect it without taking an exclusive lock
	// that would delay creation. The next statement sees committed owners; any
	// insert starting after this check is timestamped after the report receipt.
	if err := tx.QueryRow(ctx, `WITH marker AS (
 SELECT hashtextextended('retained-storage-owner-pending:' || $1, 0) key
 ) SELECT NOT EXISTS (
 SELECT 1 FROM pg_catalog.pg_locks l CROSS JOIN marker m
 WHERE l.locktype='advisory' AND l.mode='ShareLock' AND l.granted
   AND l.database=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())
   AND l.classid=((m.key >> 32) & 4294967295)::oid
   AND l.objid=(m.key & 4294967295)::oid AND l.objsubid=1
 )`, hostID).Scan(&creationFenced); err != nil {
		return err
	}
	if !creationFenced {
		return fmt.Errorf("retained owner creation is in progress")
	}
	// Ownership comes exclusively from these rows. Host-supplied owner IDs are
	// references, not authority for team attribution or retention lifetime.
	var complete bool
	err = tx.QueryRow(ctx, `WITH sandbox_candidates AS MATERIALIZED (
  SELECT 'sandbox' kind,s.id FROM sandbox s
  WHERE s.host_id=$1 AND s.created_at<=$2
    AND (s.destroyed_at IS NULL OR s.destroyed_at>$2)
    AND s.status <> 'failed'
  ORDER BY s.created_at,s.id
  LIMIT $4 + 1
 ), failed_sandbox_candidates AS MATERIALIZED (
  SELECT 'sandbox' kind,s.id FROM sandbox s
  WHERE s.host_id=$1 AND s.created_at<=$2 AND s.status='failed'
    AND (s.destroyed_at IS NULL OR s.destroyed_at>$2)
    AND (EXISTS (SELECT 1 FROM retained_storage_interval i WHERE i.owner_kind='sandbox' AND i.owner_id=s.id
           AND i.started_at<=$2 AND (i.ended_at IS NULL OR i.ended_at>$2))
      OR EXISTS (SELECT 1 FROM sandbox_storage_interval i WHERE i.sandbox_id=s.id
           AND i.started_at<=$2 AND (i.ended_at IS NULL OR i.ended_at>$2))
      OR EXISTS (SELECT 1 FROM retained_storage_measurement_obligation o WHERE o.owner_kind='sandbox' AND o.owner_id=s.id
           AND o.effective_at<=$2 AND (o.ended_at IS NULL OR o.ended_at>$2)))
  ORDER BY s.created_at,s.id
  LIMIT $4 + 1
 ), snapshot_candidates AS MATERIALIZED (
 SELECT 'snapshot' kind,s.id FROM sandbox_snapshot s
  WHERE s.host_id=$1 AND s.created_at<=$2
    AND (s.status IN ('ready','creating','deleting') OR s.retention_ended_at>$2)
    AND (LEAST(s.deleted_at,s.retention_ended_at) IS NULL OR LEAST(s.deleted_at,s.retention_ended_at)>$2)
  ORDER BY s.created_at,s.id
  LIMIT $4 + 1
 ), candidates AS (
  SELECT * FROM sandbox_candidates
  UNION ALL SELECT * FROM failed_sandbox_candidates
  UNION ALL SELECT * FROM snapshot_candidates
 ), expected AS MATERIALIZED (
  SELECT c.kind,c.id FROM candidates c
 ), supplied AS (SELECT kind,id FROM jsonb_to_recordset($3::jsonb) AS o(kind text,id uuid))
 SELECT NOT EXISTS(SELECT 1 FROM expected e LEFT JOIN supplied s USING(kind,id) WHERE s.id IS NULL)
  AND (SELECT count(*) FROM expected)<=$4
  -- A delayed report is stale if this owner was observed on any host after
  -- its receipt boundary. Checking only the reporting host lets an A→B→A
  -- reassignment reopen history while B's interval remains current.
  AND NOT EXISTS(
    SELECT 1 FROM retained_storage_interval i
    JOIN supplied o ON o.kind=i.owner_kind AND o.id=i.owner_id
    WHERE i.started_at>$2
  )
  AND NOT EXISTS(
    SELECT 1 FROM sandbox_storage_interval i
    JOIN supplied o ON o.kind='sandbox' AND o.id=i.sandbox_id
    WHERE i.started_at>$2
	 )`, hostID, at, payload, retainedstorage.MaxOwners).Scan(&complete)
	if err != nil {
		return err
	}
	if !complete {
		return retainedStorageIncompleteError("retained inventory is incomplete or superseded")
	}
	_, err = tx.Exec(ctx, `WITH supplied AS MATERIALIZED (
  SELECT o.kind,o.id,o.generation,o.extents,
         o.baseline->>'path' AS baseline_path,
         o.baseline->>'generation' AS baseline_generation,
         (o.baseline->>'allocated_bytes')::bigint AS baseline_allocated_bytes
  FROM jsonb_to_recordset($3::jsonb) AS o(kind text,id uuid,generation text,extents jsonb,baseline jsonb)
 ), eligible AS MATERIALIZED (
  SELECT o.*,s.team_id,s.destroyed_at lifetime_end FROM supplied o JOIN sandbox s ON o.kind='sandbox' AND s.id=o.id
  WHERE s.host_id=$1 AND s.created_at<=$2 AND (s.destroyed_at IS NULL OR s.destroyed_at>$2)
   AND feature_enabled('billing_metrics_write',s.team_id)
  UNION ALL
  SELECT o.*,s.team_id,LEAST(s.deleted_at,s.retention_ended_at) FROM supplied o JOIN sandbox_snapshot s ON o.kind='snapshot' AND s.id=o.id
  WHERE s.host_id=$1 AND (s.status IN ('ready','creating','deleting') OR s.retention_ended_at>$2)
   AND s.created_at<=$2 AND (LEAST(s.deleted_at,s.retention_ended_at) IS NULL OR LEAST(s.deleted_at,s.retention_ended_at)>$2)
   AND feature_enabled('billing_metrics_write',s.team_id)
 ), moved AS (
  UPDATE retained_storage_interval old SET ended_at=$2
  FROM eligible moved_owner
  WHERE moved_owner.id=old.owner_id AND moved_owner.kind=old.owner_kind
   AND old.host_id IS DISTINCT FROM $1 AND old.started_at<$2
   AND (old.ended_at IS NULL OR old.ended_at>$2)
  RETURNING old.id
 ), legacy_moved AS (
  UPDATE sandbox_storage_interval old SET ended_at=$2,end_reason='reassigned'
  FROM eligible moved_owner
  WHERE moved_owner.kind='sandbox' AND moved_owner.id=old.sandbox_id
   AND old.host_id IS DISTINCT FROM $1 AND old.started_at<$2
   AND (old.ended_at IS NULL OR old.ended_at>$2)
  RETURNING old.id
 ), cutover AS (
  INSERT INTO retained_storage_cutover(host_id,team_id,started_at)
  SELECT DISTINCT $1,team_id,$2 FROM eligible ON CONFLICT DO NOTHING
 ), current AS MATERIALIZED (
  SELECT e.*,i.id interval_id,i.generation old_generation,i.extents old_extents,i.started_at old_started_at,i.ended_at old_ended_at
 FROM eligible e LEFT JOIN retained_storage_interval i ON i.host_id=$1 AND i.owner_kind=e.kind AND i.owner_id=e.id
   AND i.started_at<=$2 AND (i.ended_at IS NULL OR i.ended_at>$2)
 ), closed AS (
  UPDATE retained_storage_interval i SET ended_at=$2 FROM current c WHERE i.id=c.interval_id
   AND c.old_started_at<$2
   AND (c.old_generation IS DISTINCT FROM c.generation OR c.old_extents IS DISTINCT FROM c.extents
        OR i.baseline_path IS DISTINCT FROM c.baseline_path OR i.baseline_generation IS DISTINCT FROM c.baseline_generation
        OR i.baseline_allocated_bytes IS DISTINCT FROM c.baseline_allocated_bytes)
  RETURNING i.id
 ), replaced AS (
  UPDATE retained_storage_interval i SET generation=c.generation,extents=c.extents,
      baseline_path=c.baseline_path,baseline_generation=c.baseline_generation,
      baseline_allocated_bytes=c.baseline_allocated_bytes,ended_at=LEAST(c.lifetime_end,c.old_ended_at)
  FROM current c WHERE i.id=c.interval_id AND c.old_started_at=$2
   AND (c.old_generation IS DISTINCT FROM c.generation OR c.old_extents IS DISTINCT FROM c.extents
        OR i.baseline_path IS DISTINCT FROM c.baseline_path OR i.baseline_generation IS DISTINCT FROM c.baseline_generation
        OR i.baseline_allocated_bytes IS DISTINCT FROM c.baseline_allocated_bytes)
  RETURNING i.id
 ) INSERT INTO retained_storage_interval(host_id,team_id,owner_kind,owner_id,generation,extents,started_at,ended_at,baseline_path,baseline_generation,baseline_allocated_bytes)
 SELECT $1,c.team_id,c.kind,c.id,c.generation,c.extents,$2,LEAST(c.lifetime_end,c.old_ended_at),
        c.baseline_path,c.baseline_generation,c.baseline_allocated_bytes FROM current c
 LEFT JOIN closed ON closed.id=c.interval_id
 WHERE c.interval_id IS NULL OR closed.id IS NOT NULL`, hostID, at, payload)
	if err != nil {
		return err
	}
	// Resolve only obligations covered by this complete, compatible receipt. The
	// report id is retained as immutable audit evidence when the processor has it;
	// direct unit callers use the zero UUID sentinel without changing authority.
	var reportID any = uuid.Nil
	if len(reportIDs) > 0 && reportIDs[0] != uuid.Nil {
		reportID = reportIDs[0]
	}
	if _, err = tx.Exec(ctx, `WITH supplied AS (
	  SELECT o.kind,o.id,COALESCE(s.team_id,ss.team_id) team_id
	  FROM jsonb_to_recordset($1::jsonb) AS o(kind text,id uuid)
	  LEFT JOIN sandbox s ON o.kind='sandbox' AND s.id=o.id
	  LEFT JOIN sandbox_snapshot ss ON o.kind='snapshot' AND ss.id=o.id
	)
UPDATE retained_storage_measurement_obligation o
SET resolved_at=$2,resolution_report_id=$3
FROM supplied s
WHERE s.kind=o.owner_kind AND s.id=o.owner_id AND s.team_id=o.team_id AND o.host_id=$4
  AND o.effective_at<=$2 AND (o.ended_at IS NULL OR o.ended_at>$2)
  AND o.resolved_at IS NULL`, payload, at, reportID, hostID); err != nil {
		return err
	}
	// Bind verified baseline evidence to every legacy stay that was active at
	// this receipt. This is additive history; later template metadata cannot
	// rewrite the mapping.
	_, err = tx.Exec(ctx, `WITH supplied AS MATERIALIZED (
  SELECT o.kind,o.id,o.generation,o.extents,
         o.baseline->>'path' AS baseline_path,
         o.baseline->>'generation' AS baseline_generation,
         (o.baseline->>'allocated_bytes')::bigint AS baseline_allocated_bytes
  FROM jsonb_to_recordset($3::jsonb) AS o(kind text,id uuid,generation text,extents jsonb,baseline jsonb)
), eligible AS (
  SELECT o.*,s.team_id,s.host_id FROM supplied o JOIN sandbox s ON o.kind='sandbox' AND s.id=o.id
  WHERE o.baseline_path IS NOT NULL AND s.host_id=$1 AND s.created_at<=$2
), stays AS MATERIALIZED (
  SELECT i.sandbox_id,i.team_id,i.host_id,i.started_at,i.ended_at,e.baseline_path,e.baseline_generation,e.baseline_allocated_bytes
  FROM sandbox_storage_interval i JOIN eligible e ON e.id=i.sandbox_id AND e.team_id=i.team_id AND e.host_id=i.host_id
  WHERE i.started_at<=$2 AND (i.ended_at IS NULL OR i.ended_at>$2)
), closed AS (
 UPDATE sandbox_storage_baseline b SET ended_at=$2
 FROM stays s
 WHERE b.sandbox_id=s.sandbox_id AND b.team_id=s.team_id AND b.host_id=s.host_id
   AND b.effective_at<$2 AND (b.ended_at IS NULL OR b.ended_at>$2)
 RETURNING b.id
)
INSERT INTO sandbox_storage_baseline(sandbox_id,team_id,host_id,path,generation,allocated_bytes,observed_at,effective_at,started_at,ended_at,receipt_id)
SELECT sandbox_id,team_id,host_id,baseline_path,baseline_generation,baseline_allocated_bytes,$2,$2,started_at,ended_at,$4
FROM stays CROSS JOIN (SELECT count(*) FROM closed) fence
ON CONFLICT (sandbox_id,host_id,effective_at,receipt_id) DO UPDATE
 SET ended_at=EXCLUDED.ended_at`, hostID, at, payload, reportID)
	return err
}
