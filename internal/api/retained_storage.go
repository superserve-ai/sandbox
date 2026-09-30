package api

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/retainedstorage"
)

// applyRetainedStorage runs within the durable report's cursor transaction.
// A complete physical-address epoch is indivisible: splitting owners across
// chunks could deduplicate a recycled address against an earlier allocation.
func applyRetainedStorage(ctx context.Context, tx pgx.Tx, hostID string, at time.Time, inv *retainedstorage.Inventory) error {
	if err := inv.Validate(); err != nil {
		return fmt.Errorf("%w: %v", errStorageReportInvalidPayload, err)
	}
	payload, err := json.Marshal(inv.Owners)
	if err != nil {
		return err
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
	err = tx.QueryRow(ctx, `WITH expected AS (
  SELECT 'sandbox' kind,s.id FROM sandbox s WHERE s.host_id=$1 AND s.created_at<=$2
   AND (s.status <> 'failed'
    OR EXISTS(SELECT 1 FROM retained_storage_interval i WHERE i.owner_kind='sandbox' AND i.owner_id=s.id
      AND i.started_at<=$2 AND (i.ended_at IS NULL OR i.ended_at>$2))
    OR EXISTS(SELECT 1 FROM sandbox_storage_interval i WHERE i.sandbox_id=s.id
      AND i.started_at<=$2 AND (i.ended_at IS NULL OR i.ended_at>$2)))
   AND (s.destroyed_at IS NULL OR s.destroyed_at>$2)
 UNION ALL
  SELECT 'snapshot',id FROM sandbox_snapshot WHERE host_id=$1 AND (status IN ('ready','creating','deleting') OR retention_ended_at>$2) AND created_at<=$2
   AND (LEAST(deleted_at,retention_ended_at) IS NULL OR LEAST(deleted_at,retention_ended_at)>$2)
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
		return fmt.Errorf("%w: retained inventory is incomplete or superseded", errStorageReportInvalidPayload)
	}
	_, err = tx.Exec(ctx, `WITH supplied AS MATERIALIZED (
  SELECT * FROM jsonb_to_recordset($3::jsonb) AS o(kind text,id uuid,generation text,extents jsonb)
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
   AND (c.old_generation IS DISTINCT FROM c.generation OR c.old_extents IS DISTINCT FROM c.extents)
  RETURNING i.id
 ), replaced AS (
  UPDATE retained_storage_interval i SET generation=c.generation,extents=c.extents,ended_at=LEAST(c.lifetime_end,c.old_ended_at)
  FROM current c WHERE i.id=c.interval_id AND c.old_started_at=$2
   AND (c.old_generation IS DISTINCT FROM c.generation OR c.old_extents IS DISTINCT FROM c.extents)
  RETURNING i.id
 ) INSERT INTO retained_storage_interval(host_id,team_id,owner_kind,owner_id,generation,extents,started_at,ended_at)
 SELECT $1,c.team_id,c.kind,c.id,c.generation,c.extents,$2,LEAST(c.lifetime_end,c.old_ended_at) FROM current c
 LEFT JOIN closed ON closed.id=c.interval_id
 WHERE c.interval_id IS NULL OR closed.id IS NOT NULL`, hostID, at, payload)
	return err
}
