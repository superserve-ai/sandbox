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
	// Lock only owners present in this report. A host-wide lock here would make
	// a periodic inventory contend with unrelated pause/resume/destroy writes.
	if _, err := tx.Exec(ctx, `WITH supplied AS (SELECT kind,id FROM jsonb_to_recordset($3::jsonb) AS o(kind text,id uuid))
 SELECT s.id FROM sandbox s JOIN supplied o ON o.kind='sandbox' AND o.id=s.id
 WHERE s.host_id=$1 AND s.created_at<=$2 AND (s.destroyed_at IS NULL OR s.destroyed_at>$2)
 FOR NO KEY UPDATE`, hostID, at, payload); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `WITH supplied AS (SELECT kind,id FROM jsonb_to_recordset($3::jsonb) AS o(kind text,id uuid))
 SELECT s.id FROM sandbox_snapshot s JOIN supplied o ON o.kind='snapshot' AND o.id=s.id
 WHERE s.host_id=$1 AND s.ready_at<=$2 AND (s.deleted_at IS NULL OR s.deleted_at>$2)
 FOR NO KEY UPDATE`, hostID, at, payload); err != nil {
		return err
	}
	// Ownership comes exclusively from these rows. Host-supplied owner IDs are
	// references, not authority for team attribution or retention lifetime.
	var complete bool
	err = tx.QueryRow(ctx, `WITH expected AS (
  SELECT 'sandbox' kind,s.id FROM sandbox s WHERE s.host_id=$1 AND s.created_at<=$2
   AND (s.destroyed_at IS NULL OR s.destroyed_at>$2)
  UNION ALL
  SELECT 'snapshot',id FROM sandbox_snapshot WHERE host_id=$1 AND ready_at<=$2
   AND (deleted_at IS NULL OR deleted_at>$2)
 ), supplied AS (SELECT kind,id FROM jsonb_to_recordset($3::jsonb) AS o(kind text,id uuid))
 SELECT NOT EXISTS(SELECT 1 FROM expected e LEFT JOIN supplied s USING(kind,id) WHERE s.id IS NULL)
  AND (SELECT count(*) FROM expected)<=$4
  AND NOT EXISTS(SELECT 1 FROM retained_storage_interval WHERE host_id=$1 AND started_at>$2)`, hostID, at, payload, retainedstorage.MaxOwners).Scan(&complete)
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
  SELECT o.*,s.team_id,s.deleted_at FROM supplied o JOIN sandbox_snapshot s ON o.kind='snapshot' AND s.id=o.id
  WHERE s.host_id=$1 AND s.ready_at<=$2 AND (s.deleted_at IS NULL OR s.deleted_at>$2)
   AND feature_enabled('billing_metrics_write',s.team_id)
 ), moved AS (
  UPDATE retained_storage_interval old SET ended_at=$2
  FROM supplied moved_owner
  WHERE moved_owner.id=old.owner_id AND moved_owner.kind=old.owner_kind
   AND old.host_id<>$1 AND old.ended_at IS NULL AND old.started_at<$2
   AND (EXISTS (SELECT 1 FROM sandbox s WHERE old.owner_kind='sandbox' AND s.id=old.owner_id AND feature_enabled('billing_metrics_write',s.team_id))
     OR EXISTS (SELECT 1 FROM sandbox_snapshot s WHERE old.owner_kind='snapshot' AND s.id=old.owner_id AND feature_enabled('billing_metrics_write',s.team_id)))
  RETURNING old.id
 ), cutover AS (
  INSERT INTO retained_storage_cutover(host_id,team_id,started_at)
  SELECT DISTINCT $1,team_id,$2 FROM eligible ON CONFLICT DO NOTHING
 ), current AS MATERIALIZED (
  SELECT e.*,i.id interval_id,i.generation old_generation,i.extents old_extents
 FROM eligible e LEFT JOIN retained_storage_interval i ON i.host_id=$1 AND i.owner_kind=e.kind AND i.owner_id=e.id
   AND i.started_at<=$2 AND (i.ended_at IS NULL OR i.ended_at>$2)
 ), closed AS (
  UPDATE retained_storage_interval i SET ended_at=$2 FROM current c WHERE i.id=c.interval_id
   AND (c.old_generation IS DISTINCT FROM c.generation OR c.old_extents IS DISTINCT FROM c.extents)
  RETURNING i.id
 ) INSERT INTO retained_storage_interval(host_id,team_id,owner_kind,owner_id,generation,extents,started_at,ended_at)
 SELECT $1,c.team_id,c.kind,c.id,c.generation,c.extents,$2,c.lifetime_end FROM current c
 LEFT JOIN closed ON closed.id=c.interval_id
 WHERE c.interval_id IS NULL OR closed.id IS NOT NULL
 ON CONFLICT(host_id,owner_kind,owner_id,started_at) DO NOTHING`, hostID, at, payload)
	return err
}
