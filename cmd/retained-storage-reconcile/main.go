// Command retained-storage-reconcile repairs legacy paused VM disk dependency
// metadata during a VMD maintenance window. It never publishes storage reports.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/hostidentity"
	"github.com/superserve-ai/sandbox/internal/retainedstorage"
	"github.com/superserve-ai/sandbox/internal/vm"
)

func main() { os.Exit(run()) }

func run() int {
	apply := flag.Bool("apply", false, "persist verified disk dependencies (default: dry run)")
	host := flag.String("host-id", "", "host ID from the local installation identity")
	identityPath := flag.String("identity", "/etc/sandbox/host-identity.json", "installation identity file")
	state := flag.String("state", "", "existing VMD_STATE_PATH")
	runDir := flag.String("run-dir", "", "VMD run directory")
	snapshotDir := flag.String("snapshot-dir", "", "VMD snapshot directory")
	flag.Parse()
	if *host == "" || *state == "" || *runDir == "" || *snapshotDir == "" || os.Getenv("DATABASE_URL") == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "--host-id, --state, --run-dir, --snapshot-dir and read-only DATABASE_URL are required")
		return 1
	}
	identity, err := hostidentity.Load(*identityPath, *host, hostidentity.Metadata)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	refs, snapshotIDs, err := creationReferences(ctx, identity)
	if err != nil {
		// Connection errors can contain credentials; do not echo them.
		fmt.Fprintln(os.Stderr, "cannot read authoritative creation references; check database access and host incarnation")
		return 1
	}
	observedAt := time.Now().UTC()
	result, err := vm.ReconcileRetainedStorage(ctx, *state, *runDir, *snapshotDir, *host, refs, snapshotIDs, *apply)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report := struct {
		HostID        string    `json:"host_id"`
		IncarnationID string    `json:"incarnation_id"`
		ObservedAt    time.Time `json:"references_observed_at"`
		Source        string    `json:"source"`
		vm.RetainedReconcileResult
	}{*host, identity.IncarnationID, observedAt, "control-plane sandbox creation columns and retained snapshot IDs; host incarnation verified", result}
	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, "write reconciliation receipt:", err)
		return 1
	}
	if *apply && !result.HostReady {
		return 2
	}
	for _, receipt := range result.Receipts {
		if receipt.Status == "unresolved" {
			return 2
		}
	}
	return 0
}

func creationReferences(ctx context.Context, identity hostidentity.Identity) ([]vm.RetainedCreationReference, []string, error) {
	conn, err := pgx.Connect(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close(ctx)
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback(ctx)
	var host string
	if err := tx.QueryRow(ctx, `SELECT id FROM host WHERE id=$1 AND incarnation_id=$2`, identity.HostID, identity.IncarnationID).Scan(&host); err != nil {
		return nil, nil, err
	}
	rows, err := tx.Query(ctx, `SELECT s.id::text, s.host_id, s.created_at,
		COALESCE(snapshot_path,''), COALESCE(mem_path,''), COALESCE(base_path,''), COALESCE(delta_path,'')
		FROM sandbox s WHERE s.host_id=$1 AND s.destroyed_at IS NULL
		  AND (s.status <> 'failed'
		    OR EXISTS (SELECT 1 FROM retained_storage_interval i WHERE i.owner_kind='sandbox' AND i.owner_id=s.id AND i.ended_at IS NULL)
		    OR EXISTS (SELECT 1 FROM sandbox_storage_interval i WHERE i.sandbox_id=s.id AND i.ended_at IS NULL))
		ORDER BY s.id LIMIT $2`, host, retainedstorage.MaxOwners+1)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	refs := []vm.RetainedCreationReference{}
	for rows.Next() {
		var ref vm.RetainedCreationReference
		if err := rows.Scan(&ref.ID, &ref.HostID, &ref.CreatedAt, &ref.SnapshotPath, &ref.MemPath, &ref.BasePath, &ref.DeltaPath); err != nil {
			return nil, nil, err
		}
		refs = append(refs, ref)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	if len(refs) > retainedstorage.MaxOwners {
		return nil, nil, fmt.Errorf("creation reference budget exceeded")
	}
	rows, err = tx.Query(ctx, `SELECT id::text FROM sandbox_snapshot
		WHERE host_id=$1 AND status IN ('ready','creating','deleting')
		AND created_at<=CURRENT_TIMESTAMP AND (deleted_at IS NULL OR deleted_at>CURRENT_TIMESTAMP)
		ORDER BY id LIMIT $2`, host, retainedstorage.MaxOwners-len(refs)+1)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	snapshotIDs := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, nil, err
		}
		snapshotIDs = append(snapshotIDs, id)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	if len(refs)+len(snapshotIDs) > retainedstorage.MaxOwners {
		return nil, nil, fmt.Errorf("retained owner reference budget exceeded")
	}
	return refs, snapshotIDs, tx.Commit(ctx)
}
