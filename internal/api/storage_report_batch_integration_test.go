//go:build integration

package api

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func newStorageBatchFixture(t *testing.T, n int) storageLeaseFixture {
	t.Helper()
	f := newStorageLeaseFixture(t)
	f.measurements = storageBatchMeasurements(n)
	f.measurements[0].SandboxID = f.sandboxID.String()
	payload, err := json.Marshal(f.measurements)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Exec(t.Context(), `INSERT INTO sandbox(id,team_id,host_id,created_at)
 SELECT (m->>'sandbox_id')::uuid,$2,$3,$4 FROM jsonb_array_elements($1::jsonb) m ON CONFLICT DO NOTHING`, payload, uuid.New(), f.hostID, f.receivedAt.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Exec(t.Context(), `UPDATE host_storage_report SET payload=$1,state='pending',next_measurement_index=0,processing_generation=0`, payload); err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Exec(t.Context(), `CREATE TEMP TABLE progress_audit(cursor int,state text,generation bigint,transaction_id bigint);
 CREATE FUNCTION pg_temp.audit_storage_progress() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN
  INSERT INTO progress_audit VALUES(NEW.next_measurement_index,NEW.state,NEW.processing_generation,txid_current());
  RETURN NEW;
 END $$;
 CREATE TRIGGER audit_storage_progress AFTER UPDATE ON host_storage_report FOR EACH ROW EXECUTE FUNCTION pg_temp.audit_storage_progress();`); err != nil {
		t.Fatal(err)
	}
	return f
}

func assertStorageBatchEffects(t *testing.T, f storageLeaseFixture, n int) {
	t.Helper()
	var total, open, matching int
	if err := f.pool.QueryRow(t.Context(), `SELECT count(*),count(*) FILTER(WHERE ended_at IS NULL) FROM sandbox_storage_interval`).Scan(&total, &open); err != nil {
		t.Fatal(err)
	}
	// The fixture has one interval preceding the report; all accepted samples
	// change quantity, closing that interval and creating exactly one per sample.
	if total != n+1 || open != n {
		t.Fatalf("intervals total=%d open=%d, want %d and %d", total, open, n+1, n)
	}
	payload, _ := json.Marshal(f.measurements[:n])
	if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM jsonb_array_elements($1::jsonb) m JOIN sandbox_storage_interval i
 ON i.sandbox_id=(m->>'sandbox_id')::uuid AND i.ended_at IS NULL
 WHERE i.disk_mib=((m->>'allocated_bytes')::bigint+(1<<20)-1)/(1<<20) AND i.started_at=$2`, payload, f.receivedAt).Scan(&matching); err != nil {
		t.Fatal(err)
	}
	if matching != n {
		t.Fatalf("correct quantities and receipt boundaries=%d, want %d", matching, n)
	}
}

func TestIntegration_StorageReportLeaseBatchesAndYields(t *testing.T) {
	n := storageReportChunksPerClaim*storageReportChunkSize + 1
	f := newStorageBatchFixture(t, n)
	if !processOneStorageReport(t.Context(), f.pool) {
		t.Fatal("claim failed")
	}
	var state string
	var cursor, generation, chunks, transactions int
	if err := f.pool.QueryRow(t.Context(), `SELECT state,next_measurement_index,processing_generation FROM host_storage_report`).Scan(&state, &cursor, &generation); err != nil {
		t.Fatal(err)
	}
	if state != "pending" || cursor != n-1 || generation != 1 {
		t.Fatalf("state=%s cursor=%d generation=%d", state, cursor, generation)
	}
	if err := f.pool.QueryRow(t.Context(), `SELECT count(*),count(DISTINCT transaction_id) FROM progress_audit WHERE cursor>0`).Scan(&chunks, &transactions); err != nil {
		t.Fatal(err)
	}
	if chunks != storageReportChunksPerClaim || transactions != chunks {
		t.Fatalf("chunks=%d transactions=%d", chunks, transactions)
	}
	var bad int
	if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM progress_audit WHERE cursor>0 AND cursor<$1 AND state<>'processing'`, n-1).Scan(&bad); err != nil {
		t.Fatal(err)
	}
	if bad != 0 {
		t.Fatal("intermediate commit yielded active lease")
	}
	assertStorageBatchEffects(t, f, n-1)
	if !processOneStorageReport(t.Context(), f.pool) {
		t.Fatal("resume failed")
	}
	assertStorageBatchEffects(t, f, n)
	if err := f.pool.QueryRow(t.Context(), `SELECT state,next_measurement_index,processing_generation FROM host_storage_report WHERE payload IS NULL`).Scan(&state, &cursor, &generation); err != nil {
		t.Fatal(err)
	}
	if state != "processed" || cursor != n || generation != 2 {
		t.Fatalf("completion state=%s cursor=%d generation=%d", state, cursor, generation)
	}
	if processOneStorageReport(t.Context(), f.pool) {
		t.Fatal("processed report applied twice")
	}
	assertStorageBatchEffects(t, f, n)
}

func TestIntegration_StorageReportLeaseBatchPartialRetry(t *testing.T) {
	f := newStorageBatchFixture(t, 1001)
	if _, err := f.pool.Exec(t.Context(), `CREATE FUNCTION pg_temp.fail_second_chunk() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN IF NEW.next_measurement_index=1000 THEN RAISE EXCEPTION 'injected progress failure'; END IF; RETURN NEW; END $$;
 CREATE TRIGGER fail_second_chunk BEFORE UPDATE ON host_storage_report FOR EACH ROW EXECUTE FUNCTION pg_temp.fail_second_chunk();`); err != nil {
		t.Fatal(err)
	}
	if !processOneStorageReport(t.Context(), f.pool) {
		t.Fatal("claim failure was not recorded")
	}
	var state string
	var cursor, attempts int
	if err := f.pool.QueryRow(t.Context(), `SELECT state,next_measurement_index,attempts FROM host_storage_report`).Scan(&state, &cursor, &attempts); err != nil {
		t.Fatal(err)
	}
	if state != "pending" || cursor != 500 || attempts != 1 {
		t.Fatalf("state=%s cursor=%d attempts=%d", state, cursor, attempts)
	}
	assertStorageBatchEffects(t, f, 500)
	if processOneStorageReport(t.Context(), f.pool) {
		t.Fatal("ignored retry delay")
	}
	if _, err := f.pool.Exec(t.Context(), `DROP TRIGGER fail_second_chunk ON host_storage_report; UPDATE host_storage_report SET next_attempt_at=now()`); err != nil {
		t.Fatal(err)
	}
	if !processOneStorageReport(t.Context(), f.pool) {
		t.Fatal("retry failed")
	}
	assertStorageBatchEffects(t, f, 1001)
}

func TestIntegration_StorageReportLeaseBatchRestartAndOrdering(t *testing.T) {
	f := newStorageBatchFixture(t, 1001)
	// Leave one committed chunk with a live processing lease, as a process
	// disappearing between chunks would. A later report must not overtake it.
	if _, err := f.pool.Exec(t.Context(), `UPDATE host_storage_report SET state='processing',processing_generation=1,next_attempt_at=now()-interval '2 minutes'`); err != nil {
		t.Fatal(err)
	}
	if err := applyStorageReportChunk(t.Context(), f.pool, f.hostID, f.incarnationID, f.reportID, 1, f.receivedAt, f.measurements[:500], 500, 1001, true); err != nil {
		t.Fatal(err)
	}
	nextID := uuid.New()
	if _, err := f.pool.Exec(t.Context(), `INSERT INTO host_storage_report(host_id,incarnation_id,report_id,ingest_seq,received_at,payload,state,next_measurement_index)
 VALUES($1,$2,$3,2,$4,'[]','pending',0)`, f.hostID, f.incarnationID, nextID, f.receivedAt.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if processOneStorageReport(t.Context(), f.pool) {
		t.Fatal("live refreshed lease reclaimed or later report overtook it")
	}
	assertStorageBatchEffects(t, f, 500)
	if _, err := f.pool.Exec(t.Context(), `UPDATE host_storage_report SET next_attempt_at=now()-interval '2 minutes' WHERE report_id=$1`, f.reportID); err != nil {
		t.Fatal(err)
	}
	if !processOneStorageReport(t.Context(), f.pool) {
		t.Fatal("restart did not reclaim durable progress")
	}
	assertStorageBatchEffects(t, f, 1001)
	var laterState string
	if err := f.pool.QueryRow(t.Context(), `SELECT state FROM host_storage_report WHERE report_id=$1`, nextID).Scan(&laterState); err != nil {
		t.Fatal(err)
	}
	if laterState != "pending" {
		t.Fatal("later report processed before predecessor completion")
	}
	if !processOneStorageReport(t.Context(), f.pool) {
		t.Fatal("later report did not proceed after completion")
	}
}

func TestIntegration_StorageReportLeaseBatchFencesBetweenChunks(t *testing.T) {
	for _, incarnationChange := range []bool{false, true} {
		name := "generation"
		if incarnationChange {
			name = "incarnation"
		}
		t.Run(name, func(t *testing.T) {
			f := newStorageBatchFixture(t, 1001)
			if _, err := f.pool.Exec(t.Context(), `UPDATE host_storage_report SET state='processing',processing_generation=1`); err != nil {
				t.Fatal(err)
			}
			if err := applyStorageReportChunk(t.Context(), f.pool, f.hostID, f.incarnationID, f.reportID, 1, f.receivedAt, f.measurements[:500], 500, 1001, true); err != nil {
				t.Fatal(err)
			}
			if incarnationChange {
				if _, err := f.pool.Exec(t.Context(), `UPDATE host SET incarnation_id=$1`, uuid.New()); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := f.pool.Exec(t.Context(), `UPDATE host_storage_report SET processing_generation=2`); err != nil {
					t.Fatal(err)
				}
			}
			before := storageLeaseRow(t, f)
			err := applyStorageReportChunk(t.Context(), f.pool, f.hostID, f.incarnationID, f.reportID, 1, f.receivedAt, f.measurements[500:1000], 1000, 1001, true)
			if err == nil {
				t.Fatal("stale owner advanced second chunk")
			}
			if incarnationChange && !errors.Is(err, errStorageReportStaleIncarnation) {
				t.Fatal(err)
			}
			if after := storageLeaseRow(t, f); before != after {
				t.Fatal("stale owner changed durable report")
			}
			assertStorageBatchEffects(t, f, 500)
		})
	}
}
