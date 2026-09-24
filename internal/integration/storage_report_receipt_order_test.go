//go:build integration

package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func waitForStorageReceiptLock(t *testing.T, key string, seed int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for {
		var waiting bool
		err := testPool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_locks
				WHERE locktype='advisory' AND NOT granted AND objsubid=1
				  AND classid=((hashtextextended($1::text, $2)>>32)&4294967295)::oid
				  AND objid=(hashtextextended($1::text, $2)&4294967295)::oid
			)`, key, seed).Scan(&waiting)
		if err != nil {
			t.Fatalf("wait for storage receipt boundary: %v", err)
		}
		if waiting {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("storage receipt did not wait at the expected boundary")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func storageReceiptHeartbeatBody(fixture storageReportFixture, reportID uuid.UUID) string {
	return fmt.Sprintf(`{"incarnation_id":%q,"vmd_addr":"192.0.2.1:50051","proxy_addr":"192.0.2.1:5007","region":"example-region","capacity_memory_mib":1024,"capacity_vcpus":2,"storage_report_id":%q,"storage":[{"sandbox_id":%q,"allocated_bytes":16777216}]}`,
		fixture.incarnation, reportID, fixture.sandboxID)
}

func awaitStorageReceiptResponse(t *testing.T, result <-chan *httptest.ResponseRecorder, status int) *httptest.ResponseRecorder {
	t.Helper()
	select {
	case response := <-result:
		if response.Code != status {
			t.Fatalf("storage receipt response: %d %s", response.Code, response.Body.String())
		}
		return response
	case <-time.After(5 * time.Second):
		t.Fatal("storage receipt request did not finish")
		return nil
	}
}

func TestIntegration_DirectReportWaitsForUncommittedLegacyReceipt(t *testing.T) {
	fixture := newStorageReportFixture(t, "active", true)
	ctx := context.Background()
	legacyID, directID := uuid.New(), uuid.New()
	functionName := "storage_receipt_gate_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := testPool.Exec(ctx, fmt.Sprintf(`
		CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.report_id = '%s'::uuid THEN
				PERFORM pg_advisory_xact_lock(hashtextextended(NEW.report_id::text, 1));
			END IF;
			RETURN NEW;
		END $$`, functionName, legacyID)); err != nil {
		t.Fatalf("create legacy receipt gate: %v", err)
	}
	t.Cleanup(func() { _, _ = testPool.Exec(context.Background(), "DROP FUNCTION "+functionName+"() CASCADE") })
	if _, err := testPool.Exec(ctx, fmt.Sprintf(`CREATE TRIGGER %s BEFORE INSERT ON legacy_host_storage_report FOR EACH ROW EXECUTE FUNCTION %s()`, functionName, functionName)); err != nil {
		t.Fatalf("create legacy receipt trigger: %v", err)
	}
	gate, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin legacy receipt gate: %v", err)
	}
	defer gate.Rollback(ctx)
	if _, err := gate.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text, 1))`, legacyID.String()); err != nil {
		t.Fatalf("hold legacy receipt gate: %v", err)
	}
	legacyResult := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		legacyResult <- hostHeartbeat(t, fixture.router, "", fixture.hostID, storageReceiptHeartbeatBody(fixture, legacyID))
	}()
	waitForStorageReceiptLock(t, legacyID.String(), 1)
	directResult := make(chan *httptest.ResponseRecorder, 1)
	go func() { directResult <- postStorageReport(t, fixture, directID, 32*1024*1024) }()
	waitForStorageReceiptLock(t, fixture.hostID, 0)
	select {
	case response := <-directResult:
		t.Fatalf("direct receipt overtook uncommitted legacy receipt: %d %s", response.Code, response.Body.String())
	default:
	}
	if err := gate.Commit(ctx); err != nil {
		t.Fatalf("release legacy receipt: %v", err)
	}
	awaitStorageReceiptResponse(t, legacyResult, http.StatusOK)
	awaitStorageReceiptResponse(t, directResult, http.StatusCreated)
	var legacySequence, directSequence int64
	var legacyTime, directTime time.Time
	if err := testPool.QueryRow(ctx, `
		SELECT legacy.ingest_seq, legacy.received_at, direct.ingest_seq, direct.received_at
		FROM host_storage_report legacy JOIN host_storage_report direct USING (host_id, incarnation_id)
		WHERE legacy.host_id=$1 AND legacy.report_id=$2 AND direct.report_id=$3`, fixture.hostID, legacyID, directID).
		Scan(&legacySequence, &legacyTime, &directSequence, &directTime); err != nil {
		t.Fatalf("read committed receipt order: %v", err)
	}
	if legacySequence >= directSequence || !legacyTime.Before(directTime) {
		t.Fatalf("legacy receipt (%d, %s) did not precede direct receipt (%d, %s)", legacySequence, legacyTime, directSequence, directTime)
	}
	waitStorageReportState(t, directID, "processed")
	var boundaries int
	if err := testPool.QueryRow(ctx, `
		SELECT count(*) FROM sandbox_storage_interval WHERE sandbox_id=$1 AND (
		    (disk_mib=8 AND ended_at=$2) OR
		    (disk_mib=16 AND started_at=$2 AND ended_at=$3) OR
		    (disk_mib=32 AND started_at=$3 AND ended_at IS NULL))`, fixture.sandboxID, legacyTime, directTime).Scan(&boundaries); err != nil {
		t.Fatalf("read ordered billing intervals: %v", err)
	}
	if boundaries != 3 {
		t.Fatalf("preserved billing intervals = %d, want all three receipt boundaries", boundaries)
	}
}

func TestIntegration_StorageReceiptTimestampFollowsSequencingLock(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy=%t", legacy), func(t *testing.T) {
			fixture := newStorageReportFixture(t, "active", true)
			ctx := context.Background()
			reportID := uuid.New()
			gate, err := testPool.Begin(ctx)
			if err != nil {
				t.Fatalf("begin receipt boundary: %v", err)
			}
			defer gate.Rollback(ctx)
			if _, err := gate.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))`, fixture.hostID); err != nil {
				t.Fatalf("hold receipt boundary: %v", err)
			}
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				if legacy {
					result <- hostHeartbeat(t, fixture.router, "", fixture.hostID, storageReceiptHeartbeatBody(fixture, reportID))
				} else {
					result <- postStorageReport(t, fixture, reportID, 16*1024*1024)
				}
			}()
			waitForStorageReceiptLock(t, fixture.hostID, 0)
			var releaseNotBefore time.Time
			if err := testPool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&releaseNotBefore); err != nil {
				t.Fatalf("read receipt release boundary: %v", err)
			}
			if err := gate.Commit(ctx); err != nil {
				t.Fatalf("release receipt boundary: %v", err)
			}
			wantStatus := http.StatusCreated
			if legacy {
				wantStatus = http.StatusOK
			}
			awaitStorageReceiptResponse(t, result, wantStatus)
			var receivedAt time.Time
			if err := testPool.QueryRow(ctx, `
				SELECT received_at FROM host_storage_report WHERE host_id=$1 AND report_id=$2
				UNION ALL
				SELECT received_at FROM legacy_host_storage_report WHERE host_id=$1 AND report_id=$2`, fixture.hostID, reportID).Scan(&receivedAt); err != nil {
				t.Fatalf("read allocated receipt timestamp: %v", err)
			}
			if receivedAt.Before(releaseNotBefore) {
				t.Fatalf("receipt timestamp %s predates sequencing boundary %s", receivedAt, releaseNotBefore)
			}
		})
	}
}

func TestIntegration_DirectReportDrainsDeferredLegacyHead(t *testing.T) {
	fixture := newStorageReportFixture(t, "active", true)
	ctx := context.Background()
	legacyID, directID := uuid.New(), uuid.New()
	payload := fmt.Sprintf(`[{"sandbox_id":%q,"allocated_bytes":8388608}]`, fixture.sandboxID)
	if _, err := testPool.Exec(ctx, `
		INSERT INTO legacy_host_storage_report(host_id, requested_incarnation_id, report_id, received_at, payload, next_attempt_at)
		VALUES ($1, $2, $3, now()-interval '1 minute', $4::jsonb, now()+interval '30 seconds')`, fixture.hostID, fixture.incarnation, legacyID, payload); err != nil {
		t.Fatalf("insert deferred legacy receipt: %v", err)
	}
	response := postStorageReport(t, fixture, directID, 16*1024*1024)
	if response.Code != http.StatusCreated {
		t.Fatalf("direct receipt: %d %s", response.Code, response.Body.String())
	}
	var ordered bool
	if err := testPool.QueryRow(ctx, `
		SELECT legacy.ingest_seq < direct.ingest_seq
		FROM host_storage_report legacy JOIN host_storage_report direct USING (host_id, incarnation_id)
		WHERE legacy.host_id=$1 AND legacy.report_id=$2 AND direct.report_id=$3`, fixture.hostID, legacyID, directID).Scan(&ordered); err != nil {
		t.Fatalf("read deferred receipt order: %v", err)
	}
	if !ordered {
		t.Fatal("direct receipt bypassed the deferred legacy receipt")
	}
}
