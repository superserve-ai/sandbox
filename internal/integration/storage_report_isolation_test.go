//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/telemetry"
)

type storageReportFixture struct {
	hostID      string
	incarnation string
	sandboxID   uuid.UUID
	router      *gin.Engine
}

type storageFailureCapture struct {
	telemetry.Recorder
	mu       sync.Mutex
	failures []telemetry.StorageReportFailure
}

type synchronizedLogBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *synchronizedLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(p)
}

func (b *synchronizedLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.String()
}

func (r *storageFailureCapture) RecordStorageReportFailure(_ context.Context, failure telemetry.StorageReportFailure) {
	r.mu.Lock()
	r.failures = append(r.failures, failure)
	r.mu.Unlock()
}

func (r *storageFailureCapture) snapshot() []telemetry.StorageReportFailure {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]telemetry.StorageReportFailure(nil), r.failures...)
}

func newStorageReportFixture(t *testing.T, sandboxStatus string, openInterval bool) storageReportFixture {
	t.Helper()
	ctx := context.Background()
	hostID := "storage-report-" + uuid.NewString()
	incarnation := uuid.NewString()
	cleanupHost(t, hostID)
	if _, err := testQueries.CreateHost(ctx, db.CreateHostParams{
		ID: hostID, VmdAddr: "192.0.2.1:50051", ProxyAddr: "192.0.2.1:5007",
		Region: "example-region", CapacityMemoryMib: 1024, CapacityVcpus: 2,
	}); err != nil {
		t.Fatalf("create host: %v", err)
	}
	h := &api.Handlers{DB: testQueries, Pool: testPool}
	r := gin.New()
	r.POST("/internal/hosts/:host_id/heartbeat", h.HostHeartbeat)
	r.POST("/internal/hosts/:host_id/storage-reports", h.HostStorageReport)

	body := fmt.Sprintf(`{"incarnation_id":%q,"vmd_addr":"192.0.2.1:50051","proxy_addr":"192.0.2.1:5007","region":"example-region","capacity_memory_mib":1024,"capacity_vcpus":2}`, incarnation)
	if w := hostHeartbeat(t, r, "", hostID, body); w.Code != http.StatusOK {
		t.Fatalf("bind heartbeat: %d %s", w.Code, w.Body.String())
	}

	teamID, _ := seedTeamAndKey(t)
	sandboxID := uuid.New()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox (id, team_id, name, status, host_id, vcpu_count, memory_mib, disk_mib)
		VALUES ($1, $2, $3, $4, $5, 1, 1024, 8)`,
		sandboxID, teamID, "storage-report-fixture", sandboxStatus, hostID); err != nil {
		t.Fatalf("insert sandbox: %v", err)
	}
	if openInterval {
		if _, err := testPool.Exec(ctx, `
			INSERT INTO sandbox_storage_interval (sandbox_id, team_id, disk_mib, started_at)
			VALUES ($1, $2, 8, now())`, sandboxID, teamID); err != nil {
			t.Fatalf("insert open storage interval: %v", err)
		}
	}
	return storageReportFixture{hostID: hostID, incarnation: incarnation, sandboxID: sandboxID, router: r}
}

func postStorageReport(t *testing.T, fixture storageReportFixture, reportID uuid.UUID, allocatedBytes int64) *httptest.ResponseRecorder {
	t.Helper()
	body := fmt.Sprintf(`{"incarnation_id":%q,"report_id":%q,"measurements":[{"sandbox_id":%q,"allocated_bytes":%d}]}`,
		fixture.incarnation, reportID, fixture.sandboxID, allocatedBytes)
	return requestStorageReport(fixture.router, fixture.hostID, body)
}

func requestStorageReport(r http.Handler, hostID, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/internal/hosts/"+hostID+"/storage-reports", strings.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

type storageReportAck struct {
	ReportID   uuid.UUID `json:"report_id"`
	IngestSeq  int64     `json:"ingest_seq"`
	ReceivedAt time.Time `json:"received_at"`
}

func decodeStorageReportAck(t *testing.T, w *httptest.ResponseRecorder) storageReportAck {
	t.Helper()
	var ack storageReportAck
	if err := json.Unmarshal(w.Body.Bytes(), &ack); err != nil {
		t.Fatalf("decode storage report acknowledgement: %v; body=%s", err, w.Body.String())
	}
	return ack
}

func waitStorageReportState(t *testing.T, reportID uuid.UUID, want ...string) (state, lastError string) {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(12 * time.Second)
	for {
		var errText *string
		err := testPool.QueryRow(ctx, `SELECT state, last_error FROM host_storage_report WHERE report_id=$1`, reportID).Scan(&state, &errText)
		if err == nil {
			lastError = ""
			if errText != nil {
				lastError = *errText
			}
			for _, candidate := range want {
				if state == candidate {
					return state, lastError
				}
			}
		} else if err != pgx.ErrNoRows {
			t.Fatalf("read storage report %s: %v", reportID, err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("storage report %s did not reach %v; state=%q error=%q", reportID, want, state, lastError)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitStorageReportRetry(t *testing.T, reportID uuid.UUID) string {
	t.Helper()
	deadline := time.Now().Add(12 * time.Second)
	for {
		var state string
		var lastError *string
		var attempts int
		if err := testPool.QueryRow(context.Background(), `
			SELECT state, attempts, last_error FROM host_storage_report WHERE report_id=$1`, reportID).
			Scan(&state, &attempts, &lastError); err != nil {
			t.Fatalf("read storage retry: %v", err)
		}
		if (state == "pending" || state == "retry_exhausted") && attempts > 0 && lastError != nil {
			return *lastError
		}
		if state == "terminal" || time.Now().After(deadline) {
			t.Fatalf("report did not remain retryable: state=%s attempts=%d error=%v", state, attempts, lastError)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func forceStorageIntervalWriteFailure(t *testing.T, sandboxID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	if _, err := testPool.Exec(ctx, `
		CREATE OR REPLACE FUNCTION test_force_storage_interval_write_failure()
		RETURNS trigger
		LANGUAGE plpgsql
		AS $$
		BEGIN
			RAISE EXCEPTION 'forced storage interval write failure'
				USING ERRCODE = '23514';
		END;
		$$;`); err != nil {
		t.Fatalf("create storage interval failure function: %v", err)
	}
	t.Cleanup(func() {
		if _, err := testPool.Exec(context.Background(), `
			DROP TRIGGER IF EXISTS test_force_storage_interval_write_failure ON sandbox_storage_interval;
			DROP FUNCTION IF EXISTS test_force_storage_interval_write_failure()`); err != nil {
			t.Errorf("drop storage interval failure fixture: %v", err)
		}
	})
	if _, err := testPool.Exec(ctx, fmt.Sprintf(`
		CREATE TRIGGER test_force_storage_interval_write_failure
		BEFORE INSERT OR UPDATE ON sandbox_storage_interval
		FOR EACH ROW
		WHEN (NEW.sandbox_id = '%s'::uuid)
		EXECUTE FUNCTION test_force_storage_interval_write_failure()`, sandboxID)); err != nil {
		t.Fatalf("create storage interval failure trigger: %v", err)
	}
}

func waitLatestStorageReport(t *testing.T, hostID string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(12 * time.Second)
	for {
		var reportID uuid.UUID
		err := testPool.QueryRow(ctx, `
			SELECT report_id
			FROM host_storage_report
			WHERE host_id=$1
			ORDER BY received_at DESC
			LIMIT 1`, hostID).Scan(&reportID)
		if err == nil {
			return reportID
		}
		if err != pgx.ErrNoRows {
			t.Fatalf("read storage report for host %s: %v", hostID, err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("storage report for host %s was not promoted", hostID)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A failed auxiliary storage application is isolated from the heartbeat
// transaction: liveness commits first, then the valid legacy report reaches
// the worker and remains retryable after an interval-write failure.
func TestIntegration_HostHeartbeatRemainsHealthyWhenStorageProcessingFails(t *testing.T) {
	var logOutput synchronizedLogBuffer
	previousLogger := log.Logger
	log.Logger = zerolog.New(&logOutput).Level(zerolog.InfoLevel)
	t.Cleanup(func() { log.Logger = previousLogger })
	recorder := &storageFailureCapture{Recorder: telemetry.NewNoopRecorder()}
	api.SetTelemetryRecorder(recorder)
	t.Cleanup(func() { api.SetTelemetryRecorder(nil) })

	fixture := newStorageReportFixture(t, "active", true)
	ctx := context.Background()
	forceStorageIntervalWriteFailure(t, fixture.sandboxID)
	before, err := testQueries.GetHost(ctx, fixture.hostID)
	if err != nil {
		t.Fatalf("read host before heartbeat: %v", err)
	}
	body := fmt.Sprintf(`{"incarnation_id":%q,"vmd_addr":"192.0.2.1:50051","proxy_addr":"192.0.2.1:5007","region":"example-region","capacity_memory_mib":1024,"capacity_vcpus":2,"storage":[{"sandbox_id":%q,"allocated_bytes":16777216}]}`,
		fixture.incarnation, fixture.sandboxID)
	if w := hostHeartbeat(t, fixture.router, "", fixture.hostID, body); w.Code != http.StatusOK {
		t.Fatalf("heartbeat with storage: %d %s", w.Code, w.Body.String())
	}
	host, err := testQueries.GetHost(ctx, fixture.hostID)
	if err != nil {
		t.Fatalf("read host after heartbeat: %v", err)
	}
	if host.Status != "active" || !host.LastHeartbeatAt.Valid || !before.LastHeartbeatAt.Valid || !host.LastHeartbeatAt.Time.After(before.LastHeartbeatAt.Time) {
		t.Fatalf("heartbeat liveness regressed: before=%+v after=%+v", before, host)
	}
	reportID := waitLatestStorageReport(t, fixture.hostID)
	lastError := waitStorageReportRetry(t, reportID)
	if !strings.Contains(lastError, "forced storage interval write failure") {
		t.Fatalf("retryable storage failure = %q, want forced interval write failure", lastError)
	}
	host, err = testQueries.GetHost(ctx, fixture.hostID)
	if err != nil {
		t.Fatalf("read host after worker failure: %v", err)
	}
	if host.Status != "active" {
		t.Fatalf("storage failure made host unhealthy: %s", host.Status)
	}
	deadline := time.Now().Add(12 * time.Second)
	for {
		output := logOutput.String()
		failures := recorder.snapshot()
		retryable := false
		for _, failure := range failures {
			if failure.Result == "error" {
				retryable = true
				break
			}
		}
		if strings.Contains(output, `"host_id":"`+fixture.hostID+`"`) &&
			strings.Contains(output, "storage measurement processing failed") && retryable {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("storage failure log = %q, metrics = %#v; want structured host_id, failure message, and retryable failure", output, failures)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestIntegration_LegacyHeartbeatAcknowledgesDurableHandoff(t *testing.T) {
	fixture := newStorageReportFixture(t, "active", true)
	reportID := uuid.New()
	body := fmt.Sprintf(`{"incarnation_id":%q,"vmd_addr":"192.0.2.1:50051","proxy_addr":"192.0.2.1:5007","region":"example-region","capacity_memory_mib":1024,"capacity_vcpus":2,"storage_report_id":%q,"storage":[{"sandbox_id":%q,"allocated_bytes":16777216}]}`,
		fixture.incarnation, reportID.String(), fixture.sandboxID)
	accepted := func() bool {
		w := hostHeartbeat(t, fixture.router, "", fixture.hostID, body)
		if w.Code != http.StatusOK {
			t.Fatalf("heartbeat with legacy storage: %d %s", w.Code, w.Body.String())
		}
		var response struct {
			StorageAccepted bool `json:"storage_accepted"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatalf("decode heartbeat: %v", err)
		}
		return response.StorageAccepted
	}
	if !accepted() {
		t.Fatal("heartbeat did not acknowledge the durable legacy handoff")
	}
	var count int
	if err := testPool.QueryRow(context.Background(), `SELECT COUNT(*) FROM legacy_host_storage_report WHERE host_id=$1 AND report_id=$2`, fixture.hostID, reportID).Scan(&count); err != nil {
		t.Fatalf("read legacy handoff: %v", err)
	}
	if count == 0 {
		if err := testPool.QueryRow(context.Background(), `SELECT COUNT(*) FROM host_storage_report WHERE host_id=$1 AND report_id=$2`, fixture.hostID, reportID).Scan(&count); err != nil {
			t.Fatalf("read promoted report: %v", err)
		}
	}
	if count != 1 {
		t.Fatalf("acknowledged report has %d durable rows, want 1", count)
	}
}

func TestIntegration_DirectReportDrainsOlderLegacyReportsInReceiptOrder(t *testing.T) {
	fixture := newStorageReportFixture(t, "active", true)
	ctx := context.Background()
	legacyID := uuid.New()
	directID := uuid.New()
	legacyReceivedAt := time.Now().UTC().Add(-time.Minute)
	legacyPayload := fmt.Sprintf(`[{"sandbox_id":%q,"allocated_bytes":%d}]`, fixture.sandboxID, 8*1024*1024)
	if _, err := testPool.Exec(ctx, `
		INSERT INTO legacy_host_storage_report(host_id, report_id, received_at, payload)
		VALUES ($1, $2, $3, $4::jsonb)`, fixture.hostID, legacyID, legacyReceivedAt, legacyPayload); err != nil {
		t.Fatalf("insert legacy handoff: %v", err)
	}

	direct := postStorageReport(t, fixture, directID, 16*1024*1024)
	if direct.Code != http.StatusCreated {
		t.Fatalf("direct storage report: %d %s", direct.Code, direct.Body.String())
	}
	rows, err := testPool.Query(ctx, `
		SELECT report_id, ingest_seq, received_at
		FROM host_storage_report
		WHERE host_id=$1 AND incarnation_id=$2
		ORDER BY ingest_seq`, fixture.hostID, fixture.incarnation)
	if err != nil {
		t.Fatalf("read unified report order: %v", err)
	}
	defer rows.Close()
	var got []struct {
		id         uuid.UUID
		seq        int64
		receivedAt time.Time
	}
	for rows.Next() {
		var row struct {
			id         uuid.UUID
			seq        int64
			receivedAt time.Time
		}
		if err := rows.Scan(&row.id, &row.seq, &row.receivedAt); err != nil {
			t.Fatalf("scan unified report order: %v", err)
		}
		got = append(got, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read unified report order: %v", err)
	}
	if len(got) != 2 || got[0].id != legacyID || got[1].id != directID || !got[0].receivedAt.Before(got[1].receivedAt) {
		t.Fatalf("unified report order = %#v, want legacy then direct by receipt time", got)
	}
}

func TestIntegration_StorageReportConstraintFailureRecoversAfterSchemaRepair(t *testing.T) {
	fixture := newStorageReportFixture(t, "active", true)
	ctx := context.Background()
	forceStorageIntervalWriteFailure(t, fixture.sandboxID)
	reportID := uuid.New()
	payload := fmt.Sprintf(`[{"sandbox_id":%q,"allocated_bytes":16777216}]`, fixture.sandboxID)
	if _, err := testPool.Exec(ctx, `
		INSERT INTO host_storage_report(host_id, incarnation_id, report_id, ingest_seq, payload)
		VALUES ($1, $2::uuid, $3, 1, $4::jsonb)`, fixture.hostID, fixture.incarnation, reportID, payload); err != nil {
		t.Fatalf("insert failing storage report: %v", err)
	}
	lastError := waitStorageReportRetry(t, reportID)
	if !strings.Contains(lastError, "forced storage interval write failure") {
		t.Fatalf("report error=%q; want retryable interval constraint failure", lastError)
	}
	teamID := sandboxTeamID(t, fixture.sandboxID)
	var retained, complete bool
	if err := testPool.QueryRow(ctx, `
		SELECT payload IS NOT NULL, storage_reports_complete_through($2, clock_timestamp())
		FROM host_storage_report WHERE report_id=$1`, reportID, teamID).Scan(&retained, &complete); err != nil {
		t.Fatalf("check failed report retention: %v", err)
	}
	if !retained || complete {
		t.Fatalf("failed report retained=%v complete=%v, want retained and incomplete", retained, complete)
	}
	host, err := testQueries.GetHost(ctx, fixture.hostID)
	if err != nil {
		t.Fatalf("read host: %v", err)
	}
	if host.Status != "active" {
		t.Fatalf("constraint rejection changed host status to %s", host.Status)
	}
	if _, err := testPool.Exec(ctx, `DROP TRIGGER test_force_storage_interval_write_failure ON sandbox_storage_interval`); err != nil {
		t.Fatalf("repair interval schema: %v", err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE host_storage_report SET next_attempt_at=now() WHERE report_id=$1`, reportID); err != nil {
		t.Fatalf("release report retry: %v", err)
	}
	waitStorageReportState(t, reportID, "processed")
	var disk int
	if err := testPool.QueryRow(ctx, `
		SELECT disk_mib, storage_reports_complete_through($2, clock_timestamp())
		FROM sandbox_storage_interval WHERE sandbox_id=$1 AND ended_at IS NULL`, fixture.sandboxID, teamID).Scan(&disk, &complete); err != nil {
		t.Fatalf("read recovered interval: %v", err)
	}
	if disk != 16 || !complete {
		t.Fatalf("recovered report disk=%d complete=%v, want 16 and complete", disk, complete)
	}
}

func TestIntegration_StorageReportCompletenessResolvesTerminalAndDestroyedReports(t *testing.T) {
	fixture := newStorageReportFixture(t, "active", false)
	ctx := context.Background()
	teamID := sandboxTeamID(t, fixture.sandboxID)
	terminalID := uuid.New()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO host_storage_report(host_id, incarnation_id, report_id, ingest_seq, received_at, payload, state)
		VALUES ($1, $2::uuid, $3, 1, now()-interval '1 hour', '[]'::jsonb, 'terminal')`,
		fixture.hostID, fixture.incarnation, terminalID); err != nil {
		t.Fatalf("insert terminal storage report: %v", err)
	}
	var complete bool
	if err := testPool.QueryRow(ctx, `SELECT storage_reports_complete_through($1, now())`, teamID).Scan(&complete); err != nil {
		t.Fatalf("check terminal report completeness: %v", err)
	}
	if !complete {
		t.Fatal("terminal storage report blocked a later billing window")
	}

	var destroyedAt time.Time
	if err := testPool.QueryRow(ctx, `
		UPDATE sandbox SET status='deleted', destroyed_at=now() WHERE id=$1
		RETURNING destroyed_at`, fixture.sandboxID).Scan(&destroyedAt); err != nil {
		t.Fatalf("soft-delete sandbox: %v", err)
	}
	pendingID := uuid.New()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO host_storage_report(host_id, incarnation_id, report_id, ingest_seq, received_at, payload, state, next_attempt_at)
		VALUES ($1, $2::uuid, $3, 2, $4::timestamptz + interval '1 second', '[]'::jsonb, 'pending', now()+interval '1 hour')`,
		fixture.hostID, fixture.incarnation, pendingID, destroyedAt); err != nil {
		t.Fatalf("insert pending storage report: %v", err)
	}
	if err := testPool.QueryRow(ctx, `SELECT storage_reports_complete_through($1, $2)`, teamID, destroyedAt.Add(2*time.Second)).Scan(&complete); err != nil {
		t.Fatalf("check destroyed sandbox completeness: %v", err)
	}
	if !complete {
		t.Fatal("storage report for a destroyed sandbox blocked a later billing window")
	}
}

func TestIntegration_RetryExhaustedStorageReportBlocksCompleteness(t *testing.T) {
	fixture := newStorageReportFixture(t, "active", false)
	ctx := context.Background()
	teamID := sandboxTeamID(t, fixture.sandboxID)
	if _, err := testPool.Exec(ctx, `
		INSERT INTO host_storage_report(host_id, incarnation_id, report_id, ingest_seq, received_at, payload, state, attempts, next_attempt_at)
		VALUES ($1, $2::uuid, $3, 1, now(), '[]'::jsonb, 'retry_exhausted', 8, now()+interval '1 hour')`,
		fixture.hostID, fixture.incarnation, uuid.New()); err != nil {
		t.Fatalf("insert retry-exhausted storage report: %v", err)
	}
	var complete bool
	if err := testPool.QueryRow(ctx, `SELECT storage_reports_complete_through($1, now()+interval '1 second')`, teamID).Scan(&complete); err != nil {
		t.Fatalf("check retry-exhausted report completeness: %v", err)
	}
	if complete {
		t.Fatal("retry-exhausted storage report was treated as settled")
	}
}

func TestIntegration_RetryExhaustedStorageReportRetriesAfterRecovery(t *testing.T) {
	fixture := newStorageReportFixture(t, "active", false)
	ctx := context.Background()
	reportID := uuid.New()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO host_storage_report(host_id, incarnation_id, report_id, ingest_seq, received_at, payload, state, attempts, next_attempt_at)
		VALUES ($1, $2::uuid, $3, 1, now(), '[]'::jsonb, 'retry_exhausted', 8, now())`,
		fixture.hostID, fixture.incarnation, reportID); err != nil {
		t.Fatalf("insert retry-exhausted storage report: %v", err)
	}

	state, lastError := waitStorageReportState(t, reportID, "processed")
	if state != "processed" || lastError != "" {
		t.Fatalf("recovered report state=%q error=%q; want processed without an error", state, lastError)
	}
}

func TestIntegration_StorageReportClaimStartsProcessingLease(t *testing.T) {
	fixture := newStorageReportFixture(t, "active", true)
	ctx := context.Background()
	holder, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin interval holder: %v", err)
	}
	defer holder.Rollback(ctx)
	if _, err := holder.Exec(ctx, `SELECT 1 FROM sandbox_storage_interval WHERE sandbox_id=$1 AND ended_at IS NULL FOR UPDATE`, fixture.sandboxID); err != nil {
		t.Fatalf("lock storage interval: %v", err)
	}
	var claimNotBefore time.Time
	if err := testPool.QueryRow(ctx, `SELECT now()`).Scan(&claimNotBefore); err != nil {
		t.Fatalf("read database time: %v", err)
	}
	reportID := uuid.New()
	payload := fmt.Sprintf(`[{"sandbox_id":%q,"allocated_bytes":%d}]`, fixture.sandboxID, 16*1024*1024)
	if _, err := testPool.Exec(ctx, `
		INSERT INTO host_storage_report(host_id, incarnation_id, report_id, ingest_seq, payload, next_attempt_at)
		VALUES ($1, $2::uuid, $3, 1, $4::jsonb, now()-interval '2 minutes')`,
		fixture.hostID, fixture.incarnation, reportID, payload); err != nil {
		t.Fatalf("insert queued storage report: %v", err)
	}
	var state string
	var leaseStartedAt time.Time
	var stale bool
	deadline := time.Now().Add(12 * time.Second)
	for {
		if err := testPool.QueryRow(ctx, `
			SELECT state, next_attempt_at, next_attempt_at < now()-interval '1 minute'
			FROM host_storage_report WHERE report_id=$1`, reportID).Scan(&state, &leaseStartedAt, &stale); err != nil {
			t.Fatalf("read processing lease: %v", err)
		}
		if state == "processing" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("report did not enter processing; state=%q", state)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if leaseStartedAt.Before(claimNotBefore) || stale {
		t.Fatalf("processing lease started at %s before claim bound %s; stale=%t", leaseStartedAt, claimNotBefore, stale)
	}
	if err := holder.Commit(ctx); err != nil {
		t.Fatalf("release storage interval: %v", err)
	}
	waitStorageReportState(t, reportID, "processed")
}

func TestIntegration_BillingRollupDisabledTeamCompletesUnresolvedStorageJob(t *testing.T) {
	fixture := newStorageReportFixture(t, "active", false)
	ctx := context.Background()
	teamID := sandboxTeamID(t, fixture.sandboxID)
	// The test worker claims the globally earliest pending job. Use a fixed
	// epoch hour so unrelated jobs left by other integration cases cannot
	// starve this targeted assertion when BatchSize is one.
	hourStart := time.Unix(0, 0).UTC()
	hourEnd := hourStart.Add(time.Hour)

	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_feature_flag (team_id, key, enabled)
		VALUES
			($1, 'billing_metrics_write', true),
			($1, 'billing_hourly_rollups', false)
		ON CONFLICT (team_id, key) DO UPDATE SET enabled = EXCLUDED.enabled
	`, teamID); err != nil {
		t.Fatalf("disable billing hourly rollups: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO host_storage_report (
			host_id, incarnation_id, report_id, ingest_seq, received_at,
			payload, state, next_attempt_at
		)
		VALUES ($1, $2::uuid, $3, 1, $4, '[]'::jsonb, 'pending', now() + interval '1 hour')
	`, fixture.hostID, fixture.incarnation, uuid.New(), hourStart.Add(30*time.Minute)); err != nil {
		t.Fatalf("insert unresolved storage report: %v", err)
	}
	jobID := insertBillingRollupJob(t, ctx, teamID, hourStart, hourEnd, "pending", "", time.Time{}, 0)

	billing.ProcessJobsForTest(ctx, testPool, testQueries, billing.HourlyRollupConfig{
		BatchSize:    1,
		MaxAttempts:  5,
		LockDuration: time.Minute,
	}, "rollup-worker-disabled-team")

	var status string
	if err := testPool.QueryRow(ctx, `SELECT status FROM billing_rollup_job WHERE id = $1`, jobID).Scan(&status); err != nil {
		t.Fatalf("read disabled rollup job: %v", err)
	}
	if status != "completed" {
		t.Fatalf("disabled rollup job status = %q, want completed no-op", status)
	}
}

func TestIntegration_StorageReportReceivedBeforeDestructionPreservesDeletionBoundary(t *testing.T) {
	fixture := newStorageReportFixture(t, "active", true)
	ctx := context.Background()
	reportID := uuid.New()
	var createdAt, intervalStartedAt time.Time
	if err := testPool.QueryRow(ctx, `
		SELECT s.created_at, i.started_at
		FROM sandbox s
		JOIN sandbox_storage_interval i ON i.sandbox_id=s.id
		WHERE s.id=$1 AND i.ended_at IS NULL`, fixture.sandboxID).Scan(&createdAt, &intervalStartedAt); err != nil {
		t.Fatalf("read sandbox creation and interval times: %v", err)
	}
	receivedAt := intervalStartedAt.Add(time.Millisecond)
	if receivedAt.Before(createdAt) {
		t.Fatalf("storage interval starts before sandbox creation: interval=%s created=%s", intervalStartedAt, createdAt)
	}
	destroyedAt := receivedAt.Add(time.Second)
	payload := fmt.Sprintf(`[{"sandbox_id":%q,"allocated_bytes":%d}]`, fixture.sandboxID, 16*1024*1024)
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin destruction transaction: %v", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `
		INSERT INTO host_storage_report(host_id, incarnation_id, report_id, ingest_seq, received_at, payload, next_attempt_at)
		VALUES ($1, $2::uuid, $3, 1, $4, $5::jsonb, now()+interval '1 hour')`,
		fixture.hostID, fixture.incarnation, reportID, receivedAt, payload); err != nil {
		t.Fatalf("insert pre-destruction report: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE sandbox_storage_interval
		SET ended_at=$2, end_reason='deleted'
		WHERE sandbox_id=$1 AND ended_at IS NULL`, fixture.sandboxID, destroyedAt); err != nil {
		t.Fatalf("close storage interval: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE sandbox SET status='deleted', destroyed_at=$2 WHERE id=$1`, fixture.sandboxID, destroyedAt); err != nil {
		t.Fatalf("destroy sandbox: %v", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE host_storage_report SET next_attempt_at=now() WHERE report_id=$1`, reportID); err != nil {
		t.Fatalf("release report for processing: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit destruction transaction: %v", err)
	}

	waitStorageReportState(t, reportID, "processed")
	rows, err := testPool.Query(ctx, `
		SELECT disk_mib, started_at, ended_at, end_reason
		FROM sandbox_storage_interval
		WHERE sandbox_id=$1
		ORDER BY started_at`, fixture.sandboxID)
	if err != nil {
		t.Fatalf("read storage intervals: %v", err)
	}
	defer rows.Close()
	type interval struct {
		disk      int
		startedAt time.Time
		endedAt   *time.Time
		endReason *string
	}
	var intervals []interval
	for rows.Next() {
		var got interval
		if err := rows.Scan(&got.disk, &got.startedAt, &got.endedAt, &got.endReason); err != nil {
			t.Fatalf("scan storage interval: %v", err)
		}
		intervals = append(intervals, got)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read storage intervals: %v", err)
	}
	if len(intervals) != 2 {
		t.Fatalf("storage intervals = %d, want 2 after applying pre-destruction report", len(intervals))
	}
	if intervals[0].disk != 8 || intervals[0].endedAt == nil || !intervals[0].endedAt.Equal(receivedAt) || intervals[0].endReason == nil || *intervals[0].endReason != "measurement" {
		t.Fatalf("prior storage interval = %+v, want disk 8 ending at report with measurement reason", intervals[0])
	}
	if intervals[1].disk != 16 || !intervals[1].startedAt.Equal(receivedAt) || intervals[1].endedAt == nil || !intervals[1].endedAt.Equal(destroyedAt) || intervals[1].endReason == nil || *intervals[1].endReason != "deleted" {
		t.Fatalf("post-report storage interval = %+v, want disk 16 ending at destruction", intervals[1])
	}
}

func TestIntegration_StorageReportAcknowledgementFencesAndPreservesSequenceTime(t *testing.T) {
	fixture := newStorageReportFixture(t, "active", true)
	firstID := uuid.New()
	first := postStorageReport(t, fixture, firstID, 8*1024*1024)
	if first.Code != http.StatusCreated {
		t.Fatalf("first storage report: %d %s", first.Code, first.Body.String())
	}
	firstAck := decodeStorageReportAck(t, first)
	if firstAck.ReportID != firstID || firstAck.IngestSeq != 1 || firstAck.ReceivedAt.IsZero() {
		t.Fatalf("first acknowledgement = %+v, want report id, sequence 1, and timestamp", firstAck)
	}

	retry := postStorageReport(t, fixture, firstID, 8*1024*1024)
	if retry.Code != http.StatusOK {
		t.Fatalf("idempotent retry: %d %s", retry.Code, retry.Body.String())
	}
	retryAck := decodeStorageReportAck(t, retry)
	if retryAck != firstAck {
		t.Fatalf("retry acknowledgement = %+v, want original %+v", retryAck, firstAck)
	}

	conflict := postStorageReport(t, fixture, firstID, 16*1024*1024)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("changed duplicate status = %d, want 409; body=%s", conflict.Code, conflict.Body.String())
	}

	secondID := uuid.New()
	second := postStorageReport(t, fixture, secondID, 16*1024*1024)
	if second.Code != http.StatusCreated {
		t.Fatalf("second storage report: %d %s", second.Code, second.Body.String())
	}
	secondAck := decodeStorageReportAck(t, second)
	if secondAck.IngestSeq != firstAck.IngestSeq+1 || secondAck.ReceivedAt.IsZero() {
		t.Fatalf("second acknowledgement = %+v, want sequence %d and timestamp", secondAck, firstAck.IngestSeq+1)
	}

	var rows []struct {
		seq        int64
		receivedAt time.Time
	}
	if err := func() error {
		ctx := context.Background()
		queryRows, err := testPool.Query(ctx, `
			SELECT ingest_seq, received_at
			FROM host_storage_report
			WHERE host_id=$1 AND incarnation_id=$2
			ORDER BY ingest_seq`, fixture.hostID, fixture.incarnation)
		if err != nil {
			return err
		}
		defer queryRows.Close()
		for queryRows.Next() {
			var row struct {
				seq        int64
				receivedAt time.Time
			}
			if err := queryRows.Scan(&row.seq, &row.receivedAt); err != nil {
				return err
			}
			rows = append(rows, row)
		}
		return queryRows.Err()
	}(); err != nil {
		t.Fatalf("read storage report sequence: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("storage report rows = %d, want 2", len(rows))
	}
	if !rows[0].receivedAt.Equal(firstAck.ReceivedAt) || !rows[1].receivedAt.Equal(secondAck.ReceivedAt) {
		t.Fatalf("stored received_at = [%s %s], want acknowledgement timestamps [%s %s]", rows[0].receivedAt, rows[1].receivedAt, firstAck.ReceivedAt, secondAck.ReceivedAt)
	}

	waitStorageReportState(t, secondID, "processed")
	var compactedPayload []byte
	var payloadHash string
	if err := testPool.QueryRow(context.Background(), `
		SELECT payload, payload_hash
		FROM host_storage_report
		WHERE host_id=$1 AND incarnation_id=$2 AND report_id=$3`, fixture.hostID, fixture.incarnation, firstID).Scan(&compactedPayload, &payloadHash); err != nil {
		t.Fatalf("read compacted storage report: %v", err)
	}
	if compactedPayload != nil || payloadHash == "" {
		t.Fatalf("compacted report payload=%v hash=%q; want payload cleared with dedup hash retained", compactedPayload, payloadHash)
	}
	compactedRetry := postStorageReport(t, fixture, firstID, 8*1024*1024)
	if compactedRetry.Code != http.StatusOK {
		t.Fatalf("idempotent retry after compaction: %d %s", compactedRetry.Code, compactedRetry.Body.String())
	}
	var firstProcessed, secondProcessed time.Time
	if err := testPool.QueryRow(context.Background(), `
		SELECT r1.processed_at, r2.processed_at
		FROM host_storage_report r1
		JOIN host_storage_report r2
		  ON r2.host_id=r1.host_id AND r2.incarnation_id=r1.incarnation_id AND r2.ingest_seq=r1.ingest_seq+1
		WHERE r1.host_id=$1 AND r1.incarnation_id=$2 AND r1.ingest_seq=1`, fixture.hostID, fixture.incarnation).Scan(&firstProcessed, &secondProcessed); err != nil {
		t.Fatalf("read processing order: %v", err)
	}
	if secondProcessed.Before(firstProcessed) {
		t.Fatalf("worker processed sequence 2 at %s before sequence 1 at %s", secondProcessed, firstProcessed)
	}

	var intervalEnded, intervalStarted time.Time
	if err := testPool.QueryRow(context.Background(), `
		SELECT ended_at, started_at
		FROM sandbox_storage_interval
		WHERE sandbox_id=$1 AND disk_mib=8 AND ended_at IS NOT NULL
		ORDER BY ended_at DESC LIMIT 1`, fixture.sandboxID).Scan(&intervalEnded, &intervalStarted); err != nil {
		t.Fatalf("read closed storage interval: %v", err)
	}
	if !intervalEnded.Equal(secondAck.ReceivedAt) {
		t.Fatalf("closed interval boundary = %s, want report received_at %s", intervalEnded, secondAck.ReceivedAt)
	}
	if err := testPool.QueryRow(context.Background(), `
		SELECT started_at
		FROM sandbox_storage_interval
		WHERE sandbox_id=$1 AND disk_mib=16 AND ended_at IS NULL`, fixture.sandboxID).Scan(&intervalStarted); err != nil {
		t.Fatalf("read reopened storage interval: %v", err)
	}
	if !intervalStarted.Equal(secondAck.ReceivedAt) {
		t.Fatalf("reopened interval boundary = %s, want report received_at %s", intervalStarted, secondAck.ReceivedAt)
	}

	staleID := uuid.New()
	stale := postStorageReport(t, storageReportFixture{hostID: fixture.hostID, incarnation: uuid.NewString(), sandboxID: fixture.sandboxID, router: fixture.router}, staleID, 16*1024*1024)
	if stale.Code != http.StatusConflict {
		t.Fatalf("stale incarnation status = %d, want 409; body=%s", stale.Code, stale.Body.String())
	}
	var staleRows int
	if err := testPool.QueryRow(context.Background(), `SELECT count(*) FROM host_storage_report WHERE report_id=$1`, staleID).Scan(&staleRows); err != nil {
		t.Fatalf("read stale report rows: %v", err)
	}
	if staleRows != 0 {
		t.Fatalf("stale report rows = %d, want 0", staleRows)
	}
}

func TestIntegration_StorageReportPayloadPersistenceDoesNotLockHeartbeatRow(t *testing.T) {
	fixture := newStorageReportFixture(t, "active", false)
	ctx := context.Background()
	reportID := uuid.New()
	triggerName := "aa_storage_report_gate_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	functionName := triggerName + "_fn"
	_, err := testPool.Exec(ctx, fmt.Sprintf(`
		CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.report_id = '%s'::uuid THEN
				PERFORM pg_advisory_xact_lock(hashtextextended(NEW.report_id::text, 1));
			END IF;
			RETURN NEW;
		END $$`, functionName, reportID))
	if err != nil {
		t.Fatalf("create report insert gate: %v", err)
	}
	t.Cleanup(func() { _, _ = testPool.Exec(context.Background(), "DROP FUNCTION "+functionName+"() CASCADE") })
	if _, err := testPool.Exec(ctx, fmt.Sprintf(`CREATE TRIGGER %s BEFORE INSERT ON host_storage_report FOR EACH ROW EXECUTE FUNCTION %s()`, triggerName, functionName)); err != nil {
		t.Fatalf("create report insert trigger: %v", err)
	}

	gate, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin report insert gate: %v", err)
	}
	defer gate.Rollback(ctx)
	if _, err := gate.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text, 1))`, reportID.String()); err != nil {
		t.Fatalf("lock report insert gate: %v", err)
	}
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() { result <- postStorageReport(t, fixture, reportID, 8*1024*1024) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting bool
		if err := testPool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_stat_activity
				WHERE wait_event='advisory' AND query LIKE '%INSERT INTO host_storage_report%'
			)`).Scan(&waiting); err != nil {
			t.Fatalf("inspect blocked report insert: %v", err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("report insert did not reach payload gate")
		}
		time.Sleep(10 * time.Millisecond)
	}

	lock, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin heartbeat row lock: %v", err)
	}
	defer lock.Rollback(ctx)
	var incarnation uuid.UUID
	if err := lock.QueryRow(ctx, `SELECT incarnation_id FROM host WHERE id=$1 FOR UPDATE NOWAIT`, fixture.hostID).Scan(&incarnation); err != nil {
		t.Fatalf("report payload persistence blocked heartbeat row: %v", err)
	}
	if incarnation.String() != fixture.incarnation {
		t.Fatalf("host incarnation = %s, want %s", incarnation, fixture.incarnation)
	}
	if err := lock.Commit(ctx); err != nil {
		t.Fatalf("release heartbeat row: %v", err)
	}
	if err := gate.Commit(ctx); err != nil {
		t.Fatalf("release report insert gate: %v", err)
	}
	select {
	case w := <-result:
		if w.Code != http.StatusCreated {
			t.Fatalf("report after gate release: %d %s", w.Code, w.Body.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("report insert did not finish after gate release")
	}
}

func TestIntegration_StorageWorkerFencesReclaimedIncarnation(t *testing.T) {
	fixture := newStorageReportFixture(t, "active", true)
	ctx := context.Background()
	reportID := uuid.New()
	payload := fmt.Sprintf(`[{"sandbox_id":%q,"allocated_bytes":16777216}]`, fixture.sandboxID)
	newIncarnation := uuid.New()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin reclaim transaction: %v", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `
		INSERT INTO host_storage_report(host_id, incarnation_id, report_id, ingest_seq, payload, next_attempt_at)
		VALUES ($1, $2::uuid, $3, 1, $4::jsonb, now()+interval '1 hour')`, fixture.hostID, fixture.incarnation, reportID, payload); err != nil {
		t.Fatalf("insert accepted report: %v", err)
	}
	if _, err := tx.Exec(ctx, `SELECT rebind_host_incarnation($1, $2::uuid, $3::uuid)`, fixture.hostID, fixture.incarnation, newIncarnation); err != nil {
		t.Fatalf("reclaim host: %v", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE host_storage_report SET next_attempt_at=now() WHERE report_id=$1`, reportID); err != nil {
		t.Fatalf("release fenced report: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit reclaim transaction: %v", err)
	}
	_, lastError := waitStorageReportState(t, reportID, "terminal")
	if !strings.Contains(lastError, "stale host incarnation") {
		t.Fatalf("fenced report error = %q, want stale host incarnation", lastError)
	}
	var intervalCount int
	if err := testPool.QueryRow(ctx, `
		SELECT count(*) FROM sandbox_storage_interval
		WHERE sandbox_id=$1 AND disk_mib=16`, fixture.sandboxID).Scan(&intervalCount); err != nil {
		t.Fatalf("read fenced interval: %v", err)
	}
	if intervalCount != 0 {
		t.Fatalf("stale report created %d interval rows", intervalCount)
	}
}

func TestIntegration_StorageWorkerRacesLifecycleActivation(t *testing.T) {
	tests := []struct {
		name   string
		status string
		claim  func(context.Context, storageReportFixture, uuid.UUID, chan<- struct{}) error
	}{
		{
			name:   "resume",
			status: "paused",
			claim: func(ctx context.Context, fixture storageReportFixture, teamID uuid.UUID, started chan<- struct{}) error {
				if _, err := testQueries.BeginResume(ctx, db.BeginResumeParams{ID: fixture.sandboxID, TeamID: teamID}); err != nil {
					return err
				}
				close(started)
				return testQueries.ActivateSandbox(ctx, db.ActivateSandboxParams{ID: fixture.sandboxID, TeamID: teamID, VcpuCount: 1, MemoryMib: 1024})
			},
		},
		{
			name:   "create",
			status: "starting",
			claim: func(ctx context.Context, fixture storageReportFixture, teamID uuid.UUID, started chan<- struct{}) error {
				close(started)
				return testQueries.ActivateSandbox(ctx, db.ActivateSandboxParams{ID: fixture.sandboxID, TeamID: teamID, VcpuCount: 1, MemoryMib: 1024})
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			testStorageWorkerLifecycleRace(t, tc.status, tc.claim)
		})
	}
}

func testStorageWorkerLifecycleRace(t *testing.T, sandboxStatus string, claim func(context.Context, storageReportFixture, uuid.UUID, chan<- struct{}) error) {
	t.Helper()
	fixture := newStorageReportFixture(t, sandboxStatus, true)
	ctx := context.Background()
	holder, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin interval holder: %v", err)
	}
	defer holder.Rollback(ctx)
	if _, err := holder.Exec(ctx, `SELECT 1 FROM sandbox_storage_interval WHERE sandbox_id=$1 AND ended_at IS NULL FOR UPDATE`, fixture.sandboxID); err != nil {
		_ = holder.Rollback(ctx)
		t.Fatalf("lock open storage interval: %v", err)
	}
	reportID := uuid.New()
	w := postStorageReport(t, fixture, reportID, 16*1024*1024)
	if w.Code != http.StatusCreated {
		_ = holder.Rollback(ctx)
		t.Fatalf("storage report: %d %s", w.Code, w.Body.String())
	}

	teamID := sandboxTeamID(t, fixture.sandboxID)
	activationStarted := make(chan struct{})
	activationDone := make(chan error, 1)
	go func() {
		activationDone <- claim(ctx, fixture, teamID, activationStarted)
	}()
	select {
	case <-activationStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("lifecycle activation did not start")
	}
	waitStorageReportState(t, reportID, "processing")
	if err := holder.Commit(ctx); err != nil {
		t.Fatalf("release interval holder: %v", err)
	}
	select {
	case err := <-activationDone:
		if err != nil {
			t.Fatalf("activation raced with storage worker: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("activation remained blocked after storage lock release")
	}
	waitStorageReportState(t, reportID, "processed")
	var status string
	if err := testPool.QueryRow(ctx, `SELECT status FROM sandbox WHERE id=$1`, fixture.sandboxID).Scan(&status); err != nil {
		t.Fatalf("read activated sandbox: %v", err)
	}
	if status != "active" {
		t.Fatalf("sandbox status=%q after activation race, want active", status)
	}
}

func sandboxTeamID(t *testing.T, sandboxID uuid.UUID) uuid.UUID {
	t.Helper()
	var teamID uuid.UUID
	if err := testPool.QueryRow(context.Background(), `SELECT team_id FROM sandbox WHERE id=$1`, sandboxID).Scan(&teamID); err != nil {
		t.Fatalf("read sandbox team: %v", err)
	}
	return teamID
}
