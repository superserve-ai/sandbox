//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/billing"
)

func TestIntegration_StorageReportReceiptFencesSettlement(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		for _, finalize := range []bool{false, true} {
			t.Run(fmt.Sprintf("legacy=%t/finalize=%t", legacy, finalize), func(t *testing.T) {
				ctx := t.Context()
				fixture := newStorageReportFixture(t, "active", true)
				teamID := sandboxTeamID(t, fixture.sandboxID)
				unrelated := newStorageReportFixture(t, "active", true)
				unrelatedTeamID := sandboxTeamID(t, unrelated.sandboxID)
				adminID := seedPlatformAdminProfile(t)
				billingRouter := newBillingRouter(t, &fakeStripeClient{})
				h := &api.Handlers{DB: testQueries, Pool: testPool}
				router := gin.New()
				router.POST("/internal/hosts/:host_id/heartbeat", h.HostHeartbeat)
				router.POST("/internal/hosts/:host_id/storage-reports", h.HostStorageReport)
				reportID := uuid.New()
				gate, err := testPool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer gate.Rollback(context.Background())
				blockerPID := gate.Conn().PgConn().PID()
				if legacy {
					functionName := "storage_settlement_gate_" + strings.ReplaceAll(uuid.NewString(), "-", "")
					if _, err := testPool.Exec(ctx, fmt.Sprintf(`
						CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
						BEGIN
							IF NEW.report_id = '%s'::uuid THEN
								PERFORM pg_advisory_xact_lock(hashtextextended(NEW.report_id::text, 1));
							END IF;
							RETURN NEW;
						END $$;
						CREATE TRIGGER %s BEFORE INSERT ON legacy_host_storage_report
						FOR EACH ROW EXECUTE FUNCTION %s()`, functionName, reportID, functionName, functionName)); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						defer cancel()
						if _, err := testPool.Exec(cleanupCtx, "DROP FUNCTION "+functionName+"() CASCADE"); err != nil {
							t.Errorf("remove settlement gate: %v", err)
						}
					})
					if _, err := gate.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text, 1))`, reportID.String()); err != nil {
						t.Fatal(err)
					}
				} else if _, err := gate.Exec(ctx, `SELECT id FROM host WHERE id=$1 FOR NO KEY UPDATE`, fixture.hostID); err != nil {
					t.Fatal(err)
				}

				requestCtx, cancelRequest := context.WithCancel(ctx)
				response := make(chan *httptest.ResponseRecorder, 1)
				requestDone := make(chan struct{})
				defer func() {
					cancelRequest()
					cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					_ = gate.Rollback(cleanupCtx)
					select {
					case <-requestDone:
					case <-cleanupCtx.Done():
						t.Error("storage receipt request did not stop after gate release")
					}
					h.WaitAsyncBookkeeping()
				}()
				go func() {
					defer close(requestDone)
					path := "/internal/hosts/" + fixture.hostID + "/storage-reports"
					body := fmt.Sprintf(`{"incarnation_id":%q,"report_id":%q,"measurements":[{"sandbox_id":%q,"allocated_bytes":16777216}]}`,
						fixture.incarnation, reportID, fixture.sandboxID)
					if legacy {
						path = "/internal/hosts/" + fixture.hostID + "/heartbeat"
						body = storageReceiptHeartbeatBody(fixture, reportID)
					}
					w := httptest.NewRecorder()
					router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)).WithContext(requestCtx))
					response <- w
				}()
				if legacy {
					waitForStorageReceiptLock(t, reportID.String(), 1)
					var firstAttempt time.Time
					if err := testPool.QueryRow(ctx, `SELECT max(a.query_start)
						FROM pg_locks l JOIN pg_stat_activity a USING(pid)
						WHERE l.locktype='advisory' AND NOT l.granted AND l.objsubid=1
						  AND l.classid=((hashtextextended($1::text,1)>>32)&4294967295)::oid
						  AND l.objid=(hashtextextended($1::text,1)&4294967295)::oid`, reportID.String()).Scan(&firstAttempt); err != nil {
						t.Fatal(err)
					}
					w := awaitStorageReceiptResponse(t, response, http.StatusOK)
					var heartbeat struct {
						StorageAccepted bool `json:"storage_accepted"`
					}
					if err := json.Unmarshal(w.Body.Bytes(), &heartbeat); err != nil {
						t.Fatal(err)
					}
					if heartbeat.StorageAccepted {
						t.Fatal("legacy heartbeat acknowledged a blocked durable handoff")
					}
					// Exercise the longer-lived retry, so settlement is not racing the
					// inline handoff's two-second deadline on slower test machines.
					waitForStorageSettlementRetry(t, reportID, firstAttempt)
				} else {
					waitForStorageSettlementFence(t, blockerPID)
				}

				var cutoff time.Time
				if err := testPool.QueryRow(ctx, `SELECT date_trunc('second',clock_timestamp())+interval '1 second'`).Scan(&cutoff); err != nil {
					t.Fatal(err)
				}
				cutoff = cutoff.UTC()
				waitForStorageSettlementCutoff(t, cutoff)
				anchor := time.Date(cutoff.Year()-1, time.January, cutoff.Day(), cutoff.Hour(), cutoff.Minute(), cutoff.Second(), cutoff.Nanosecond(), time.UTC)
				start, end, ok := billing.AnniversaryPeriod(anchor, cutoff.Add(-time.Nanosecond))
				if !ok || !end.Equal(cutoff) {
					t.Fatal("fixture did not create a commercial period ending at the receipt cutoff")
				}
				seedStorageSettlementPeriod(t, teamID, anchor, start, cutoff, finalize)
				seedStorageSettlementPeriod(t, unrelatedTeamID, anchor, start, cutoff, finalize)
				var visible, complete bool
				if err := testPool.QueryRow(ctx, `SELECT
					EXISTS(SELECT 1 FROM host_storage_report WHERE report_id=$1)
					OR EXISTS(SELECT 1 FROM legacy_host_storage_report WHERE report_id=$1),
					storage_reports_complete_through($2,$3)`, reportID, teamID, cutoff).Scan(&visible, &complete); err != nil {
					t.Fatal(err)
				}
				if visible || !complete {
					t.Fatalf("fixture did not expose the MVCC gap: visible=%t complete=%t", visible, complete)
				}
				settle := func(id uuid.UUID) error {
					if finalize {
						_, err := billing.FinalizeTeamBillingPeriodWithCredits(ctx, testPool, id, start, cutoff)
						return err
					}
					periodID := start.Format(time.RFC3339Nano) + "," + cutoff.Format(time.RFC3339Nano)
					w := doInternal(billingRouter, http.MethodPost, "/internal/teams/"+id.String()+"/billing/periods/"+periodID+"/export", adminID.String(), "")
					if w.Code == http.StatusConflict && strings.Contains(w.Body.String(), "storage reports are still being accepted or processed") {
						return billing.ErrStorageReportsIncomplete
					}
					if w.Code != http.StatusOK {
						return fmt.Errorf("export response %d: %s", w.Code, w.Body.String())
					}
					return nil
				}
				if err := settle(teamID); !errors.Is(err, billing.ErrStorageReportsIncomplete) {
					t.Fatalf("settled across an uncommitted receipt: %v", err)
				}
				if err := settle(unrelatedTeamID); err != nil {
					t.Fatalf("unrelated host's settlement was blocked: %v", err)
				}
				if !legacy {
					select {
					case w := <-response:
						t.Fatalf("receipt escaped its gate before settlement checks: %d %s", w.Code, w.Body.String())
					default:
					}
				}
				if err := gate.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				if legacy {
					h.WaitAsyncBookkeeping()
				} else {
					awaitStorageReceiptResponse(t, response, http.StatusCreated)
				}
				waitStorageReportState(t, reportID, "processed")
				var receivedAt time.Time
				var diskMiB int
				if err := testPool.QueryRow(ctx, `SELECT r.received_at, i.disk_mib
					FROM host_storage_report r JOIN sandbox_storage_interval i ON i.started_at=r.received_at
					WHERE r.report_id=$1 AND i.sandbox_id=$2 AND i.ended_at IS NULL`, reportID, fixture.sandboxID).Scan(&receivedAt, &diskMiB); err != nil {
					t.Fatal(err)
				}
				if !receivedAt.Before(cutoff) || diskMiB != 16 {
					t.Fatalf("report did not revise the settlement window: received=%s cutoff=%s disk=%d", receivedAt, cutoff, diskMiB)
				}
				if err := settle(teamID); err != nil {
					t.Fatalf("settlement did not recover after report processing: %v", err)
				}
				if !finalize {
					var incorporated bool
					if err := testPool.QueryRow(ctx, `SELECT u.storage_mib_seconds=(
						SELECT sum(i.disk_mib * extract(epoch FROM LEAST(COALESCE(i.ended_at,$3),$3)-GREATEST(i.started_at,$2)))
						FROM sandbox_storage_interval i WHERE i.team_id=$1 AND i.started_at<$3
						  AND COALESCE(i.ended_at,$3)>$2)
						FROM team_billing_usage u WHERE u.team_id=$1 AND u.period_start=$2 AND u.period_end=$3`, teamID, start, cutoff).Scan(&incorporated); err != nil {
						t.Fatal(err)
					}
					if !incorporated {
						t.Fatal("export retry froze usage without the committed storage report")
					}
				}
			})
		}
	}
}

func seedStorageSettlementPeriod(t *testing.T, teamID uuid.UUID, anchor, start, end time.Time, exported bool) {
	t.Helper()
	if _, err := testPool.Exec(t.Context(), `INSERT INTO team_billing_account(team_id,commercial_billing_anchor)
		VALUES ($1,$2) ON CONFLICT(team_id) DO UPDATE SET commercial_billing_anchor=EXCLUDED.commercial_billing_anchor`, teamID, anchor); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(t.Context(), `INSERT INTO team_feature_flag(team_id,key,enabled)
		VALUES ($1,'billing_export_enabled',false) ON CONFLICT(team_id,key) DO UPDATE SET enabled=false`, teamID); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(t.Context(), `INSERT INTO team_billing_usage(team_id,period_start,period_end,vcpu_seconds,memory_mib_seconds,storage_mib_seconds)
		VALUES ($1,$2,$3,0,0,0)`, teamID, start, end); err != nil {
		t.Fatal(err)
	}
	status := "approved"
	if exported {
		status = "exported"
	}
	if _, err := testPool.Exec(t.Context(), `INSERT INTO team_billing_period(team_id,period_start,period_end,status,exported_at)
		VALUES ($1,$2,$3,$4,CASE WHEN $4='exported' THEN now() ELSE NULL END)`, teamID, start, end, status); err != nil {
		t.Fatal(err)
	}
}

func waitForStorageSettlementFence(t *testing.T, blockerPID uint32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	for {
		var waiting bool
		if err := testPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity
			WHERE $1::int=ANY(pg_blocking_pids(pid)) AND wait_event_type='Lock'
			  AND query LIKE '%SELECT incarnation_id FROM host%FOR UPDATE%')`, blockerPID).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("storage report did not wait at its final identity fence")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func waitForStorageSettlementRetry(t *testing.T, reportID uuid.UUID, firstAttempt time.Time) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for {
		var waiting bool
		if err := testPool.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1 FROM pg_locks l JOIN pg_stat_activity a USING(pid)
			WHERE l.locktype='advisory' AND NOT l.granted AND l.objsubid=1
			  AND l.classid=((hashtextextended($1::text,1)>>32)&4294967295)::oid
			  AND l.objid=(hashtextextended($1::text,1)&4294967295)::oid
			  AND a.query_start>$2)`, reportID.String(), firstAttempt).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("legacy storage retry did not reach its receipt gate")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func waitForStorageSettlementCutoff(t *testing.T, cutoff time.Time) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	for {
		var closed bool
		if err := testPool.QueryRow(ctx, `SELECT clock_timestamp()>$1`, cutoff).Scan(&closed); err != nil {
			t.Fatal(err)
		}
		if closed {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("database clock did not reach settlement cutoff")
		case <-time.After(5 * time.Millisecond):
		}
	}
}
