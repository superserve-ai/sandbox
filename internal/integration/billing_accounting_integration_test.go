//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestIntegration_BillingExportAccounting(t *testing.T) {
	store, period := seedIncrementalPeriod(t)
	_, otherTeam := seedIncrementalPeriod(t)
	otherPeriod := billing.ExportPeriod{TeamID: period.TeamID, Start: period.End, End: period.End.AddDate(0, 1, 0)}
	if _, err := testQueries.UpsertTeamBillingPeriod(t.Context(), db.UpsertTeamBillingPeriodParams{
		TeamID: otherPeriod.TeamID, PeriodStart: otherPeriod.Start, PeriodEnd: otherPeriod.End, Status: "approved",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Enroll(t.Context(), otherPeriod); err != nil {
		t.Fatal(err)
	}

	events := make(map[string]*billing.ExportEvent)
	var ids []string
	for i := 1; i <= 502; i++ {
		event := reserveIncrement(t, store, period, fmt.Sprint(i))
		if event == nil {
			t.Fatalf("missing reservation %d", i)
		}
		id := event.ID.String()
		events[id] = event
		ids = append(ids, id)
	}
	// Keep a real active lease so redaction cannot pass just because it is null.
	leased, err := store.Claim(t.Context(), period)
	if err != nil || leased == nil || leased.LeaseToken == uuid.Nil {
		t.Fatalf("claim: %+v %v", leased, err)
	}
	rejected := events[ids[0]]
	if rejected.ID == leased.ID {
		rejected = events[ids[1]]
	}
	if found, err := store.Reject(t.Context(), rejected.Identifier, "", rejected.CustomerID, rejected.EventName, "provider rejected event"); err != nil || !found {
		t.Fatalf("reject: %v %v", found, err)
	}

	observedAt := period.End.Add(time.Hour)
	for i, p := range []billing.ExportPeriod{period, otherTeam, otherPeriod} {
		if i > 0 {
			reserveIncrement(t, store, p, "99")
		}
		if _, err := testPool.Exec(t.Context(), `INSERT INTO billing_export_usage
			(team_id,period_start,period_end,vcpu_seconds) VALUES ($1,$2,$3,$4)`,
			p.TeamID, p.Start, p.End, 1807200+i); err != nil {
			t.Fatal(err)
		}
		if _, err := testPool.Exec(t.Context(), `INSERT INTO billing_export_observation
			(team_id,period_start,period_end,resource_type,local_quantity,submitted_quantity,reserved_quantity,
			 counted_quantity,observed_at,query_start,query_end,last_error)
			VALUES ($1,$2,$3,'cpu',502,0,502,7,$4,$2,$3,'provider total differs'),
			       ($1,$2,$3,'memory',3,2,3,NULL,$4,$2,$3,'provider summary unavailable')`,
			p.TeamID, p.Start, p.End, observedAt); err != nil {
			t.Fatal(err)
		}
	}
	workerLease := uuid.New()
	if _, err := testPool.Exec(t.Context(), `INSERT INTO billing_export_work
		(team_id,next_run_at,seed_complete,last_error,lease_token,lease_until)
		VALUES ($1,$2,true,'export retry pending',$3,$2)`, period.TeamID, observedAt, workerLease); err != nil {
		t.Fatal(err)
	}

	admin := seedPlatformAdminProfile(t)
	router := newBillingRouter(t, nil)
	path := "/internal/teams/" + period.TeamID.String() + "/billing/periods/" + apiPeriodID(period.Start, period.End) + "/export-accounting"
	for _, page := range []struct {
		name, after string
		start, end  int
	}{
		{name: "first", start: 0, end: 500},
		{name: "remaining", after: ids[499], start: 500, end: 502},
		{name: "exhausted", after: ids[501], start: 502, end: 502},
	} {
		t.Run(page.name, func(t *testing.T) {
			url := path
			if page.after != "" {
				url += "?after=" + page.after
			}
			response := doInternal(router, http.MethodGet, url, admin.String(), "")
			if response.Code != http.StatusOK {
				t.Fatalf("accounting: %d %s", response.Code, response.Body.String())
			}
			for _, secret := range []string{"lease_token", "lease_until", leased.LeaseToken.String(), workerLease.String()} {
				if strings.Contains(response.Body.String(), secret) {
					t.Fatalf("accounting exposed lease data: %s", secret)
				}
			}
			var body struct {
				Events           []map[string]any `json:"events"`
				Observations     []map[string]any `json:"observations"`
				LocalMeasurement map[string]any   `json:"local_measurement"`
				Worker           map[string]any   `json:"worker"`
			}
			decoder := json.NewDecoder(response.Body)
			decoder.UseNumber()
			if err := decoder.Decode(&body); err != nil {
				t.Fatal(err)
			}
			if len(body.Events) != page.end-page.start {
				t.Fatalf("event count=%d, want %d", len(body.Events), page.end-page.start)
			}
			for i, got := range body.Events {
				id := ids[page.start+i]
				want := events[id]
				status, lastError := "pending", any(nil)
				if want.ID == leased.ID {
					status = "uncertain"
				}
				if want.ID == rejected.ID {
					status, lastError = "rejected", "provider rejected event"
				}
				for field, value := range map[string]any{
					"id": id, "allocation_id": want.AllocationID.String(), "identifier": want.Identifier,
					"quantity_payload": "1.000000000000", "status": status, "last_error": lastError,
				} {
					if got[field] != value {
						t.Errorf("event %s %s=%v, want %v", id, field, got[field], value)
					}
				}
			}
			checkTime := func(row map[string]any, field string, want time.Time) {
				t.Helper()
				text, _ := row[field].(string)
				got, err := time.Parse(time.RFC3339Nano, text)
				if err != nil || !got.Equal(want) {
					t.Errorf("%s=%v, want %s", field, row[field], want)
				}
			}
			checkScope := func(row map[string]any) {
				t.Helper()
				if row["team_id"] != period.TeamID.String() {
					t.Errorf("wrong accounting scope: %+v", row)
				}
				checkTime(row, "period_start", period.Start)
				checkTime(row, "period_end", period.End)
			}
			checkScope(body.LocalMeasurement)
			if body.LocalMeasurement["vcpu_seconds"] != json.Number("1807200") {
				t.Errorf("local usage: %+v", body.LocalMeasurement)
			}
			if len(body.Observations) != 2 {
				t.Fatalf("observations=%+v, want only requested period's two resources", body.Observations)
			}
			seen := make(map[string]bool)
			for _, observation := range body.Observations {
				checkScope(observation)
				resource, _ := observation["resource_type"].(string)
				if seen[resource] || (resource != "cpu" && resource != "memory") {
					t.Fatalf("unexpected observation: %+v", observation)
				}
				seen[resource] = true
				local, submitted, reserved, counted, message := "502", "0", "502", any(json.Number("7")), "provider total differs"
				if resource == "memory" {
					local, submitted, reserved, counted, message = "3", "2", "3", nil, "provider summary unavailable"
				}
				for field, value := range map[string]any{
					"local_quantity": json.Number(local), "submitted_quantity": json.Number(submitted),
					"reserved_quantity": json.Number(reserved), "counted_quantity": counted, "last_error": message,
				} {
					if observation[field] != value {
						t.Errorf("%s observation %s=%v, want %v", resource, field, observation[field], value)
					}
				}
				checkTime(observation, "observed_at", observedAt)
				checkTime(observation, "query_start", period.Start)
				checkTime(observation, "query_end", period.End)
			}
			if body.Worker["seed_complete"] != true || body.Worker["last_error"] != "export retry pending" {
				t.Errorf("worker state: %+v", body.Worker)
			}
			checkTime(body.Worker, "next_run_at", observedAt)
		})
	}
}

func TestIntegration_BillingExportAccountingInsertionCursors(t *testing.T) {
	store, period := seedIncrementalPeriod(t)
	original := reserveIncrement(t, store, period, "1")
	created := time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)
	first := uuid.MustParse("80000000-0000-4000-8000-000000000001")
	tied := uuid.MustParse("80000000-0000-4000-8000-000000000002")
	later := uuid.MustParse("10000000-0000-4000-8000-000000000001")
	exec := testPool.Exec
	insert := func(id uuid.UUID, at time.Time) {
		t.Helper()
		if _, err := exec(t.Context(), `INSERT INTO billing_export_event
            (id,allocation_id,identifier,idempotency_key,event_name,customer_id,quantity,quantity_payload,event_timestamp,source,status,active,created_at)
            SELECT $1::uuid,allocation_id,($1::uuid)::text,($1::uuid)::text,event_name,customer_id,quantity,quantity_payload,event_timestamp,source,status,false,$3
            FROM billing_export_event WHERE id=$2`, id, original.ID, at); err != nil {
			t.Fatal(err)
		}
		if _, err := exec(t.Context(), `INSERT INTO billing_export_correction
            (id,team_id,period_start,period_end,resource_type,frozen,version,measured_quantity,baseline_quantity,reserved_quantity,target_quantity,measurement_snapshot,created_at)
            VALUES ($1,$2,$3,$4,'cpu',false,0,1,1,1,1,'fixture',$5)`, id, period.TeamID, period.Start, period.End, at); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := testPool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	var transactionStart time.Time
	if err := tx.QueryRow(t.Context(), `SELECT now()`).Scan(&transactionStart); err != nil {
		t.Fatal(err)
	}
	insert(first, created)
	insert(tied, created)
	admin := seedPlatformAdminProfile(t)
	router := newBillingRouter(t, nil)
	path := "/internal/teams/" + period.TeamID.String() + "/billing/periods/" + apiPeriodID(period.Start, period.End) + "/export-accounting"
	read := func(query string, wantEvents, wantCorrections []uuid.UUID) {
		t.Helper()
		response := doInternal(router, http.MethodGet, path+query, admin.String(), "")
		if response.Code != http.StatusOK {
			t.Fatalf("accounting: %d %s", response.Code, response.Body.String())
		}
		var body struct {
			Events      []struct{ ID uuid.UUID } `json:"events"`
			Corrections []struct{ ID uuid.UUID } `json:"corrections"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if len(body.Events) != len(wantEvents) || len(body.Corrections) != len(wantCorrections) {
			t.Fatalf("unexpected page for %s: %s", query, response.Body.String())
		}
		for i, want := range wantEvents {
			if body.Events[i].ID != want {
				t.Fatalf("event %d: got %s, want %s", i, body.Events[i].ID, want)
			}
		}
		for i, want := range wantCorrections {
			if body.Corrections[i].ID != want {
				t.Fatalf("correction %d: got %s, want %s", i, body.Corrections[i].ID, want)
			}
		}
	}
	read("", []uuid.UUID{original.ID, first, tied}, []uuid.UUID{first, tied})
	// A transaction begun before the previous page commits rows with an older timestamp.
	exec = tx.Exec
	insert(later, transactionStart)
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	read("?after="+tied.String()+"&after_correction="+tied.String(), []uuid.UUID{later}, []uuid.UUID{later})
	read("?after="+first.String(), []uuid.UUID{tied, later}, []uuid.UUID{first, tied, later})
	read("?after_correction="+first.String(), []uuid.UUID{original.ID, first, tied, later}, []uuid.UUID{tied, later})
	read("?after="+later.String()+"&after_correction="+later.String(), nil, nil)

	_, otherPeriod := seedIncrementalPeriod(t)
	foreign := reserveIncrement(t, store, otherPeriod, "1")
	foreignCorrection := uuid.New()
	if _, err := testPool.Exec(t.Context(), `INSERT INTO billing_export_correction
            (id,team_id,period_start,period_end,resource_type,frozen,version,measured_quantity,baseline_quantity,reserved_quantity,target_quantity,measurement_snapshot)
            VALUES ($1,$2,$3,$4,'cpu',false,0,1,1,1,1,'fixture')`, foreignCorrection, otherPeriod.TeamID, otherPeriod.Start, otherPeriod.End); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		"?after=invalid", "?after_correction=invalid",
		"?after=" + uuid.NewString(), "?after_correction=" + uuid.NewString(),
		"?after=" + foreign.ID.String(), "?after_correction=" + foreignCorrection.String(),
	} {
		response := doInternal(router, http.MethodGet, path+query, admin.String(), "")
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid cursor %s: %d %s", query, response.Code, response.Body.String())
		}
	}
}
