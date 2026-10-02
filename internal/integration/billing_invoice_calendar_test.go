//go:build integration

package integration

import (
	"testing"
	"time"

	"github.com/superserve-ai/sandbox/internal/billing"
)

func TestIntegration_InvoiceCalendarGuards(t *testing.T) {
	store, p := seedIncrementalPeriod(t)
	customer, sub := "cus_"+p.TeamID.String(), "sub_"+p.TeamID.String()
	correctionExec(t, `INSERT INTO billing_invoice_account(team_id,customer_id,subscription_id,adjustment_price_id,adjustment_event_name,adjustment_meter_id,enrolled_at) VALUES($1,$2,$3,'price_round','round','mtr_round',$4)`, p.TeamID, customer, sub, p.Start)
	mappedStart, mappedEnd := p.Start.Add(4*24*time.Hour), p.End.Add(4*24*time.Hour)
	insertMap := func(period billing.ExportPeriod, start, end time.Time) error {
		_, err := testPool.Exec(t.Context(), `INSERT INTO billing_invoice_calendar(team_id,period_start,period_end,customer_id,subscription_id,invoice_start,invoice_end,billing_cycle_anchor) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, period.TeamID, period.Start, period.End, customer, sub, start, end, mappedStart.Unix())
		return err
	}
	if err := insertMap(p, mappedStart, mappedEnd); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reserve(t.Context(), p, "cpu", "1", p.End, billing.ExportPayload{CustomerID: customer, EventName: "example_cpu_hours", Timestamp: mappedStart.Add(-time.Second).Unix()}); err == nil {
		t.Fatal("accepted export before provider cycle")
	}
	if _, err := store.Reserve(t.Context(), p, "cpu", "1", p.End, billing.ExportPayload{CustomerID: customer, EventName: "example_cpu_hours", Timestamp: p.End.Add(-time.Second).Unix()}); err != nil {
		t.Fatal(err)
	}
	event := acceptIncrement(t, store, p)
	next := billing.ExportPeriod{TeamID: p.TeamID, Start: p.End, End: p.End.AddDate(0, 1, 0)}
	correctionExec(t, `INSERT INTO team_billing_period(team_id,period_start,period_end,status) VALUES($1,$2,$3,'approved')`, next.TeamID, next.Start, next.End)
	if err := store.Enroll(t.Context(), next); err != nil {
		t.Fatal(err)
	}
	// An old replica has not created a mapping for the next commercial period.
	// Its event must still not leak onto the previous invoice.
	if _, err := store.Reserve(t.Context(), next, "cpu", "1", mappedEnd, billing.ExportPayload{CustomerID: customer, EventName: "example_cpu_hours", Timestamp: mappedEnd.Add(-time.Second).Unix()}); err == nil {
		t.Fatal("legacy writer leaked next-period usage onto prior invoice")
	}
	if err := insertMap(next, mappedStart, mappedEnd); err == nil {
		t.Fatal("assigned two periods to one invoice")
	}
	if err := insertMap(next, mappedEnd, mappedEnd.AddDate(0, 1, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reserve(t.Context(), next, "cpu", "1", mappedEnd.Add(time.Hour), billing.ExportPayload{CustomerID: customer, EventName: "example_cpu_hours", Timestamp: mappedEnd.Unix()}); err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{`UPDATE billing_invoice_calendar SET invoice_end=invoice_end+interval '1 day' WHERE team_id=$1`, `DELETE FROM billing_invoice_calendar WHERE team_id=$1`} {
		if _, err := testPool.Exec(t.Context(), sql, p.TeamID); err == nil {
			t.Fatal("calendar history was mutable")
		}
	}
	var unchanged bool
	if err := testPool.QueryRow(t.Context(), `SELECT identifier=$2 AND quantity_payload=$4 AND event_timestamp=$3 AND status='submitted' AND active FROM billing_export_event WHERE id=$1`, event.ID, event.Identifier, event.Timestamp, event.Quantity).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("accepted event changed", err)
	}
}

func TestIntegration_InvoiceCalendarRejectsCrossingHistory(t *testing.T) {
	for _, otherPeriod := range []bool{false, true} {
		t.Run(map[bool]string{false: "own event before cycle", true: "other period in cycle"}[otherPeriod], func(t *testing.T) {
			store, p := seedIncrementalPeriod(t)
			customer, sub := "cus_"+p.TeamID.String(), "sub_"+p.TeamID.String()
			mappedStart, mappedEnd := p.Start.Add(4*24*time.Hour), p.End.Add(4*24*time.Hour)
			eventPeriod, at := p, p.Start.Add(time.Hour)
			if otherPeriod {
				eventPeriod = billing.ExportPeriod{TeamID: p.TeamID, Start: p.End, End: p.End.AddDate(0, 1, 0)}
				at = p.End.Add(time.Hour)
				correctionExec(t, `INSERT INTO team_billing_period(team_id,period_start,period_end,status) VALUES($1,$2,$3,'approved')`, p.TeamID, eventPeriod.Start, eventPeriod.End)
				if err := store.Enroll(t.Context(), eventPeriod); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := store.Reserve(t.Context(), eventPeriod, "cpu", "1", at.Add(time.Hour), billing.ExportPayload{CustomerID: customer, EventName: "example_cpu_hours", Timestamp: at.Unix()}); err != nil {
				t.Fatal(err)
			}
			acceptIncrement(t, store, eventPeriod)
			correctionExec(t, `INSERT INTO billing_invoice_account(team_id,customer_id,subscription_id,adjustment_price_id,adjustment_event_name,adjustment_meter_id,enrolled_at) VALUES($1,$2,$3,'price_round','round','mtr_round',$4)`, p.TeamID, customer, sub, p.Start)
			if _, err := testPool.Exec(t.Context(), `INSERT INTO billing_invoice_calendar(team_id,period_start,period_end,customer_id,subscription_id,invoice_start,invoice_end,billing_cycle_anchor) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, p.TeamID, p.Start, p.End, customer, sub, mappedStart, mappedEnd, mappedStart.Unix()); err == nil {
				t.Fatal("silently reassigned incompatible accepted history")
			}
		})
	}
}

func TestIntegration_InvoiceCalendarPartialMinuteEvents(t *testing.T) {
	for _, historical := range []bool{false, true} {
		t.Run(map[bool]string{false: "new legacy event", true: "accepted history"}[historical], func(t *testing.T) {
			store, p := seedIncrementalPeriod(t)
			customer, sub := "cus_"+p.TeamID.String(), "sub_"+p.TeamID.String()
			mappedStart := p.Start.Add(4*24*time.Hour + 59*time.Minute + 10*time.Second)
			mappedEnd := mappedStart.AddDate(0, 1, 0)
			reserve := func() error {
				_, err := store.Reserve(t.Context(), p, "cpu", "1", mappedStart.Truncate(time.Hour).Add(time.Hour), billing.ExportPayload{CustomerID: customer, EventName: "example_cpu_hours", Timestamp: mappedStart.Add(49 * time.Second).Unix()})
				return err
			}
			if historical {
				if err := reserve(); err != nil {
					t.Fatal(err)
				}
				acceptIncrement(t, store, p)
			}
			correctionExec(t, `INSERT INTO billing_invoice_account(team_id,customer_id,subscription_id,adjustment_price_id,adjustment_event_name,adjustment_meter_id,enrolled_at) VALUES($1,$2,$3,'price_round','round','mtr_round',$4)`, p.TeamID, customer, sub, p.Start)
			_, err := testPool.Exec(t.Context(), `INSERT INTO billing_invoice_calendar(team_id,period_start,period_end,customer_id,subscription_id,invoice_start,invoice_end,billing_cycle_anchor) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, p.TeamID, p.Start, p.End, customer, sub, mappedStart, mappedEnd, mappedStart.Unix())
			if historical {
				if err == nil {
					t.Fatal("accepted historical event excluded by provider observation")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := reserve(); err == nil {
				t.Fatal("accepted new event excluded by provider observation")
			}
		})
	}
}
