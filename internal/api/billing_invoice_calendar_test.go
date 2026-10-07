package api

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/superserve-ai/sandbox/internal/billing"
)

func TestInvoiceCalendarPeriod(t *testing.T) {
	parse := func(s string) time.Time {
		v, e := time.Parse(time.RFC3339, s)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	for _, tc := range []struct {
		name, start, end, anchor, providerStart, providerEnd, wantStart, wantEnd string
		valid                                                                    bool
	}{
		{"aligned", "2026-09-03T22:36:00Z", "2026-10-03T22:36:00Z", "2026-09-03T22:36:00Z", "2026-10-03T22:36:00Z", "2026-11-03T22:36:00Z", "2026-09-03T22:36:00Z", "2026-10-03T22:36:00Z", true},
		{"legacy first cycle", "2026-09-03T22:36:00Z", "2026-10-03T22:36:00Z", "2026-09-07T10:20:10Z", "2026-10-07T10:20:10Z", "2026-11-07T10:20:10Z", "2026-09-07T10:20:10Z", "2026-10-07T10:20:10Z", true},
		{"next cycle", "2026-10-03T22:36:00Z", "2026-11-03T22:36:00Z", "2026-09-07T10:20:10Z", "2026-10-07T10:20:10Z", "2026-11-07T10:20:10Z", "2026-10-07T10:20:10Z", "2026-11-07T10:20:10Z", true},
		{"late activation", "2026-09-03T22:36:00Z", "2026-10-03T22:36:00Z", "2026-10-01T13:17:12Z", "2026-10-01T13:17:12Z", "2026-11-01T13:17:12Z", "2026-10-01T13:17:12Z", "2026-11-01T13:17:12Z", true},
		{"UTC month end", "2026-02-03T22:36:00Z", "2026-03-03T22:36:00Z", "2026-01-31T23:00:00Z", "2026-02-28T23:00:00Z", "2026-03-31T23:00:00Z", "2026-02-28T23:00:00Z", "2026-03-31T23:00:00Z", true},
		{"before subscription", "2026-08-03T22:36:00Z", "2026-09-03T22:36:00Z", "2026-09-07T10:20:10Z", "2026-09-07T10:20:10Z", "2026-10-07T10:20:10Z", "", "", false},
		{"same minute offset", "2026-09-03T22:36:00Z", "2026-10-03T22:36:00Z", "2026-09-03T22:35:30Z", "2026-09-03T22:35:30Z", "2026-10-03T22:35:30Z", "", "", false},
		{"irregular provider period", "2026-09-03T22:36:00Z", "2026-10-03T22:36:00Z", "2026-09-07T10:20:10Z", "2026-09-07T10:20:10Z", "2026-10-08T10:20:10Z", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := billing.ExportPeriod{Start: parse(tc.start), End: parse(tc.end)}
			raw, _ := json.Marshal(map[string]any{"billing_cycle_anchor": parse(tc.anchor).Unix(), "items": map[string]any{"data": []any{map[string]any{"price": map[string]any{"id": "cpu"}, "current_period_start": parse(tc.providerStart).Unix(), "current_period_end": parse(tc.providerEnd).Unix()}, map[string]any{"price": map[string]any{"id": "round"}}}}})
			var sub invoiceSubscription
			if err := json.Unmarshal(raw, &sub); err != nil {
				t.Fatal(err)
			}
			got, err := invoiceCalendarPeriod(p, sub, "round")
			if !tc.valid {
				if err == nil {
					t.Fatalf("accepted %+v", got)
				}
				return
			}
			if err != nil || !got.Start.Equal(parse(tc.wantStart)) || !got.End.Equal(parse(tc.wantEnd)) {
				t.Fatalf("got %+v, %v", got, err)
			}
			if got.TeamID != p.TeamID {
				t.Fatal("team changed")
			}
		})
	}
}

func TestInvoicePlanPeriodLegacy(t *testing.T) {
	p := billing.ExportPeriod{Start: time.Unix(100, 0), End: time.Unix(200, 0)}
	if got := invoicePlanPeriod(p, billing.InvoiceClosePlan{}); got != p {
		t.Fatal("legacy period changed")
	}
	got := invoicePlanPeriod(p, billing.InvoiceClosePlan{InvoiceStart: 150, InvoiceEnd: 250})
	if got.Start.Unix() != 150 || got.End.Unix() != 250 {
		t.Fatal(got)
	}
}

func TestInvoiceCalendarRejectsMonthEndCollision(t *testing.T) {
	commercial := time.Date(2026, 1, 30, 22, 36, 0, 0, time.UTC)
	provider := time.Date(2026, 1, 31, 10, 0, 0, 0, time.UTC)
	start, end, _ := billing.AnniversaryPeriod(provider, provider)
	raw, _ := json.Marshal(map[string]any{"billing_cycle_anchor": provider.Unix(), "items": map[string]any{"data": []any{map[string]any{"price": map[string]any{"id": "cpu"}, "current_period_start": start.Unix(), "current_period_end": end.Unix()}}}})
	var sub invoiceSubscription
	if err := json.Unmarshal(raw, &sub); err != nil {
		t.Fatal(err)
	}
	if err := invoiceCalendarCompatible(commercial, sub, "round"); err == nil {
		t.Fatal("accepted a schedule that assigns two periods to one invoice")
	}
	if err := invoiceCalendarCompatible(provider, sub, "round"); err != nil {
		t.Fatalf("aligned month-end rejected: %v", err)
	}
	if err := invoiceCalendarCompatible(time.Date(2026, 1, 3, 22, 36, 0, 0, time.UTC), sub, "round"); err != nil {
		t.Fatalf("stable mismatched calendar rejected: %v", err)
	}
}
