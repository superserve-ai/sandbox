package api

import (
	"encoding/json"
	"math"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestTrialRunwayState(t *testing.T) {
	now := time.Now().UTC()
	sample := trialBurnSample{SpentUSD: 1, Started: now.Add(-time.Hour), Ended: now}
	for _, tc := range []struct {
		name      string
		remaining float64
		sample    trialBurnSample
		want      string
	}{
		{"under", 23, sample, "under_24h"},
		{"boundary", 24, sample, "over_24h"},
		{"over", 25, sample, "over_24h"},
		{"exhausted", 0, sample, "unknown"},
		{"invalid", math.NaN(), sample, "unknown"},
		{"missing", 1, trialBurnSample{}, "unknown"},
		{"stale", 1, trialBurnSample{SpentUSD: 1, Started: now.Add(-time.Hour), Ended: now.Add(-15 * time.Minute)}, "unknown"},
		{"insufficient", 1, trialBurnSample{SpentUSD: 0.01, Started: now.Add(-time.Hour), Ended: now}, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := trialRunwayState(tc.remaining, now, tc.sample); got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestBillingTrialRunwayFreshnessAndJSON(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name, state, trial, want string
		age                      time.Duration
		missing                  bool
	}{
		{"under", "under_24h", "active", "under_24h", time.Minute, false},
		{"over", "over_24h", "active", "over_24h", time.Minute, false},
		{"unknown", "unknown", "active", "unknown", time.Minute, false},
		{"stale", "under_24h", "active", "unknown", 15 * time.Minute, false},
		{"future", "under_24h", "active", "unknown", -time.Minute, false},
		{"ended", "under_24h", "exhausted", "unknown", time.Minute, false},
		{"missing", "", "active", "unknown", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := db.GetTeamTrialRunwayRow{State: tc.state, ObservedAt: pgtype.Timestamptz{Time: now.Add(-tc.age), Valid: !tc.missing}}
			state, observed := billingTrialRunway(row, true, tc.trial, now)
			if state != tc.want || (observed == nil) != tc.missing {
				t.Fatalf("state=%s observed=%v", state, observed)
			}
			if observed != nil && !observed.Equal(row.ObservedAt.Time) {
				t.Fatal("freshness timestamp was replaced")
			}
			payload, err := json.Marshal(billingTrialBalance{RunwayState: state, RunwayObservedAt: observed})
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]any
			if err = json.Unmarshal(payload, &fields); err != nil {
				t.Fatal(err)
			}
			if fields["runway_state"] != tc.want {
				t.Fatalf("JSON: %s", payload)
			}
			for key := range fields {
				switch key {
				case "grant_usd", "consumed_usd", "remaining_usd", "state", "eligible", "runway_state", "runway_observed_at":
				default:
					t.Fatalf("unexpected public field %s", key)
				}
			}
		})
	}
}
