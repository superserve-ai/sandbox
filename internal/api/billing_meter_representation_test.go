package api

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/superserve-ai/sandbox/internal/billing"
)

var meterRepresentationCases = []struct {
	provider, local string
	want            bool
}{
	{"24695.364339748336", "24695.364339748334", true},
	{"24695.364339748334", "24695.364339748336", true},
	{"34407.81931579778", "34407.819315797778", true},
	{"10000.0000000000005", "10000", true},
	{"9999.9999999999995", "10000", true},
	{"10000.000000000001", "10000", false}, // within one ULP, different representations
	{"0", "0", true},
	{"0.000000000001", "0", false},
	{"0", "0.000000000001", false},
	{"1e-400", "2e-400", false},
	{"1e400", "2e400", false},
	{"0.00000000000090000000000000001", "0.0000000000009", false},
	{"1000000001.000000000001", "1000000001", false},
	{"1000000001", "1000000001", true}, // exact equality outside precision range
	{"-1", "-1", false},
	// Halfway above 1 rounds to the even significand; just above it does not.
	{"1.00000000000000011102230246251565404236316680908203125", "1", true},
	{"1.000000000000000111022302462515654042363166809082031251", "1", false},
	// The next significand is odd, so its upper midpoint rounds away.
	{"1.00000000000000033306690738754696212708950042724609375", "1.0000000000000002220446049250313080847263336181640625", false},
}

func TestMeterRepresentation(t *testing.T) {
	for _, tc := range meterRepresentationCases {
		provider, _ := new(big.Rat).SetString(tc.provider)
		local, _ := new(big.Rat).SetString(tc.local)
		if got := meterPrecisionEquivalent(provider, local); got != tc.want {
			t.Fatalf("%s/%s: got %v, want %v", tc.provider, tc.local, got, tc.want)
		}
	}
}

func TestMeterBucketPassStability(t *testing.T) {
	a := []meterCloseBucket{{Start: 1, End: 2, Quantity: "24695.364339748334"}}
	b := []meterCloseBucket{{Start: 1, End: 2, Quantity: "24695.364339748336"}}
	if sameMeterBucketPass(a, b) {
		t.Fatal("different decimal reads were treated as stable")
	}
	b[0].Quantity = a[0].Quantity + "0"
	if !sameMeterBucketPass(a, b) {
		t.Fatal("decimal formatting changed the numeric comparison")
	}
}

type unavailableBucketReader struct{}

func (unavailableBucketReader) CountedMeterUsage(context.Context, string, string, time.Time, time.Time) (string, error) {
	return "10000", nil
}

func TestMeterNegativeRepresentationWithoutEvidenceStaysLag(t *testing.T) {
	// Pending coverage can itself fit inside a float cell. Its absence must not
	// block delivery, and cannot authorize a close without submitted evidence.
	h := &Handlers{}
	p := billing.ExportPeriod{Start: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), End: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)}
	totals := billing.ExportTotals{Reserved: "100000.000000000001", Submitted: "100000", Pending: "0.000000000001"}
	for _, through := range []time.Time{p.Start.Add(time.Hour), p.End} {
		d := h.assessMeterSummary(t.Context(), p, incrementalExportItem{ResourceType: "storage", Quantity: totals.Reserved}, through,
			unavailableBucketReader{}, "cus_example", totals.Submitted, totals, nil)
		if d.Err != nil || d.Outcome != "provider_lag" || d.CloseEvidence != nil {
			t.Fatalf("lag became delivery hold or close evidence: %+v", d)
		}
	}
}
