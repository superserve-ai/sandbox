package billing

import (
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestAdoptionBoundaryValidation(t *testing.T) {
	start := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	p := ExportPeriod{Start: start, End: start.AddDate(0, 1, 0)}
	through := start.Add(time.Hour)
	for _, tc := range []struct {
		name      string
		through   time.Time
		timestamp int64
		valid     bool
	}{
		{"open", through, through.Add(-time.Second).Unix(), true},
		{"close", p.End, p.End.Add(-time.Second).Unix(), true},
		{"partial_minute", through.Add(30 * time.Second), through.Add(-time.Second).Unix(), true},
		{"later_boundary", through.Add(time.Hour), through.Add(-time.Second).Unix(), false},
		{"earlier_boundary", through.Add(-time.Minute), through.Add(-time.Second).Unix(), false},
		{"timestamp_at_boundary", through, through.Unix(), false},
		{"empty_coverage", start, start.Add(-time.Second).Unix(), false},
		{"outside_period", p.End.Add(time.Minute), p.End.Add(time.Minute - time.Second).Unix(), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := AdoptedExport{Through: tc.through, ExportPayload: ExportPayload{Timestamp: tc.timestamp}}
			if err := e.ValidateBoundary(p); (err == nil) != tc.valid {
				t.Fatalf("boundary validation = %v, want valid=%v", err, tc.valid)
			}
		})
	}
}

func TestDecimalDeltaReservesOutstandingCoverage(t *testing.T) {
	for _, tc := range []struct{ total, reserved, want string }{
		{"15", "10", "5.000000000000"}, {"15", "15", "0.000000000000"},
		{"12345.123456789100", "12345.123456789099", "0.000000000001"},
		{"1000000000000000000.000000000001", "1000000000000000000", "0.000000000001"},
	} {
		got, err := DecimalDelta(tc.total, tc.reserved)
		if err != nil || got != tc.want {
			t.Fatalf("delta(%s,%s)=%s,%v; want %s", tc.total, tc.reserved, got, err, tc.want)
		}
	}
	if _, err := DecimalDelta("9", "10"); !errors.Is(err, ErrExportRecoveryRequired) {
		t.Fatalf("downward correction: %v", err)
	}
	for _, invalid := range []string{"NaN", "+Inf", "-1", "1/2", "0.0000000000001"} {
		if _, err := DecimalDelta(invalid, "0"); err == nil {
			t.Fatalf("accepted invalid quantity %q", invalid)
		}
	}
}

func TestDecimalDeltaPartitionDoesNotChangeFinalBill(t *testing.T) {
	for _, checkpoints := range [][]string{
		{"0.000000000001", "0.000000000002", "0.333333333333", "1.000000000001"},
		{"0.333333333333", "1.000000000001"},
		{"1.000000000001"},
	} {
		total := new(big.Rat)
		reserved := "0"
		for _, checkpoint := range checkpoints {
			delta, err := DecimalDelta(checkpoint, reserved)
			if err != nil {
				t.Fatal(err)
			}
			value, _ := new(big.Rat).SetString(delta)
			total.Add(total, value)
			reserved = checkpoint
		}
		want, _ := new(big.Rat).SetString("1.000000000001")
		if total.Cmp(want) != 0 {
			t.Fatalf("partition changed bill: %s", total.RatString())
		}
	}
}

func TestMeterQuantitySplitPreservesOverPrecisionDelta(t *testing.T) {
	remaining := "12345.123456789123"
	sum := new(big.Rat)
	for part := 0; part < 2; part++ {
		quantity, err := meterQuantityPrefix(remaining)
		if err != nil {
			t.Fatal(err)
		}
		digits := 0
		for _, r := range quantity {
			if r >= '0' && r <= '9' {
				digits++
			}
		}
		if digits > 15 {
			t.Fatalf("payload has %d digits: %s", digits, quantity)
		}
		value, _ := new(big.Rat).SetString(quantity)
		sum.Add(sum, value)
		remaining, err = DecimalDelta(remaining, quantity)
		if err != nil {
			t.Fatal(err)
		}
	}
	expected, _ := new(big.Rat).SetString("12345.123456789123")
	if sum.Cmp(expected) != 0 || remaining != "0.000000000000" {
		t.Fatalf("split changed quantity: %s remainder %s", sum.RatString(), remaining)
	}
}

func TestMeterUsageQuantityPrecision(t *testing.T) {
	for _, tc := range []struct{ resource, seconds, want string }{
		{"vcpu", "44442444.4444408428", "12345.123456789123"},
		{"memory_gib", "45509063111.1074230272", "12345.123456789123"},
		{"storage_gib", "45509063111.1074230272", "12345.123456789123"},
		{"vcpu", "0.000000001799999999", "0.000000000000"},
		{"vcpu", "0.0000000018", "0.000000000001"},
		{"vcpu", "0.000000001800000001", "0.000000000001"},
		{"vcpu", "1", "0.000277777778"},
		{"memory_gib", "1", "0.000000271267"},
		{"vcpu", "0", "0.000000000000"},
	} {
		t.Run(tc.resource+"/"+tc.seconds, func(t *testing.T) {
			var usage pgtype.Numeric
			if err := usage.Scan(tc.seconds); err != nil {
				t.Fatal(err)
			}
			got, err := MeterUsageQuantity(usage, tc.resource)
			if err != nil || got != tc.want {
				t.Fatalf("quantity=%q, %v; want %s", got, err, tc.want)
			}
		})
	}
	for _, raw := range []string{"-1", "NaN", "Infinity", "-Infinity"} {
		var usage pgtype.Numeric
		if err := usage.Scan(raw); err != nil {
			t.Fatal(err)
		}
		if _, err := MeterUsageQuantity(usage, "vcpu"); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	if _, err := MeterUsageQuantity(pgtype.Numeric{}, "vcpu"); err == nil {
		t.Fatal("accepted null usage")
	}
}
