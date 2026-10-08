package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"
)

func storageBatchMeasurements(n int) []storageReportMeasurement {
	measurements := make([]storageReportMeasurement, n)
	for i := range measurements {
		measurements[i] = storageReportMeasurement{SandboxID: uuid.NewString(), AllocatedBytes: int64(i+1) << 20}
	}
	return measurements
}

func TestStorageReportPayloadDecodesOnceAndBoundsChunks(t *testing.T) {
	measurements := storageBatchMeasurements(storageReportChunkSize*storageReportChunksPerClaim + 1)
	payload, err := json.Marshal(measurements)
	if err != nil {
		t.Fatal(err)
	}
	calls, cursor := 0, 0
	err = applyStorageReportPayload(t.Context(), payload, 0, func(chunk []storageReportMeasurement, end, total int, keep bool) error {
		calls++
		if len(chunk) != storageReportChunkSize || total != len(measurements) || end != cursor+len(chunk) {
			t.Fatalf("unexpected chunk: length=%d end=%d total=%d", len(chunk), end, total)
		}
		for i, m := range chunk {
			if m != measurements[cursor+i] {
				t.Fatalf("measurement %d changed", cursor+i)
			}
		}
		cursor = end
		if keep != (calls < storageReportChunksPerClaim) {
			t.Fatalf("chunk %d keep=%v", calls, keep)
		}
		// A later decode would fail; subsequent chunks must use the decoded copy.
		payload[0] = '!'
		return nil
	})
	if err != nil || calls != storageReportChunksPerClaim || cursor != len(measurements)-1 {
		t.Fatalf("calls=%d cursor=%d err=%v", calls, cursor, err)
	}
}

func TestStorageReportPayloadRetryAndCancellation(t *testing.T) {
	measurements := storageBatchMeasurements(2*storageReportChunkSize + 1)
	payload, _ := json.Marshal(measurements)
	failure := errors.New("chunk failed before commit")
	cursor, calls := 0, 0
	seen := make(map[string]int)
	apply := func(chunk []storageReportMeasurement, end, total int, keep bool) error {
		calls++
		if calls == 2 {
			return failure
		}
		for _, m := range chunk {
			seen[m.SandboxID]++
		}
		cursor = end
		return nil
	}
	if err := applyStorageReportPayload(t.Context(), payload, 0, apply); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if cursor != storageReportChunkSize || calls != 2 {
		t.Fatalf("cursor=%d calls=%d", cursor, calls)
	}
	if err := applyStorageReportPayload(t.Context(), payload, cursor, apply); err != nil {
		t.Fatal(err)
	}
	for _, m := range measurements {
		if seen[m.SandboxID] != 1 {
			t.Fatalf("measurement applied %d times", seen[m.SandboxID])
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	calls = 0
	err := applyStorageReportPayload(ctx, payload, 0, func(_ []storageReportMeasurement, _, _ int, _ bool) error { calls++; cancel(); return nil })
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("cancellation: calls=%d err=%v", calls, err)
	}
}

func TestStorageReportPayloadBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload string
		cursor  int
		invalid bool
	}{
		{"empty", "[]", 0, false}, {"negative cursor", "[]", -1, true}, {"past end", "[]", 1, true}, {"malformed", "[", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			err := applyStorageReportPayload(t.Context(), []byte(tc.payload), tc.cursor, func(chunk []storageReportMeasurement, end, total int, keep bool) error {
				calls++
				if len(chunk) != 0 || end != 0 || total != 0 || keep {
					t.Fatal("empty report did not complete")
				}
				return nil
			})
			if errors.Is(err, errStorageReportInvalidPayload) != tc.invalid || (tc.invalid && calls != 0) || (!tc.invalid && calls != 1) {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
		})
	}
}

func BenchmarkStorageReportPayload(b *testing.B) {
	measurements := storageBatchMeasurements(181000)
	payload, err := json.Marshal(measurements)
	if err != nil {
		b.Fatal(err)
	}
	for _, chunksPerClaim := range []int{1, storageReportChunksPerClaim} {
		b.Run(fmt.Sprintf("chunks_per_claim_%d", chunksPerClaim), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				cursor, decodes := 0, 0
				for cursor < len(measurements) {
					decodes++
					if chunksPerClaim == 1 {
						var decoded []storageReportMeasurement
						if err := json.Unmarshal(payload, &decoded); err != nil {
							b.Fatal(err)
						}
						cursor = min(cursor+storageReportChunkSize, len(decoded))
					} else {
						if err := applyStorageReportPayload(context.Background(), payload, cursor, func(_ []storageReportMeasurement, end, _ int, _ bool) error { cursor = end; return nil }); err != nil {
							b.Fatal(err)
						}
					}
				}
				b.ReportMetric(float64(decodes), "decodes/report")
			}
		})
	}
}
