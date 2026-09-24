package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestStorageReportErrorIsTerminal(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "stale incarnation", err: errStorageReportStaleIncarnation, want: true},
		{name: "invalid payload", err: errStorageReportInvalidPayload, want: true},
		{name: "missing database row", err: pgx.ErrNoRows, want: false},
		{name: "constraint violation", err: &pgconn.PgError{Code: "23514"}, want: false},
		{name: "data exception", err: &pgconn.PgError{Code: "22003"}, want: false},
		{name: "serialization failure", err: &pgconn.PgError{Code: "40001"}, want: false},
		{name: "lock timeout", err: &pgconn.PgError{Code: "55P03"}, want: false},
		{name: "other transient error", err: errors.New("connection reset"), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := storageReportErrorIsTerminal(tt.err); got != tt.want {
				t.Fatalf("storageReportErrorIsTerminal(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestHostStorageReportRejectsAllocatedBytesOverflowBeforeDB(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/internal/hosts/:host_id/storage-reports", (&Handlers{}).HostStorageReport)

	for _, allocatedBytes := range []int64{maxHostStorageAllocatedBytes + 1, int64(^uint64(0) >> 1)} {
		t.Run(fmt.Sprintf("allocated_bytes_%d", allocatedBytes), func(t *testing.T) {
			body := fmt.Sprintf(`{"incarnation_id":"0f794b2e-f7a4-46eb-85b4-60f69e6cc831","report_id":"2f794b2e-f7a4-46eb-85b4-60f69e6cc831","measurements":[{"sandbox_id":"3f794b2e-f7a4-46eb-85b4-60f69e6cc831","allocated_bytes":%d}]}`, allocatedBytes)
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/internal/hosts/example-host/storage-reports", strings.NewReader(body))
			r.ServeHTTP(w, req)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestStorageReportsRejectDuplicateSandboxIDsBeforeDB(t *testing.T) {
	gin.SetMode(gin.TestMode)
	id := "3f794b2e-f7a4-46eb-85b4-60f69e6cc831"
	measurement := storageReportMeasurement{SandboxID: id, AllocatedBytes: 1 << 20}
	crossChunk := []storageReportMeasurement{measurement}
	for len(crossChunk) < storageReportChunkSize {
		crossChunk = append(crossChunk, storageReportMeasurement{SandboxID: uuid.NewString(), AllocatedBytes: 1 << 20})
	}
	crossChunk = append(crossChunk, measurement)
	cases := []struct {
		name         string
		measurements []storageReportMeasurement
		duplicate    bool
	}{
		{name: "same value", measurements: []storageReportMeasurement{measurement, measurement}, duplicate: true},
		{name: "different values", measurements: []storageReportMeasurement{measurement, {SandboxID: id, AllocatedBytes: 2 << 20}}, duplicate: true},
		{name: "uppercase UUID", measurements: []storageReportMeasurement{measurement, {SandboxID: strings.ToUpper(id), AllocatedBytes: 2 << 20}}, duplicate: true},
		{name: "URN UUID", measurements: []storageReportMeasurement{measurement, {SandboxID: "urn:uuid:" + id, AllocatedBytes: 2 << 20}}, duplicate: true},
		{name: "across chunk boundary", measurements: crossChunk, duplicate: true},
		{name: "unique", measurements: crossChunk[:storageReportChunkSize]},
		{name: "empty"},
	}
	for _, endpoint := range []struct {
		name, field string
		handler     gin.HandlerFunc
	}{
		{name: "storage-reports", field: "measurements", handler: (&Handlers{}).HostStorageReport},
		{name: "heartbeat", field: "storage", handler: (&Handlers{}).HostHeartbeat},
	} {
		t.Run(endpoint.name, func(t *testing.T) {
			r := gin.New()
			path := "/internal/hosts/example-host/" + endpoint.name
			r.POST("/internal/hosts/:host_id/"+endpoint.name, endpoint.handler)
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					body := map[string]any{endpoint.field: tc.measurements}
					if endpoint.name == "storage-reports" {
						body["incarnation_id"] = uuid.NewString()
						body["report_id"] = uuid.NewString()
					}
					encoded, err := json.Marshal(body)
					if err != nil {
						t.Fatal(err)
					}
					w := httptest.NewRecorder()
					r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(encoded))))
					want := http.StatusServiceUnavailable // Valid input reaches the unconfigured database.
					if tc.duplicate {
						want = http.StatusBadRequest
					}
					if w.Code != want || (tc.duplicate && !strings.Contains(w.Body.String(), "duplicate storage measurement")) {
						t.Fatalf("status=%d body=%s, want status=%d duplicate=%v", w.Code, w.Body.String(), want, tc.duplicate)
					}
				})
			}
		})
	}
}
