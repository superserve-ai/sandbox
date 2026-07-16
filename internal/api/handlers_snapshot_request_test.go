package api

import (
	"encoding/json"
	"math"
	"testing"
)

func TestCreateSnapshotRequestRejectsExplicitNull(t *testing.T) {
	for _, body := range []string{`null`, `{"name":null}`} {
		var req createSnapshotRequest
		if err := json.Unmarshal([]byte(body), &req); err == nil {
			t.Errorf("json.Unmarshal(%s) succeeded, want explicit null rejection", body)
		}
	}
}

func TestCreateSnapshotRequestAllowsOmittedOrStringName(t *testing.T) {
	for _, tc := range []struct {
		body string
		name *string
	}{
		{body: `{}`},
		{body: `{"name":"before-change"}`, name: stringPointer("before-change")},
	} {
		var req createSnapshotRequest
		if err := json.Unmarshal([]byte(tc.body), &req); err != nil {
			t.Fatalf("json.Unmarshal(%s): %v", tc.body, err)
		}
		switch {
		case tc.name == nil && req.Name != nil:
			t.Errorf("json.Unmarshal(%s) name = %q, want nil", tc.body, *req.Name)
		case tc.name != nil && (req.Name == nil || *req.Name != *tc.name):
			t.Errorf("json.Unmarshal(%s) name = %v, want %q", tc.body, req.Name, *tc.name)
		}
	}
}

func stringPointer(value string) *string { return &value }

func TestSavedSnapshotWorstCaseExclusiveBytes(t *testing.T) {
	const mib = int64(1 << 20)
	if got, want := savedSnapshotWorstCaseExclusiveBytes(2048, 8192), int64(10240)*mib+savedSnapshotMetadataReserve; got != want {
		t.Fatalf("worst-case bytes = %d, want %d", got, want)
	}
	if got := savedSnapshotWorstCaseExclusiveBytes(-1, 1); got != math.MaxInt64 {
		t.Fatalf("invalid shape estimate = %d, want MaxInt64", got)
	}
}
