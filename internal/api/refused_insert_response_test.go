package api

import (
	"errors"
	"net/http"
	"testing"
)

// A refused insert means the template was deleted, was rebuilt, or could not be
// reached to tell which. Only the last is new, and it is the one that must not
// answer "not found": a caller told its template is gone does not retry, and
// the template may be sitting there intact.
func TestRefusedInsertResponseSeparatesGoneFromRebuiltFromUnknown(t *testing.T) {
	for _, tc := range []struct {
		name     string
		probeErr error
		servable bool
		status   int
		code     string
	}{
		{"deleted mid-create", nil, false, http.StatusNotFound, "not_found"},
		{"rebuilt mid-create", nil, true, http.StatusConflict, "template_rebuilt"},
		{"probe failed", errors.New("connection reset"), false, http.StatusServiceUnavailable, "service_unavailable"},
		// A failed probe cannot be trusted either way, so its verdict must not
		// depend on whatever the zero value of servable happened to be.
		{"probe failed, stale true", errors.New("connection reset"), true, http.StatusServiceUnavailable, "service_unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, message, status := refusedInsertResponse(tc.probeErr, tc.servable)
			if status != tc.status || code != tc.code {
				t.Fatalf("got %d/%s, want %d/%s", status, code, tc.status, tc.code)
			}
			if message == "" {
				t.Fatal("no message for the caller")
			}
		})
	}
}
