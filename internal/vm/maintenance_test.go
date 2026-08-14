package vm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func withMaintenanceServer(t *testing.T, status int, body string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			t.Error("probe must send Metadata-Flavor: Google")
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	old := maintenanceMetadataURL
	maintenanceMetadataURL = srv.URL
	t.Cleanup(func() { maintenanceMetadataURL = old })
}

func TestProbeMaintenanceWindow(t *testing.T) {
	client := &http.Client{}

	t.Run("announced window parses", func(t *testing.T) {
		withMaintenanceServer(t, 200, `{"windowStartTime":"2030-01-02T03:04:05Z","type":"SCHEDULED"}`)
		got, err := probeMaintenanceWindow(context.Background(), client)
		if err != nil || got == nil {
			t.Fatalf("want window, got %v err %v", got, err)
		}
		if !got.Equal(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)) {
			t.Fatalf("wrong time: %v", got)
		}
	})

	t.Run("NONE body means nothing announced", func(t *testing.T) {
		withMaintenanceServer(t, 200, "NONE")
		got, err := probeMaintenanceWindow(context.Background(), client)
		if err != nil || got != nil {
			t.Fatalf("want nil/nil, got %v err %v", got, err)
		}
	})

	t.Run("404 means nothing announced", func(t *testing.T) {
		withMaintenanceServer(t, 404, "not found")
		got, err := probeMaintenanceWindow(context.Background(), client)
		if err != nil || got != nil {
			t.Fatalf("want nil/nil, got %v err %v", got, err)
		}
	})

	t.Run("server error is unknowable, not cleared", func(t *testing.T) {
		withMaintenanceServer(t, 500, "boom")
		if _, err := probeMaintenanceWindow(context.Background(), client); err == nil {
			t.Fatal("non-200 must be an error — callers omit, never clear")
		}
	})

	t.Run("malformed body is unknowable", func(t *testing.T) {
		withMaintenanceServer(t, 200, "{torn")
		if _, err := probeMaintenanceWindow(context.Background(), client); err == nil {
			t.Fatal("malformed body must be an error")
		}
	})
}
