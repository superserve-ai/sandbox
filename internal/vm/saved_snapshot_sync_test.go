package vm

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"testing"
)

func TestSyncGuestFilesystemsRunsSyncThroughBoxd(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(boxdPort))
	if err != nil {
		t.Skipf("port %d busy: %v", boxdPort, err)
	}
	var got struct {
		Command string `json:"command"`
	}
	exit := int32(0)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/exec" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_ = json.NewEncoder(w).Encode(map[string]any{"stdout": "", "stderr": "", "exit_code": exit})
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	if err := syncGuestFilesystems(context.Background(), "127.0.0.1"); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if got.Command != "sync" {
		t.Errorf("guest ran %q, want sync", got.Command)
	}
	exit = 1
	if err := syncGuestFilesystems(context.Background(), "127.0.0.1"); err == nil {
		t.Error("a failed sync was reported as success")
	}
}
