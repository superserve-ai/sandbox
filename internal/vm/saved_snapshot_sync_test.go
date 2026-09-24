package vm

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
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
	reply := []byte(`{"stdout":"","stderr":"","exit_code":0}`)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/exec" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write(reply)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	if err := syncGuestFilesystems(context.Background(), "127.0.0.1"); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if got.Command != "sync" {
		t.Errorf("guest ran %q, want sync", got.Command)
	}
	// Only a whole reply that says exit 0 is a flush: not a failure that
	// comes after a long stderr, not a reply without an exit code, not one
	// that is not a reply at all.
	for name, bad := range map[string][]byte{
		"nonzero exit":            []byte(`{"stdout":"","stderr":"","exit_code":1}`),
		"nonzero exit past 64KiB": []byte(`{"stdout":"","stderr":"` + strings.Repeat("x", 70<<10) + `","exit_code":1}`),
		"no exit code":            []byte(`{"stdout":"","stderr":""}`),
		"not json":                []byte(`<html>gateway timeout</html>`),
		"cut short":               []byte(`{"stdout":"","stderr":"","exit_c`),
	} {
		reply = bad
		if err := syncGuestFilesystems(context.Background(), "127.0.0.1"); err == nil {
			t.Errorf("%s: reported as a flush", name)
		}
	}
}
