package vm

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// Firecracker's API admits ten connections at a time. A client that kept
// each call's connection open would use a VM's tenth call up and have every
// later one refused; twelve calls in a row must all get through.
func TestFCClientClosesItsConnectionAfterEachCall(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "fc.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	var open atomic.Int32
	srv := &http.Server{
		ConnState: func(_ net.Conn, st http.ConnState) {
			switch st {
			case http.StateNew:
				open.Add(1)
			case http.StateClosed, http.StateHijacked:
				open.Add(-1)
			}
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if open.Load() > 10 {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{ "error": "Too many open connections" }`))
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}),
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close(); ln.Close() })
	waitForUnixSocket(t, socketPath)

	dir := t.TempDir()
	for i := 0; i < 12; i++ {
		if err := CreateSnapshotContext(context.Background(), socketPath, filepath.Join(dir, "vmstate.snap"), filepath.Join(dir, "mem.snap"), "", SnapshotNormal); err != nil {
			t.Fatalf("call %d refused: %v", i+1, err)
		}
	}
	deadline := time.Now().Add(time.Second)
	for open.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := open.Load(); n != 0 {
		t.Fatalf("%d connections still open after the calls returned", n)
	}
}
