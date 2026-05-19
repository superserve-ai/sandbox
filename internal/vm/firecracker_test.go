package vm

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestCreateSnapshot_FlattenFieldInJSONBody asserts that the Go-side enum
// (SnapshotNormal/SnapshotFlatten) maps to the correct `flatten` field in
// the JSON body sent to firecracker. Guards against a future go-swagger
// model regen accidentally dropping the json:"flatten,omitempty" tag.
func TestCreateSnapshot_FlattenFieldInJSONBody(t *testing.T) {
	cases := []struct {
		name        string
		mode        SnapshotMode
		wantFlatten bool
	}{
		{"normal_mode_omits_flatten_or_sends_false", SnapshotNormal, false},
		{"flatten_mode_sends_true", SnapshotFlatten, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			socketPath := filepath.Join(t.TempDir(), "fc.sock")

			var (
				bodyMu       sync.Mutex
				capturedBody []byte
			)
			ln, err := net.Listen("unix", socketPath)
			if err != nil {
				t.Fatalf("listen unix: %v", err)
			}
			defer ln.Close()

			srv := &http.Server{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch {
					case r.Method == http.MethodPatch && r.URL.Path == "/vm":
						w.WriteHeader(http.StatusNoContent)
					case r.Method == http.MethodPut && r.URL.Path == "/snapshot/create":
						b, _ := io.ReadAll(r.Body)
						bodyMu.Lock()
						capturedBody = b
						bodyMu.Unlock()
						w.WriteHeader(http.StatusNoContent)
					default:
						t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
						w.WriteHeader(http.StatusNotFound)
					}
				}),
			}
			go srv.Serve(ln)
			defer srv.Close()
			waitForUnixSocket(t, socketPath)

			if err := CreateSnapshot(socketPath, "/tmp/snap", "/tmp/mem", "/tmp/delta", tc.mode); err != nil {
				t.Fatalf("CreateSnapshot: %v", err)
			}

			bodyMu.Lock()
			body := capturedBody
			bodyMu.Unlock()
			if body == nil {
				t.Fatal("snapshot/create handler never invoked")
			}

			var decoded struct {
				Flatten bool `json:"flatten"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil {
				t.Fatalf("unmarshal body: %v (body=%s)", err, string(body))
			}
			if decoded.Flatten != tc.wantFlatten {
				t.Errorf("flatten=%v, want %v (body=%s)", decoded.Flatten, tc.wantFlatten, string(body))
			}
		})
	}
}

// Client-side guard: SnapshotFlatten with empty blockDeltaDir is rejected
// before any RPC.
func TestCreateSnapshot_FlattenRequiresBlockDeltaDir(t *testing.T) {
	err := CreateSnapshot("/dev/null/unused", "/tmp/snap", "/tmp/mem", "", SnapshotFlatten)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "blockDeltaDir") {
		t.Errorf("unexpected error: %v", err)
	}
}

// waitForUnixSocket blocks until the listener at socketPath accepts a connection
// or the deadline elapses. Avoids the race where CreateSnapshot dials before
// http.Server.Serve has installed its handler in the accept loop.
func waitForUnixSocket(t *testing.T, socketPath string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if conn, err := net.Dial("unix", socketPath); err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("server at %s never became ready", socketPath)
}
