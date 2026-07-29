package vm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/superserve-ai/sandbox/internal/vm/fc/client/operations"
)

// TestFCClientClosesConnections guards Firecracker's small API connection
// budget. newFCClient is intentionally created per high-level operation, so a
// keep-alive left behind by each client eventually makes the VMM reject every
// request with "Too many open connections".
func TestFCClientClosesConnections(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "fc.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer ln.Close()

	var openConnections atomic.Int32
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/" {
				t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"app_name":"Firecracker","id":"vm-1","state":"Running","vmm_version":"test"}`)
		}),
		ConnState: func(_ net.Conn, state http.ConnState) {
			switch state {
			case http.StateNew:
				openConnections.Add(1)
			case http.StateHijacked, http.StateClosed:
				openConnections.Add(-1)
			}
		},
	}
	go srv.Serve(ln)
	defer srv.Close()
	waitForUnixSocket(t, socketPath)

	for i := 0; i < 20; i++ {
		state, err := FirecrackerVMStateContext(context.Background(), socketPath)
		if err != nil {
			t.Fatalf("state probe %d: %v", i, err)
		}
		if state != "Running" {
			t.Fatalf("state probe %d = %q, want Running", i, state)
		}
	}

	deadline := time.Now().Add(time.Second)
	for openConnections.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := openConnections.Load(); got != 0 {
		t.Fatalf("Firecracker API connections still open after requests: %d", got)
	}
}

// TestCreateSnapshot_FlattenFieldInJSONBody asserts that the Go-side enum
// (SnapshotNormal/SnapshotFlatten) serializes the `flatten` field correctly
// in the JSON body sent to firecracker. The SnapshotNormal cases use the
// substring check (not unmarshal) so an accidentally-dropped `omitempty`
// would surface as `"flatten": false` appearing in the body — unmarshal
// alone would silently accept that as the zero value.
func TestCreateSnapshot_FlattenFieldInJSONBody(t *testing.T) {
	cases := []struct {
		name          string
		mode          SnapshotMode
		blockDeltaDir string
		assertBody    func(t *testing.T, body []byte)
	}{
		{
			name:          "normal_mode_with_empty_delta_dir_omits_flatten",
			mode:          SnapshotNormal,
			blockDeltaDir: "",
			assertBody: func(t *testing.T, body []byte) {
				if strings.Contains(string(body), "flatten") {
					t.Errorf("flatten field must be omitted for SnapshotNormal; body=%s", string(body))
				}
			},
		},
		{
			name:          "normal_mode_with_delta_dir_omits_flatten",
			mode:          SnapshotNormal,
			blockDeltaDir: "/tmp/delta",
			assertBody: func(t *testing.T, body []byte) {
				if strings.Contains(string(body), "flatten") {
					t.Errorf("flatten field must be omitted for SnapshotNormal; body=%s", string(body))
				}
			},
		},
		{
			name:          "flatten_mode_sends_true",
			mode:          SnapshotFlatten,
			blockDeltaDir: "/tmp/delta",
			assertBody: func(t *testing.T, body []byte) {
				var decoded struct {
					Flatten bool `json:"flatten"`
				}
				if err := json.Unmarshal(body, &decoded); err != nil {
					t.Fatalf("unmarshal body: %v (body=%s)", err, string(body))
				}
				if !decoded.Flatten {
					t.Errorf("flatten=%v, want true (body=%s)", decoded.Flatten, string(body))
				}
			},
		},
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

			if err := CreateSnapshot(socketPath, "/tmp/snap", "/tmp/mem", tc.blockDeltaDir, tc.mode); err != nil {
				t.Fatalf("CreateSnapshot: %v", err)
			}

			bodyMu.Lock()
			body := capturedBody
			bodyMu.Unlock()
			if body == nil {
				t.Fatal("snapshot/create handler never invoked")
			}
			tc.assertBody(t, body)
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

// TestIsLayeredInvalidErr guards the cross-repo string coupling: the matcher must
// recognize the forked Firecracker's LayeredInvalid display text (and not generic
// errors). If the fork changes that message, this test fails instead of the
// classification silently degrading to a retryable Internal error at runtime.
func TestIsLayeredInvalidErr(t *testing.T) {
	// Representative of the full Display chain Firecracker surfaces on the API error.
	fcErr := fmt.Errorf("load snapshot (uffd-internal): [PUT /snapshot/load][400] " +
		"Error creating guest memory from uffd: Layered restore " +
		"overlay/base pairing is invalid (permanent — do not retry): " +
		"base \"/t/mem.base\" is 1048576 bytes, smaller than guest RAM 2097152")
	if !isLayeredInvalidErr(fcErr) {
		t.Errorf("isLayeredInvalidErr = false, want true for %q", fcErr)
	}
	if isLayeredInvalidErr(fmt.Errorf("load snapshot: connection refused")) {
		t.Error("isLayeredInvalidErr = true for an unrelated error, want false")
	}
	if isLayeredInvalidErr(nil) {
		t.Error("isLayeredInvalidErr(nil) = true, want false")
	}
}

func TestWrapSnapshotLoadErrorMarksOnlyFirecrackerRejections(t *testing.T) {
	rejected := wrapSnapshotLoadError("load snapshot", operations.NewLoadSnapshotBadRequest())
	if !errors.Is(rejected, ErrSnapshotLoadRejected) {
		t.Fatalf("Firecracker 400 was not marked as an artifact rejection: %v", rejected)
	}

	transport := wrapSnapshotLoadError("load snapshot", fmt.Errorf("dial unix: connection refused"))
	if errors.Is(transport, ErrSnapshotLoadRejected) {
		t.Fatalf("transport failure was misclassified as an artifact rejection: %v", transport)
	}
}
