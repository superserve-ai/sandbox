package vm

import (
	"encoding/json"
	"fmt"
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

// TestRestoreSnapshot_AbortOnHandlerDeathInJSONBody mirrors the flatten guard on
// the restore path. The disabled case uses a substring check (not unmarshal) so a
// lost omission surfaces as `"abort_on_handler_death": false` in the body rather
// than being silently accepted as the zero value. Firecracker deserializes these
// params with deny_unknown_fields, so a binary predating the field rejects the
// whole request instead of ignoring it.
func TestRestoreSnapshot_AbortOnHandlerDeathInJSONBody(t *testing.T) {
	cases := []struct {
		name       string
		abort      bool
		assertBody func(t *testing.T, body []byte)
	}{
		{
			name:  "disabled_omits_abort_on_handler_death",
			abort: false,
			assertBody: func(t *testing.T, body []byte) {
				if strings.Contains(string(body), "abort_on_handler_death") {
					t.Errorf("abort_on_handler_death must be omitted when disabled; body=%s", string(body))
				}
			},
		},
		{
			name:  "enabled_sends_true",
			abort: true,
			assertBody: func(t *testing.T, body []byte) {
				var decoded struct {
					MemBackend struct {
						AbortOnHandlerDeath bool `json:"abort_on_handler_death"`
					} `json:"mem_backend"`
				}
				if err := json.Unmarshal(body, &decoded); err != nil {
					t.Fatalf("unmarshal body: %v (body=%s)", err, string(body))
				}
				if !decoded.MemBackend.AbortOnHandlerDeath {
					t.Errorf("abort_on_handler_death=false, want true (body=%s)", string(body))
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
					if r.Method == http.MethodPut && r.URL.Path == "/snapshot/load" {
						b, _ := io.ReadAll(r.Body)
						bodyMu.Lock()
						capturedBody = b
						bodyMu.Unlock()
						w.WriteHeader(http.StatusNoContent)
						return
					}
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}),
			}
			go srv.Serve(ln)
			defer srv.Close()
			waitForUnixSocket(t, socketPath)

			if err := RestoreSnapshotUffdInternalWithOverrides(
				socketPath, "/tmp/snap", "/tmp/mem", "", "", "", "eth0", "tap0", "",
				false, tc.abort, nil,
			); err != nil {
				t.Fatalf("RestoreSnapshotUffdInternalWithOverrides: %v", err)
			}

			bodyMu.Lock()
			body := capturedBody
			bodyMu.Unlock()
			if body == nil {
				t.Fatal("snapshot/load handler never invoked")
			}
			tc.assertBody(t, body)
		})
	}
}

// TestRestoreSnapshot_ClockRealtimeInJSONBody pins the three wire states apart.
// The legacy case uses a substring check (not unmarshal) because an omitted field
// and an explicit false decode identically, yet mean different things to
// Firecracker: omitted restores the flags the snapshot carries, false freezes the
// guest clock. An old binary also rejects the field outright, so a stray
// "clock_realtime" is a failed restore, not a slower one.
func TestRestoreSnapshot_ClockRealtimeInJSONBody(t *testing.T) {
	freeze := false
	cases := []struct {
		name       string
		policy     *bool
		assertBody func(t *testing.T, body []byte)
	}{
		{
			name:   "nil_policy_omits_the_field",
			policy: nil,
			assertBody: func(t *testing.T, body []byte) {
				if strings.Contains(string(body), "clock_realtime") {
					t.Errorf("clock_realtime must be omitted for the legacy policy; body=%s", string(body))
				}
			},
		},
		{
			name:   "freeze_sends_explicit_false",
			policy: &freeze,
			assertBody: func(t *testing.T, body []byte) {
				var decoded map[string]any
				if err := json.Unmarshal(body, &decoded); err != nil {
					t.Fatalf("unmarshal body: %v (body=%s)", err, string(body))
				}
				got, ok := decoded["clock_realtime"]
				if !ok {
					t.Fatalf("clock_realtime missing; body=%s", string(body))
				}
				if got != false {
					t.Errorf("clock_realtime = %v, want false", got)
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
					if r.Method == http.MethodPut && r.URL.Path == "/snapshot/load" {
						b, _ := io.ReadAll(r.Body)
						bodyMu.Lock()
						capturedBody = b
						bodyMu.Unlock()
						w.WriteHeader(http.StatusNoContent)
						return
					}
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}),
			}
			go srv.Serve(ln)
			defer srv.Close()
			waitForUnixSocket(t, socketPath)

			if err := RestoreSnapshotUffdInternalWithOverrides(
				socketPath, "/tmp/snap", "/tmp/mem", "", "", "", "eth0", "tap0", "",
				false, false, tc.policy,
			); err != nil {
				t.Fatalf("RestoreSnapshotUffdInternalWithOverrides: %v", err)
			}

			bodyMu.Lock()
			body := capturedBody
			bodyMu.Unlock()
			if body == nil {
				t.Fatal("snapshot/load handler never invoked")
			}
			tc.assertBody(t, body)
		})
	}
}

// The fork's message is the only signal that an older binary refused the option.
// If it changes, this fails instead of the fallback silently never firing.
func TestIsUnknownClockFieldErr(t *testing.T) {
	fcErr := fmt.Errorf("load snapshot (uffd-internal): [PUT /snapshot/load][400] " +
		"Bad Request: unknown field `clock_realtime`, expected one of `snapshot_path`, `mem_backend`")
	if !isUnknownClockFieldErr(fcErr) {
		t.Errorf("isUnknownClockFieldErr = false, want true for %q", fcErr)
	}
	if isUnknownClockFieldErr(fmt.Errorf("load snapshot: connection refused")) {
		t.Error("isUnknownClockFieldErr = true for an unrelated error, want false")
	}
	if isUnknownClockFieldErr(nil) {
		t.Error("isUnknownClockFieldErr(nil) = true, want false")
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
