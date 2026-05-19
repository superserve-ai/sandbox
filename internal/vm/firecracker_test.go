package vm

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
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

			var capturedBody []byte
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
						capturedBody, _ = io.ReadAll(r.Body)
						w.WriteHeader(http.StatusNoContent)
					default:
						t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
						w.WriteHeader(http.StatusNotFound)
					}
				}),
			}
			go srv.Serve(ln)
			defer srv.Close()

			if err := CreateSnapshot(socketPath, "/tmp/snap", "/tmp/mem", "/tmp/delta", tc.mode); err != nil {
				t.Fatalf("CreateSnapshot: %v", err)
			}

			if capturedBody == nil {
				t.Fatal("snapshot/create handler never invoked")
			}

			var body struct {
				Flatten bool `json:"flatten"`
			}
			if err := json.Unmarshal(capturedBody, &body); err != nil {
				t.Fatalf("unmarshal body: %v (body=%s)", err, string(capturedBody))
			}
			if body.Flatten != tc.wantFlatten {
				t.Errorf("flatten=%v, want %v (body=%s)", body.Flatten, tc.wantFlatten, string(capturedBody))
			}
		})
	}
}
