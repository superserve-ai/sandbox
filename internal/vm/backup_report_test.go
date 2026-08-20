package vm

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/backup"
)

// Deliver returns nil only when the control plane accepted the report,
// with the heartbeat's auth shape and the manifest facts (no host paths)
// in the body.
func TestBackupReporterDelivers(t *testing.T) {
	var gotPath, gotAuth string
	var gotBody backupReportBody
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := &BackupReporter{
		ControlPlaneURL: srv.URL,
		HostID:          "host-1",
		Token:           "tok",
		Bucket:          "cell-bucket",
		Log:             zerolog.Nop(),
	}
	task := backup.Task{
		SandboxID:  "5df6a509-4c9e-4f6a-9f27-1af1a29b1111",
		Generation: "gen-key",
		Files: []backup.TaskFile{
			{Name: "rootfs.ext4", Path: "/staging/rootfs.ext4", SHA256: "aa", Size: 4096, BaseSHA256: "bb"},
			{Name: "vmstate.snap", Path: "/staging/vmstate.snap", SHA256: "cc", Size: 128},
		},
	}
	if err := r.Deliver(task); err != nil {
		t.Fatalf("Deliver = %v, want nil on 200", err)
	}
	if gotPath != "/internal/hosts/host-1/backups" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotAuth != "Bearer tok" {
		t.Fatalf("auth = %q", gotAuth)
	}
	if gotBody.Bucket != "cell-bucket" || gotBody.Generation != "gen-key" || gotBody.SandboxID != task.SandboxID {
		t.Fatalf("body = %+v", gotBody)
	}
	if len(gotBody.Files) != 3 || gotBody.Files[0].BaseSHA256 != "bb" || gotBody.Files[1].SizeBytes != 128 {
		t.Fatalf("files = %+v", gotBody.Files)
	}
	// The synthesized shared base travels too: task.Files alone would
	// understate the generation's restorable set.
	if base := gotBody.Files[2]; !base.Shared || base.SHA256 != "bb" || base.Name != "base-bb.ext4" {
		t.Fatalf("shared base entry = %+v", base)
	}
	if gotBody.CompletedAt.IsZero() {
		t.Fatal("completed_at not stamped")
	}
}

// A rejection or unreachable control plane returns an error so the
// outbox retains the signal for redelivery.
func TestBackupReporterErrorsKeepTheSignal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	r := &BackupReporter{ControlPlaneURL: srv.URL, HostID: "h", Token: "t", Bucket: "b", Log: zerolog.Nop()}
	if err := r.Deliver(backup.Task{SandboxID: "sb", Generation: "g"}); err == nil {
		t.Fatal("Deliver = nil on 500, want error")
	}
	srv.Close()
	if err := r.Deliver(backup.Task{SandboxID: "sb", Generation: "g"}); err == nil {
		t.Fatal("Deliver = nil against a closed server, want error")
	}
}

// A notification pinned to the bucket it verified against reports that
// bucket, not the reporter's current configuration.
func TestBackupReporterUsesPinnedBucket(t *testing.T) {
	var gotBody backupReportBody
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := &BackupReporter{ControlPlaneURL: srv.URL, HostID: "h", Token: "t", Bucket: "new-bucket", Log: zerolog.Nop()}
	pinned := time.Date(2026, 8, 10, 3, 0, 0, 0, time.UTC)
	task := backup.Task{SandboxID: "sb", Generation: "g", VerifiedBucket: "old-bucket", VerifiedAt: pinned,
		Files: []backup.TaskFile{{Name: "rootfs.ext4", SHA256: "aa", Size: 1}}}
	if err := r.Deliver(task); err != nil {
		t.Fatal(err)
	}
	if gotBody.Bucket != "old-bucket" {
		t.Fatalf("bucket = %q, want the pinned verified bucket", gotBody.Bucket)
	}
	if !gotBody.CompletedAt.Equal(pinned) {
		t.Fatalf("completed_at = %v, want the pinned verification instant", gotBody.CompletedAt)
	}
}

// A permanent rejection clears instead of erroring: the flush stops at
// the first failure, so one report the control plane will never accept
// must not wedge every later report behind it. Auth failures stay
// retryable, since a rotated token would otherwise drain the outbox.
func TestBackupReporterDropsPermanentRejections(t *testing.T) {
	status := http.StatusBadRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	}))
	defer srv.Close()
	r := &BackupReporter{ControlPlaneURL: srv.URL, HostID: "h", Token: "t", Bucket: "b", Log: zerolog.Nop()}
	task := backup.Task{SandboxID: "sb", Generation: "g",
		Files: []backup.TaskFile{{Name: "rootfs.ext4", SHA256: "aa", Size: 1}}}
	if err := r.Deliver(task); err != nil {
		t.Fatalf("Deliver on 400 = %v, want nil so the outbox clears", err)
	}
	status = http.StatusUnauthorized
	if err := r.Deliver(task); err == nil {
		t.Fatal("Deliver on 401 = nil, want error so a rotated token retries")
	}
}

// A finalized manifest's exact object paths travel on the wire, shared
// bases under their full bases/ path; entries without recorded paths
// serialize no object key at all, so an old vmd's payload shape is
// unchanged.
func TestBackupReporterCarriesObjectPaths(t *testing.T) {
	var raw []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	r := &BackupReporter{ControlPlaneURL: srv.URL, HostID: "h", Token: "t", Bucket: "b", Log: zerolog.Nop()}

	task := backup.Task{SandboxID: "sb", Generation: "g", FilesFinal: true,
		Files: []backup.TaskFile{
			{Name: "rootfs.ext4", SHA256: "aa", Size: 4, Object: "sandboxes/sb/g/rootfs.ext4.pabc123"},
			{Name: "base-bb.ext4", SHA256: "bb", Size: 8, Shared: true, Object: "bases/bb.pdef456"},
		}}
	if err := r.Deliver(task); err != nil {
		t.Fatal(err)
	}
	var gotBody backupReportBody
	if err := json.Unmarshal(raw, &gotBody); err != nil {
		t.Fatal(err)
	}
	if len(gotBody.Files) != 2 ||
		gotBody.Files[0].Object != "sandboxes/sb/g/rootfs.ext4.pabc123" ||
		gotBody.Files[1].Object != "bases/bb.pdef456" {
		t.Fatalf("files = %+v, want the recorded object paths", gotBody.Files)
	}

	legacy := backup.Task{SandboxID: "sb", Generation: "g", FilesFinal: true,
		Files: []backup.TaskFile{{Name: "rootfs.ext4", SHA256: "aa", Size: 4}}}
	if err := r.Deliver(legacy); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"object"`) {
		t.Fatalf("legacy payload = %s, want no object key on the wire", raw)
	}
}

// An old control plane binds report bodies strictly and 400s the object
// field as unknown; the reporter degrades once to the pre-field payload
// instead of dropping the coverage row, and still drops when even that
// is rejected. Only the binder's own unknown-field message triggers the
// degraded retry: any other 400 (a new control plane rejecting a
// malformed path) drops on the first attempt, never stripped past the
// validation it failed.
func TestBackupReporterStripsObjectPathsForOldControlPlane(t *testing.T) {
	acceptStripped := true
	// The strict binder's message as respondErrorMsg actually ships it:
	// JSON-escaped inside the error envelope.
	reject := `{"error":{"code":"bad_request","message":"Invalid request body: json: unknown field \"object\""}}`
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(body))
		if strings.Contains(string(body), `"object"`) || !acceptStripped {
			http.Error(w, reject, http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	r := &BackupReporter{ControlPlaneURL: srv.URL, HostID: "h", Token: "t", Bucket: "b", Log: zerolog.Nop()}
	task := backup.Task{SandboxID: "sb", Generation: "g", FilesFinal: true,
		Files: []backup.TaskFile{{Name: "rootfs.ext4", SHA256: "aa", Size: 4,
			Object: "sandboxes/sb/g/rootfs.ext4.pabc123"}}}

	if err := r.Deliver(task); err != nil {
		t.Fatalf("Deliver = %v, want nil after the stripped retry lands", err)
	}
	if len(bodies) != 2 || !strings.Contains(bodies[0], `"object"`) || strings.Contains(bodies[1], `"object"`) {
		t.Fatalf("bodies = %q, want one attempt with objects then one without", bodies)
	}

	// A rejection that persists without the field is genuinely permanent:
	// exactly one stripped retry, then the drop that keeps the outbox
	// moving.
	bodies = nil
	acceptStripped = false
	if err := r.Deliver(task); err != nil {
		t.Fatalf("Deliver = %v, want nil so the poisoned entry clears", err)
	}
	if len(bodies) != 2 {
		t.Fatalf("attempts = %d, want exactly one stripped retry", len(bodies))
	}

	// A 400 without the unknown-field marker is a content rejection from
	// a control plane that understands the field: no stripped retry.
	bodies = nil
	reject = `{"error":{"code":"bad_request","message":"object for \"rootfs.ext4\" must name this entry under its own prefix"}}`
	acceptStripped = true
	if err := r.Deliver(task); err != nil {
		t.Fatalf("Deliver = %v, want nil so the poisoned entry clears", err)
	}
	if len(bodies) != 1 {
		t.Fatalf("attempts = %d, want a single non-stripped attempt", len(bodies))
	}
}
