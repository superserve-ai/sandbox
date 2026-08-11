package vm

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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
