package vm

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

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
	if len(gotBody.Files) != 2 || gotBody.Files[0].BaseSHA256 != "bb" || gotBody.Files[1].SizeBytes != 128 {
		t.Fatalf("files = %+v", gotBody.Files)
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
