package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/superserve-ai/sandbox/internal/db"
)

func setupBackupReportRouter(h *Handlers) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/internal/hosts/:host_id/backups", h.ReportHostBackup)
	return r
}

// backupReportMock records the files jsonb handed to the template
// generation insert; the template path exercises the shared files
// marshalling without the sandbox path's lock and size-sync choreography.
func backupReportMock(t *testing.T, gotFiles *[]byte) *mockDBTX {
	t.Helper()
	return &mockDBTX{
		execFn: func(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
			if !strings.Contains(sql, "-- name: RecordTemplateBackupGeneration :execrows") {
				return pgconn.CommandTag{}, fmt.Errorf("unexpected Exec: %s", sql)
			}
			*gotFiles = args[5].([]byte)
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
}

func postBackupReport(t *testing.T, h *Handlers, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/internal/hosts/host-a/backups", strings.NewReader(body))
	setupBackupReportRouter(h).ServeHTTP(w, req)
	return w
}

// A report carrying per-file object paths persists them verbatim into
// the files jsonb, shared bases under their full bases/ path: the ledger
// must let a future GC name a generation's objects without listing the
// bucket.
func TestReportHostBackupPersistsObjectPaths(t *testing.T) {
	var gotFiles []byte
	h := &Handlers{DB: db.New(backupReportMock(t, &gotFiles))}
	const tid = "5df6a509-4c9e-4f6a-9f27-1af1a29b1111"
	gen := strings.Repeat("ab", 32)
	sha := strings.Repeat("cd", 32)
	rootObj := "templates/" + tid + "/build-1/" + gen + "/rootfs.ext4.pabc123def456"
	baseObj := "bases/" + sha + ".p1234abcd5678"
	body := fmt.Sprintf(`{"template_id":%q,"build_id":"build-1",`+
		`"generation":%q,"bucket":"cell-bucket","completed_at":"2026-08-01T00:00:00Z","files":[`+
		`{"name":"rootfs.ext4","size_bytes":4,"sha256":%q,"object":%q},`+
		`{"name":"base-%s.ext4","size_bytes":8,"sha256":%q,"shared":true,"object":%q}]}`,
		tid, gen, sha, rootObj, sha, sha, baseObj)

	w := postBackupReport(t, h, body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	var files []backupFileReport
	if err := json.Unmarshal(gotFiles, &files); err != nil {
		t.Fatalf("files jsonb: %v", err)
	}
	if len(files) != 2 || files[0].Object != rootObj ||
		files[1].Object != baseObj || !files[1].Shared {
		t.Fatalf("persisted files = %+v, want the reported object paths", files)
	}
}

// Object paths are optional but never free-form: an entry claiming a
// path outside its own layout (another owner's prefix, a foreign shared
// object, a traversal segment) is rejected before anything persists,
// since these paths are meant to become deletion authority for GC.
func TestReportHostBackupRejectsForeignObjectPaths(t *testing.T) {
	const tid = "5df6a509-4c9e-4f6a-9f27-1af1a29b1111"
	gen := strings.Repeat("ab", 32)
	sha := strings.Repeat("cd", 32)
	for name, object := range map[string]string{
		"foreign generation":  "templates/" + tid + "/build-1/" + strings.Repeat("ee", 32) + "/rootfs.ext4.pabc123",
		"manifest object":     "templates/" + tid + "/build-1/" + gen + "/manifest.json",
		"missing fingerprint": "templates/" + tid + "/build-1/" + gen + "/rootfs.ext4",
		"non-hex fingerprint": "templates/" + tid + "/build-1/" + gen + "/rootfs.ext4.pZZ12",
		"trailing segment":    "templates/" + tid + "/build-1/" + gen + "/rootfs.ext4.pabc123/x",
	} {
		var gotFiles []byte
		h := &Handlers{DB: db.New(backupReportMock(t, &gotFiles))}
		body := fmt.Sprintf(`{"template_id":%q,"build_id":"build-1",`+
			`"generation":%q,"bucket":"cell-bucket","completed_at":"2026-08-01T00:00:00Z","files":[`+
			`{"name":"rootfs.ext4","size_bytes":4,"sha256":%q,"object":%q}]}`, tid, gen, sha, object)
		if w := postBackupReport(t, h, body); w.Code != http.StatusBadRequest {
			t.Fatalf("%s: status = %d, want 400; body: %s", name, w.Code, w.Body.String())
		}
		if gotFiles != nil {
			t.Fatalf("%s: rejected report still persisted files %s", name, gotFiles)
		}
	}

	// A shared entry must sit under its own content address.
	var gotFiles []byte
	h := &Handlers{DB: db.New(backupReportMock(t, &gotFiles))}
	body := fmt.Sprintf(`{"template_id":%q,"build_id":"build-1",`+
		`"generation":%q,"bucket":"cell-bucket","completed_at":"2026-08-01T00:00:00Z","files":[`+
		`{"name":"base-%s.ext4","size_bytes":8,"sha256":%q,"shared":true,"object":"bases/%s.pabc123"}]}`,
		tid, gen, sha, sha, strings.Repeat("ee", 32))
	if w := postBackupReport(t, h, body); w.Code != http.StatusBadRequest {
		t.Fatalf("foreign shared object: status = %d, want 400; body: %s", w.Code, w.Body.String())
	}

	// A mixed set (paths on some entries only) is rejected: paths land
	// all-or-none, so a partial manifest can never rank as path-bearing
	// and demote a complete ledger entry.
	body = fmt.Sprintf(`{"template_id":%q,"build_id":"build-1",`+
		`"generation":%q,"bucket":"cell-bucket","completed_at":"2026-08-01T00:00:00Z","files":[`+
		`{"name":"rootfs.ext4","size_bytes":4,"sha256":%q,"object":"templates/%s/build-1/%s/rootfs.ext4.pabc123"},`+
		`{"name":"vmstate.snap","size_bytes":2,"sha256":%q}]}`, tid, gen, sha, tid, gen, sha)
	if w := postBackupReport(t, h, body); w.Code != http.StatusBadRequest {
		t.Fatalf("mixed object coverage: status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
}

// Reports from hosts predating the object field are accepted and stored
// exactly as before: no object key appears in the persisted jsonb.
func TestReportHostBackupAcceptsReportsWithoutObjectPaths(t *testing.T) {
	var gotFiles []byte
	h := &Handlers{DB: db.New(backupReportMock(t, &gotFiles))}
	gen := strings.Repeat("ab", 32)
	sha := strings.Repeat("cd", 32)
	body := fmt.Sprintf(`{"template_id":"5df6a509-4c9e-4f6a-9f27-1af1a29b1111","build_id":"build-1",`+
		`"generation":%q,"bucket":"cell-bucket","completed_at":"2026-08-01T00:00:00Z","files":[`+
		`{"name":"rootfs.ext4","size_bytes":4,"sha256":%q}]}`, gen, sha)

	w := postBackupReport(t, h, body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	var files []backupFileReport
	if err := json.Unmarshal(gotFiles, &files); err != nil {
		t.Fatalf("files jsonb: %v", err)
	}
	if len(files) != 1 || files[0].Name != "rootfs.ext4" {
		t.Fatalf("persisted files = %+v", files)
	}
	if strings.Contains(string(gotFiles), `"object"`) {
		t.Fatalf("files jsonb = %s, want no object key for a pre-field report", gotFiles)
	}
}
