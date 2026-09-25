package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/superserve-ai/sandbox/internal/backup"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestReportHostBackupTemplatePublication(t *testing.T) {
	const token = "example-internal-token"
	const bucket = "example-cell-bucket"
	t.Setenv("INTERNAL_API_TOKEN", token)
	attempt := uuid.MustParse("5df6a509-4c9e-4f6a-9f27-1af1a29b1111")
	template := uuid.MustParse("ea1d7e72-e5e1-41b2-b437-24755d2c2c11")
	incarnation := uuid.MustParse("b2714ae8-51b4-4cb9-9e41-f12862f26dc1")
	buildID := "build-" + attempt.String()
	files := []backupFileReport{}
	for _, name := range []string{"rootfs.ext4", "vmstate.snap", "mem.snap", "build.meta.json"} {
		files = append(files, backupFileReport{Name: name, RuntimePath: "/build/" + name, SizeBytes: 4, AllocatedBytes: 4, SHA256: strings.Repeat("a", 64)})
	}
	keyFiles := make([]backup.TaskFile, 0, len(files))
	for _, f := range files {
		keyFiles = append(keyFiles, backup.TaskFile{Name: f.Name, Size: f.SizeBytes, SHA256: f.SHA256})
	}
	base := backupReport{
		TemplateID: template.String(), BuildID: buildID, BuildIncarnation: incarnation.String(),
		Bucket: bucket, Generation: backup.GenerationKey(keyFiles), CompletedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		TemplateRuntime: &backup.TemplateRuntime{RootfsPath: "/build/rootfs.ext4", SnapshotPath: "/build/vmstate.snap", MemPath: "/build/mem.snap", SizeBytes: 4},
		Files:           files,
	}
	tests := []struct {
		name       string
		change     func(*backupReport)
		host       string
		ownerVMID  string
		configured string
		authorized bool
		recorded   bool
		wantStatus int
		wantWrite  bool
	}{
		{name: "verified publication", host: "host-a", configured: bucket, authorized: true, recorded: true, wantStatus: http.StatusOK, wantWrite: true},
		{name: "idempotent or fenced attempt", host: "host-a", configured: bucket, authorized: true, recorded: false, wantStatus: http.StatusOK, wantWrite: true},
		{name: "unauthenticated", host: "host-a", configured: bucket, wantStatus: http.StatusUnauthorized},
		{name: "wrong host", host: "host-b", configured: bucket, authorized: true, wantStatus: http.StatusBadRequest},
		{name: "wrong attempt VM", host: "host-a", ownerVMID: "build-other-attempt", configured: bucket, authorized: true, wantStatus: http.StatusBadRequest},
		{name: "wrong incarnation", host: "host-a", configured: bucket, authorized: true, wantStatus: http.StatusBadRequest, change: func(r *backupReport) { r.BuildIncarnation = uuid.NewString() }},
		{name: "wrong template", host: "host-a", configured: bucket, authorized: true, wantStatus: http.StatusBadRequest, change: func(r *backupReport) { r.TemplateID = uuid.NewString() }},
		{name: "wrong bucket", host: "host-a", configured: "different-cell-bucket", authorized: true, wantStatus: http.StatusServiceUnavailable},
		{name: "missing runtime artifact", host: "host-a", configured: bucket, authorized: true, wantStatus: http.StatusBadRequest, change: func(r *backupReport) { r.TemplateRuntime.MemPath = "/build/missing.snap" }},
		{name: "wrong generation", host: "host-a", configured: bucket, authorized: true, wantStatus: http.StatusBadRequest, change: func(r *backupReport) { r.Generation = strings.Repeat("b", 64) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			report := base
			runtime := *base.TemplateRuntime
			report.TemplateRuntime = &runtime
			if tc.change != nil {
				tc.change(&report)
			}
			writes := 0
			mock := &mockDBTX{queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
				if strings.Contains(sql, "FROM template_build_attempt a") {
					if len(args) != 1 || args[0] != attempt {
						t.Fatalf("attempt lookup args = %v", args)
					}
					return &mockRow{scanFn: func(dest ...any) error {
						*dest[0].(*uuid.UUID) = attempt
						*dest[1].(*uuid.UUID) = attempt
						*dest[2].(*uuid.UUID) = template
						*dest[3].(*string) = "host-a"
						*dest[4].(*uuid.UUID) = incarnation
						if tc.ownerVMID == "" {
							*dest[5].(*string) = buildID
						} else {
							*dest[5].(*string) = tc.ownerVMID
						}
						*dest[6].(*string) = "uploading"
						*dest[7].(*time.Time) = base.CompletedAt
						return nil
					}}
				}
				if strings.Contains(sql, "SELECT record_template_publication(") {
					writes++
					if len(args) != 8 || args[0] != attempt || args[1] != "host-a" || args[2] != bucket || args[3] != base.Generation || args[7] != base.CompletedAt {
						t.Fatalf("publication args = %v", args)
					}
					manifest, _ := backup.TemplateObject(template.String(), buildID, base.Generation, backup.ManifestObject)
					if args[4] != manifest {
						t.Fatalf("manifest = %v, want %s", args[4], manifest)
					}
					var storedFiles []backup.PublicationFile
					if err := json.Unmarshal(args[5].(json.RawMessage), &storedFiles); err != nil || len(storedFiles) != len(files) || storedFiles[0].RuntimePath != files[0].RuntimePath || storedFiles[0].SHA256 != files[0].SHA256 {
						t.Fatalf("stored files = %+v, err = %v", storedFiles, err)
					}
					var storedRuntime backup.TemplateRuntime
					if err := json.Unmarshal(args[6].(json.RawMessage), &storedRuntime); err != nil || storedRuntime != *base.TemplateRuntime {
						t.Fatalf("stored runtime = %+v, err = %v", storedRuntime, err)
					}
					return &mockRow{scanFn: func(dest ...any) error { *dest[0].(*bool) = tc.recorded; return nil }}
				}
				t.Fatalf("unexpected query: %s", sql)
				return nil
			}}
			gin.SetMode(gin.TestMode)
			router := gin.New()
			router.POST("/internal/hosts/:host_id/backups", InternalAuth(), (&Handlers{DB: db.New(mock), Config: &config.Config{TemplateBackupBucket: tc.configured}}).ReportHostBackup)
			body, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/internal/hosts/"+tc.host+"/backups", strings.NewReader(string(body)))
			if tc.authorized {
				req.Header.Set("Authorization", "Bearer "+token)
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", w.Code, tc.wantStatus, w.Body.String())
			}
			if (writes == 1) != tc.wantWrite {
				t.Fatalf("publication writes = %d, want write = %v", writes, tc.wantWrite)
			}
			if tc.wantWrite && !strings.Contains(w.Body.String(), `"publication_recorded":`+map[bool]string{true: "true", false: "false"}[tc.recorded]) {
				t.Fatalf("publication response = %s", w.Body.String())
			}
		})
	}
}
