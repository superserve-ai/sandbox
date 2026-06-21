package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/start"
)

func fromImageReq(body string) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/sandboxes/from-image", strings.NewReader(body))
}

// stubDigest overrides the package-level image-digest resolver for a test.
func stubDigest(t *testing.T, digest string) {
	t.Helper()
	orig := resolveImageDigest
	resolveImageDigest = func(context.Context, string) (string, error) { return digest, nil }
	t.Cleanup(func() { resolveImageDigest = orig })
}

func TestCreateSandboxFromImage_MissingImage(t *testing.T) {
	h := &Handlers{VMD: &stubVMD{}, DB: db.New(&mockDBTX{})}
	w := httptest.NewRecorder()
	setupTestRouter(h, uuid.New().String()).ServeHTTP(w, fromImageReq(`{"name":"x"}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing image should 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateSandboxFromImage_CacheHit(t *testing.T) {
	stubDigest(t, "sha256:abc123")
	teamID := uuid.New()
	sandboxID := uuid.New()
	vmd := &stubVMD{}

	tpl := defaultReadyTemplate()
	digest := "sha256:abc123"
	tpl.ResolvedDigest = &digest

	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "resolved_digest"):
				return templateRow(tpl) // cache HIT
			case strings.Contains(sql, "INSERT INTO sandbox"):
				return sandboxRow(db.Sandbox{
					ID: sandboxID, TeamID: teamID, Name: "agent",
					Status: db.SandboxStatusStarting, VcpuCount: 1, MemoryMib: 1024, CreatedAt: time.Now(),
				})
			default:
				return activityRow()
			}
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}
	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, fromImageReq(`{"image":"ghcr.io/org/agent:latest","name":"agent"}`))

	if w.Code != http.StatusCreated {
		t.Fatalf("cache hit should create (201), got %d: %s", w.Code, w.Body.String())
	}
	body := parseJSON(t, w)
	if body["status"] != "active" {
		t.Errorf("sandbox should be active, got %v", body["status"])
	}
}

func TestCreateSandboxFromImage_HitMissingName(t *testing.T) {
	stubDigest(t, "sha256:abc")
	tpl := defaultReadyTemplate()
	d := "sha256:abc"
	tpl.ResolvedDigest = &d
	mock := &mockDBTX{queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
		if strings.Contains(sql, "resolved_digest") {
			return templateRow(tpl)
		}
		return activityRow()
	}}
	h := &Handlers{VMD: &stubVMD{}, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, uuid.New().String()).ServeHTTP(w, fromImageReq(`{"image":"ghcr.io/org/agent:latest"}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("hit without name should 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestResolveImageStartSpec(t *testing.T) {
	// A realistic python image config as it would be stored in image_config jsonb.
	pyConfig := []byte(`{
		"entrypoint": ["/usr/local/bin/python"],
		"cmd": ["app.py"],
		"env": {"PATH": "/usr/local/bin:/usr/bin", "LANG": "C.UTF-8"},
		"working_dir": "/app",
		"user": "1000:1000"
	}`)

	t.Run("bare image runs entrypoint+cmd", func(t *testing.T) {
		spec, err := resolveImageStartSpec(pyConfig, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"/usr/local/bin/python", "app.py"}; !reflect.DeepEqual(spec.Argv, want) {
			t.Errorf("argv = %v, want %v", spec.Argv, want)
		}
		if spec.WorkingDir != "/app" || spec.User != "1000:1000" {
			t.Errorf("workdir/user = %q/%q", spec.WorkingDir, spec.User)
		}
		if spec.Env["LANG"] != "C.UTF-8" {
			t.Errorf("env not carried: %v", spec.Env)
		}
		if !spec.IsRunnable() {
			t.Error("should be runnable")
		}
	})

	t.Run("command overrides entrypoint+cmd (docker run IMG CMD)", func(t *testing.T) {
		spec, err := resolveImageStartSpec(pyConfig, []string{"bash", "-c", "echo hi"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"bash", "-c", "echo hi"}; !reflect.DeepEqual(spec.Argv, want) {
			t.Errorf("argv = %v, want %v", spec.Argv, want)
		}
		// image workdir/user still apply when not overridden
		if spec.WorkingDir != "/app" {
			t.Errorf("workdir = %q", spec.WorkingDir)
		}
	})

	t.Run("request env overrides image env", func(t *testing.T) {
		spec, err := resolveImageStartSpec(pyConfig, nil, map[string]string{"LANG": "en_US.UTF-8", "EXTRA": "1"})
		if err != nil {
			t.Fatal(err)
		}
		if spec.Env["LANG"] != "en_US.UTF-8" {
			t.Errorf("request env should win: LANG=%q", spec.Env["LANG"])
		}
		if spec.Env["EXTRA"] != "1" {
			t.Errorf("request env not added: %v", spec.Env)
		}
		if spec.Env["PATH"] != "/usr/local/bin:/usr/bin" {
			t.Errorf("image env should remain: PATH=%q", spec.Env["PATH"])
		}
	})

	t.Run("nil image config, no command -> not runnable", func(t *testing.T) {
		spec, err := resolveImageStartSpec(nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if spec.IsRunnable() {
			t.Errorf("legacy template with no image config should not auto-start, got argv %v", spec.Argv)
		}
	})

	t.Run("nil image config + command -> runs command", func(t *testing.T) {
		spec, err := resolveImageStartSpec(nil, []string{"python", "agent.py"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"python", "agent.py"}; !reflect.DeepEqual(spec.Argv, want) {
			t.Errorf("argv = %v, want %v", spec.Argv, want)
		}
	})

	t.Run("restart defaults to on-failure", func(t *testing.T) {
		spec, _ := resolveImageStartSpec(pyConfig, nil, nil)
		if spec.Restart != start.RestartOnFailure {
			t.Errorf("restart = %q, want on-failure", spec.Restart)
		}
	})

	t.Run("malformed image config errors", func(t *testing.T) {
		if _, err := resolveImageStartSpec([]byte(`{not json`), nil, nil); err == nil {
			t.Error("expected error for malformed image config")
		}
	})
}
