package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

// These tests cover the purely-functional helpers in handlers_template.go
// (validation, spec hashing, shell-quoting). HTTP handler coverage goes
// through integration tests in handlers_test.go.

func TestValidateBuildSpec_Minimal(t *testing.T) {
	spec := &buildSpec{From: "python:3.11"}
	if err := validateBuildSpec(spec); err != nil {
		t.Fatalf("minimal spec should be valid: %v", err)
	}
}

func TestValidateBuildSpec_RejectsNil(t *testing.T) {
	if err := validateBuildSpec(nil); err == nil {
		t.Fatalf("nil spec must be rejected")
	}
}

func TestValidateBuildSpec_RequiresFrom(t *testing.T) {
	if err := validateBuildSpec(&buildSpec{From: ""}); err == nil {
		t.Fatalf("empty from must be rejected")
	}
	if err := validateBuildSpec(&buildSpec{From: "   "}); err == nil {
		t.Fatalf("whitespace-only from must be rejected")
	}
}

func TestValidateBuildSpec_RejectsAlpine(t *testing.T) {
	cases := []string{
		"alpine",
		"alpine:3.21",
		"docker.io/library/alpine:latest",
		"python:3.11-alpine3.21",
	}
	for _, from := range cases {
		t.Run(from, func(t *testing.T) {
			err := validateBuildSpec(&buildSpec{From: from})
			if err == nil || !strings.Contains(err.Error(), "alpine") {
				t.Fatalf("expected alpine rejection for %q, got: %v", from, err)
			}
		})
	}
}

func TestValidateBuildSpec_RejectsDistroless(t *testing.T) {
	err := validateBuildSpec(&buildSpec{From: "gcr.io/distroless/base"})
	if err == nil || !strings.Contains(err.Error(), "distroless") {
		t.Fatalf("expected distroless rejection, got: %v", err)
	}
}

func TestValidateBuildSpec_RequiresExactlyOneOp(t *testing.T) {
	run := "echo hi"
	workdir := "/app"

	// Two ops set → reject.
	err := validateBuildSpec(&buildSpec{
		From: "python:3.11",
		Steps: []buildStep{
			{Run: &run, Workdir: &workdir},
		},
	})
	if err == nil {
		t.Fatalf("step with two ops must be rejected")
	}

	// Zero ops → reject.
	err = validateBuildSpec(&buildSpec{
		From:  "python:3.11",
		Steps: []buildStep{{}},
	})
	if err == nil {
		t.Fatalf("empty step must be rejected")
	}

	// Exactly one → accept.
	err = validateBuildSpec(&buildSpec{
		From:  "python:3.11",
		Steps: []buildStep{{Run: &run}},
	})
	if err != nil {
		t.Fatalf("valid single-op step rejected: %v", err)
	}
}

func TestValidateBuildSpec_EnvRequiresKey(t *testing.T) {
	err := validateBuildSpec(&buildSpec{
		From: "python:3.11",
		Steps: []buildStep{
			{Env: &buildEnvOp{Key: "", Value: "x"}},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "key") {
		t.Fatalf("env without key must be rejected, got: %v", err)
	}
}

// canonicalSpecHash must produce the same hash for equivalent specs
// regardless of JSON field ordering. Go's encoding/json writes map keys
// in sorted order, but struct fields follow declaration order — we rely
// on that, so test it explicitly so a future struct reorder breaks loudly.
func TestCanonicalSpecHash_StableAcrossFieldReorder(t *testing.T) {
	run := "pip install requests"
	a := &buildSpec{
		From: "python:3.11",
		Steps: []buildStep{
			{Run: &run},
		},
		StartCmd: "python server.py",
	}
	h1, err := canonicalSpecHash(a)
	if err != nil {
		t.Fatalf("hash a: %v", err)
	}

	// Re-marshal via an intermediate JSON → struct roundtrip. This mimics
	// what happens when a spec is persisted to jsonb and then unmarshaled
	// on dispatch.
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal a: %v", err)
	}
	var b buildSpec
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("unmarshal a: %v", err)
	}
	h2, err := canonicalSpecHash(&b)
	if err != nil {
		t.Fatalf("hash b: %v", err)
	}
	if h1 != h2 {
		t.Fatalf("hash drifted across roundtrip:\nh1=%s\nh2=%s", h1, h2)
	}
}

// canonicalSpecHash must differ when a meaningful field changes, so the
// idempotency key doesn't collide across distinct specs.
func TestCanonicalSpecHash_DistinctForDifferentSpecs(t *testing.T) {
	a := &buildSpec{From: "python:3.11"}
	b := &buildSpec{From: "python:3.12"}
	ha, _ := canonicalSpecHash(a)
	hb, _ := canonicalSpecHash(b)
	if ha == hb {
		t.Fatalf("different specs produced same hash: %s", ha)
	}
}

// ---------------------------------------------------------------------------
// Template-cache tests
// ---------------------------------------------------------------------------

func clearTemplateCache() {
	templateCache.Range(func(k, _ any) bool {
		templateCache.Delete(k)
		return true
	})
}

type templateCacheTestEnv struct {
	h            *Handlers
	c            *gin.Context
	w            *httptest.ResponseRecorder
	systemTeamID uuid.UUID
	dbCalls      *atomic.Int64
	tplReturned  db.Template
	tplErr       error
}

func newTemplateCacheTestEnv(t *testing.T) *templateCacheTestEnv {
	clearTemplateCache()
	env := &templateCacheTestEnv{
		systemTeamID: uuid.New(),
		dbCalls:      &atomic.Int64{},
	}
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if strings.Contains(sql, "FROM template") {
				env.dbCalls.Add(1)
				if env.tplErr != nil {
					return errorRow(env.tplErr)
				}
				return templateRow(env.tplReturned)
			}
			t.Fatalf("unexpected SQL: %s", sql)
			return nil
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag(""), nil
		},
	}
	env.h = &Handlers{
		DB:     db.New(mock),
		Config: &config.Config{SystemTeamID: env.systemTeamID.String()},
	}
	env.w = httptest.NewRecorder()
	env.c, _ = gin.CreateTestContext(env.w)
	env.c.Request = httptest.NewRequest(http.MethodPost, "/sandboxes", nil)
	return env
}

func TestTemplateCache_SystemTemplate_CachedAcrossCalls(t *testing.T) {
	env := newTemplateCacheTestEnv(t)
	env.tplReturned = db.Template{
		ID:     uuid.New(),
		TeamID: env.systemTeamID,
		Name:   "superserve/base",
		Status: db.TemplateStatusReady,
	}

	callerTeam := uuid.New()
	for i := 0; i < 5; i++ {
		tpl, err := env.h.lookupTemplateForCreate(env.c, callerTeam, "superserve/base")
		if err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
		if tpl.ID != env.tplReturned.ID {
			t.Errorf("call %d: wrong template returned", i)
		}
	}
	if got := env.dbCalls.Load(); got != 1 {
		t.Errorf("DB calls = %d, want 1 (subsequent reads should hit cache)", got)
	}
}

func TestTemplateCache_TeamOwnedTemplate_NotCached(t *testing.T) {
	env := newTemplateCacheTestEnv(t)
	customerTeam := uuid.New()
	env.tplReturned = db.Template{
		ID:     uuid.New(),
		TeamID: customerTeam, // <-- not the system team
		Name:   "my-custom-template",
		Status: db.TemplateStatusReady,
	}

	for i := 0; i < 3; i++ {
		_, err := env.h.lookupTemplateForCreate(env.c, customerTeam, "my-custom-template")
		if err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
	}
	if got := env.dbCalls.Load(); got != 3 {
		t.Errorf("DB calls = %d, want 3 (team-owned templates must skip the cache)", got)
	}
}

func TestTemplateCache_ExpiredEntry_RefetchedFromDB(t *testing.T) {
	env := newTemplateCacheTestEnv(t)
	env.tplReturned = db.Template{
		ID:     uuid.New(),
		TeamID: env.systemTeamID,
		Name:   "superserve/base",
		Status: db.TemplateStatusReady,
	}

	callerTeam := uuid.New()
	if _, err := env.h.lookupTemplateForCreate(env.c, callerTeam, "superserve/base"); err != nil {
		t.Fatalf("initial lookup: %v", err)
	}
	if got := env.dbCalls.Load(); got != 1 {
		t.Fatalf("after first call: db_calls=%d, want 1", got)
	}

	// Reach into the cache and backdate the entry so it appears expired
	// without waiting in real time.
	key := templateCacheKey{teamID: callerTeam, ref: "superserve/base"}
	v, ok := templateCache.Load(key)
	if !ok {
		t.Fatalf("expected entry present after first call")
	}
	v.(*templateCacheEntry).expiry = time.Now().Add(-time.Second)

	if _, err := env.h.lookupTemplateForCreate(env.c, callerTeam, "superserve/base"); err != nil {
		t.Fatalf("second lookup: %v", err)
	}
	if got := env.dbCalls.Load(); got != 2 {
		t.Errorf("after expired entry: db_calls=%d, want 2", got)
	}
}

func TestTemplateCache_NotFound_NotCached(t *testing.T) {
	env := newTemplateCacheTestEnv(t)
	env.tplErr = pgx.ErrNoRows

	callerTeam := uuid.New()
	for i := 0; i < 3; i++ {
		_, err := env.h.lookupTemplateForCreate(env.c, callerTeam, "does-not-exist")
		if err == nil {
			t.Fatalf("call %d: expected error, got nil", i)
		}
		// Reset recorder so the next call's 404 doesn't conflict with the prior.
		env.w = httptest.NewRecorder()
		env.c, _ = gin.CreateTestContext(env.w)
		env.c.Request = httptest.NewRequest(http.MethodPost, "/sandboxes", nil)
	}
	if got := env.dbCalls.Load(); got != 3 {
		t.Errorf("DB calls = %d, want 3 (not-found results must not be cached)", got)
	}
}
