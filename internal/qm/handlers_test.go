package qm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/qm/adminlink"
	"github.com/superserve-ai/sandbox/internal/qm/provisioner"
	"github.com/superserve-ai/sandbox/internal/qm/secrets"
	"github.com/superserve-ai/sandbox/internal/qm/tenantstore"
)

const (
	keyTeamA     = "ss_live_team_a_key"
	keyTeamB     = "ss_live_team_b_key"
	keyReadOnly  = "ss_live_impersonation_key"
	keyViewer    = "ss_live_team_a_viewer_key"
	keyNoActor   = "ss_live_team_a_legacy_key"
	keyImpNoRead = "ss_live_impersonation_without_scope"
	modelKey     = "sk-ant-api03-fixture-0123456789abcdef"
	fixedSecret  = "0123456789abcdef0123456789abcdef-fixed-test-secret"
	fixedJTI     = "AAAAAAAAAAAAAAAAAAAAAAAA"
	fixedLinkURL = "https://pilot-team.qm.example.com/auth/admin-login#token=eyJrIjoiYWRtaW4tbG9naW4iLCJzdWIiOiJhZG1pbkBleGFtcGxlLmNvbSIsImF1ZCI6Imh0dHBzOi8vcGlsb3QtdGVhbS5xbS5leGFtcGxlLmNvbSIsImlhdCI6MTc4OTAwMDAwMCwiZXhwIjoxNzg5MDAwMzAwLCJqdGkiOiJBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUEifQ.vX2YGPabtW3HWSPva0lVkv22qZPMp-DXSl6FrjJD7SY"
)

var fixedNow = time.Unix(1789000000, 0)

// fakeResolver authenticates by hash and grants permissions per actor,
// the way the RBAC tables would.
type fakeResolver struct {
	keys  map[string]Principal
	perms map[uuid.UUID][]string
}

func (f fakeResolver) Resolve(_ context.Context, hash string) (Principal, error) {
	p, ok := f.keys[hash]
	if !ok {
		return Principal{}, ErrKeyNotFound
	}
	return p, nil
}

func (fakeResolver) Touch(context.Context, Principal) {}

func (f fakeResolver) Can(_ context.Context, p Principal, permission string) (bool, error) {
	if p.ActorID == nil {
		return false, nil
	}
	return slices.Contains(f.perms[*p.ActorID], permission), nil
}

// ownerResolver grants every key full team permissions; for tests that
// are not about authorization.
func ownerResolver(keys map[string]Principal) fakeResolver {
	r := fakeResolver{keys: map[string]Principal{}, perms: map[uuid.UUID][]string{}}
	for hash, p := range keys {
		if p.ActorID == nil && !p.ReadOnly {
			actor := uuid.New()
			p.ActorID = &actor
		}
		if p.ActorID != nil {
			r.perms[*p.ActorID] = []string{PermissionRead, PermissionWrite}
		}
		r.keys[hash] = p
	}
	return r
}

type fixture struct {
	router  *gin.Engine
	store   *tenantstore.Memory
	secrets *secrets.Fake
	trigger *provisioner.Recorder
	teamA   uuid.UUID
	teamB   uuid.UUID
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	gin.SetMode(gin.TestMode)
	f := &fixture{
		store:   tenantstore.NewMemory(),
		secrets: secrets.NewFake(),
		trigger: &provisioner.Recorder{},
		teamA:   uuid.New(),
		teamB:   uuid.New(),
	}
	owner, viewer, teamBOwner := uuid.New(), uuid.New(), uuid.New()
	h := &Handlers{
		Store: f.store, Secrets: f.secrets, Trigger: f.trigger, Log: zerolog.Nop(),
		Now:    func() time.Time { return fixedNow },
		NewJTI: func() (string, error) { return fixedJTI, nil },
	}
	resolver := fakeResolver{
		keys: map[string]Principal{
			HashAPIKey(keyTeamA):     {KeyID: uuid.New(), TeamID: f.teamA, KeyName: "__console_proxy__", ActorID: &owner},
			HashAPIKey(keyViewer):    {KeyID: uuid.New(), TeamID: f.teamA, KeyName: "__console_proxy__", ActorID: &viewer},
			HashAPIKey(keyNoActor):   {KeyID: uuid.New(), TeamID: f.teamA, KeyName: "legacy"},
			HashAPIKey(keyTeamB):     {KeyID: uuid.New(), TeamID: f.teamB, KeyName: "sdk", ActorID: &teamBOwner},
			HashAPIKey(keyReadOnly):  {KeyID: uuid.New(), TeamID: f.teamA, KeyName: consoleImpersonationKeyName, ReadOnly: true, Scopes: []string{"platform:sandbox:read", ImpersonationReadScope}},
			HashAPIKey(keyImpNoRead): {KeyID: uuid.New(), TeamID: f.teamA, KeyName: consoleImpersonationKeyName, ReadOnly: true, Scopes: []string{"platform:sandbox:read"}},
		},
		perms: map[uuid.UUID][]string{
			owner:      {PermissionRead, PermissionWrite},
			viewer:     {PermissionRead},
			teamBOwner: {PermissionRead, PermissionWrite},
		},
	}
	f.router = SetupRouter(h, resolver, zerolog.Nop())
	return f
}

func (f *fixture) do(t *testing.T, method, path, key string, body any) (int, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	if key != "" {
		req.Header.Set("X-API-Key", key)
	}
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	out := map[string]any{}
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s %s: non-JSON body %q", method, path, w.Body.String())
		}
	}
	return w.Code, out
}

func validCreate() map[string]any {
	return map[string]any{
		"slug": "pilot-team", "orgName": "Pilot Team", "adminEmail": "Admin@Example.com",
		"signIn": "magic_link", "modelProvider": "anthropic", "modelKey": modelKey,
	}
}

func (f *fixture) create(t *testing.T) string {
	t.Helper()
	code, body := f.do(t, http.MethodPost, "/v1/qm/tenants", keyTeamA, validCreate())
	if code != http.StatusAccepted {
		t.Fatalf("create: status %d body %v", code, body)
	}
	return body["tenant"].(map[string]any)["id"].(string)
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestAuth(t *testing.T) {
	f := newFixture(t)
	if code, _ := f.do(t, http.MethodGet, "/v1/qm/tenants", "", nil); code != http.StatusUnauthorized {
		t.Errorf("no key: %d", code)
	}
	if code, _ := f.do(t, http.MethodGet, "/v1/qm/tenants", "ss_live_unknown", nil); code != http.StatusUnauthorized {
		t.Errorf("unknown key: %d", code)
	}
	if code, _ := f.do(t, http.MethodGet, "/v1/qm/tenants", keyReadOnly, nil); code != http.StatusOK {
		t.Errorf("read-only list: %d", code)
	}
	for _, m := range []struct{ method, path string }{
		{http.MethodPost, "/v1/qm/tenants"},
		{http.MethodDelete, "/v1/qm/tenants/" + uuid.NewString()},
		{http.MethodPost, "/v1/qm/tenants/" + uuid.NewString() + "/retry"},
		{http.MethodPost, "/v1/qm/tenants/" + uuid.NewString() + "/admin-link"},
	} {
		if code, _ := f.do(t, m.method, m.path, keyReadOnly, validCreate()); code != http.StatusForbidden {
			t.Errorf("read-only %s %s: %d, want 403", m.method, m.path, code)
		}
	}
	if code, _ := f.do(t, http.MethodGet, "/health", "", nil); code != http.StatusOK {
		t.Errorf("health: %d", code)
	}

	// Role-based: a viewer reads but cannot mutate; a key with no actor
	// holds no permission at all; an impersonation key without a platform
	// read scope cannot even read.
	if code, _ := f.do(t, http.MethodGet, "/v1/qm/tenants", keyViewer, nil); code != http.StatusOK {
		t.Errorf("viewer list: %d", code)
	}
	if code, _ := f.do(t, http.MethodPost, "/v1/qm/tenants", keyViewer, validCreate()); code != http.StatusForbidden {
		t.Errorf("viewer create: %d, want 403", code)
	}
	if code, _ := f.do(t, http.MethodGet, "/v1/qm/tenants", keyNoActor, nil); code != http.StatusForbidden {
		t.Errorf("actorless key list: %d, want 403", code)
	}
	if code, _ := f.do(t, http.MethodPost, "/v1/qm/tenants", keyNoActor, validCreate()); code != http.StatusForbidden {
		t.Errorf("actorless key create: %d, want 403", code)
	}
	if code, _ := f.do(t, http.MethodGet, "/v1/qm/tenants", keyImpNoRead, nil); code != http.StatusForbidden {
		t.Errorf("impersonation with only another resource's read scope: %d, want 403", code)
	}
	if len(f.trigger.Calls) != 0 || len(f.secrets.Puts) != 0 {
		t.Error("a forbidden request reached the trigger or secret store")
	}
}

func TestCreateTenantValidation(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		name  string
		patch map[string]any
		field string
	}{
		{"reserved slug", map[string]any{"slug": "admin"}, "slug"},
		{"short slug", map[string]any{"slug": "ab"}, "slug"},
		{"bad slug chars", map[string]any{"slug": "Pilot_Team"}, "slug"},
		{"long slug", map[string]any{"slug": strings.Repeat("a", 41)}, "slug"},
		{"empty org", map[string]any{"orgName": " "}, "orgName"},
		{"long org", map[string]any{"orgName": strings.Repeat("é", 101)}, "orgName"},
		{"bad email", map[string]any{"adminEmail": "nope"}, "adminEmail"},
		{"bad sign-in", map[string]any{"signIn": "password"}, "signIn"},
		{"bad provider", map[string]any{"modelProvider": "mistral"}, "modelProvider"},
		{"empty model key", map[string]any{"modelKey": ""}, "modelKey"},
		{"model key with spaces", map[string]any{"modelKey": "sk-ant one two"}, "modelKey"},
		{"bad harness", map[string]any{"harness": "aider"}, "harness"},
	}
	for _, tc := range cases {
		body := validCreate()
		for k, v := range tc.patch {
			body[k] = v
		}
		code, resp := f.do(t, http.MethodPost, "/v1/qm/tenants", keyTeamA, body)
		if code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", tc.name, code)
			continue
		}
		if _, ok := resp["error"].(string); !ok {
			t.Errorf("%s: missing error string", tc.name)
		}
		fields, _ := resp["fields"].(map[string]any)
		if _, ok := fields[tc.field]; !ok {
			t.Errorf("%s: fields = %v, want %q", tc.name, fields, tc.field)
		}
	}
	if code, _ := f.do(t, http.MethodPost, "/v1/qm/tenants", keyTeamA, nil); code != http.StatusBadRequest {
		t.Errorf("empty body: %d", code)
	}
	if len(f.trigger.Calls) != 0 || len(f.secrets.Puts) != 0 {
		t.Errorf("invalid requests reached the trigger or secret store")
	}
	// The limit is characters, not bytes.
	multibyte := validCreate()
	multibyte["orgName"] = strings.Repeat("é", 100)
	if code, body := f.do(t, http.MethodPost, "/v1/qm/tenants", keyTeamA, multibyte); code != http.StatusAccepted {
		t.Errorf("100-character multibyte org name: %d %v", code, body)
	}
}

func TestCreateTenant(t *testing.T) {
	f := newFixture(t)
	code, body := f.do(t, http.MethodPost, "/v1/qm/tenants", keyTeamA, validCreate())
	if code != http.StatusAccepted {
		t.Fatalf("status %d body %v", code, body)
	}
	tenant := body["tenant"].(map[string]any)
	wantKeys := []string{"adminEmail", "createdAt", "harness", "id", "imageTag", "modelProvider", "orgName", "publicUrl", "signIn", "slug", "status", "teamId", "updatedAt"}
	if got := keysOf(tenant); strings.Join(got, ",") != strings.Join(wantKeys, ",") {
		t.Errorf("tenant keys = %v, want %v", got, wantKeys)
	}
	if tenant["status"] != "provisioning" || tenant["harness"] != "pi" || tenant["adminEmail"] != "admin@example.com" || tenant["teamId"] != f.teamA.String() {
		t.Errorf("tenant = %v", tenant)
	}
	if tenant["publicUrl"] != nil || tenant["imageTag"] != nil {
		t.Errorf("unprovisioned tenant has publicUrl/imageTag: %v", tenant)
	}

	id := uuid.MustParse(tenant["id"].(string))
	secretName := "qm-pilot-team-ANTHROPIC_API_KEY"
	if !f.secrets.Has(secretName) || f.secrets.Puts[secretName] != 1 {
		t.Errorf("model key not stored exactly once under %s: %v", secretName, f.secrets.Puts)
	}
	if v, _ := f.secrets.Get(context.Background(), secretName); string(v) != modelKey {
		t.Errorf("stored key = %q", v)
	}
	refs, _ := f.store.ListSecretRefs(context.Background(), f.teamA, id)
	if len(refs) != 1 || refs[0].Name != "ANTHROPIC_API_KEY" {
		t.Errorf("secret refs = %+v", refs)
	}
	if len(f.trigger.Calls) != 1 || f.trigger.Calls[0] != (provisioner.TriggerCall{TeamID: f.teamA, TenantID: id, Mode: provisioner.ModeProvision}) {
		t.Errorf("trigger calls = %+v", f.trigger.Calls)
	}
	events, _ := f.store.ListEvents(context.Background(), f.teamA, id)
	var steps []string
	for _, e := range events {
		steps = append(steps, e.Step+":"+e.Status)
		if strings.Contains(string(e.Detail), modelKey) || (e.Message != nil && strings.Contains(*e.Message, modelKey)) {
			t.Errorf("model key leaked into event %+v", e)
		}
	}
	if strings.Join(steps, ",") != "model_key:ok,trigger:started,trigger:ok" {
		t.Errorf("events = %v", steps)
	}

	if code, _ := f.do(t, http.MethodPost, "/v1/qm/tenants", keyTeamA, validCreate()); code != http.StatusConflict {
		t.Errorf("second tenant for the team: %d, want 409", code)
	}
	if code, resp := f.do(t, http.MethodPost, "/v1/qm/tenants", keyTeamB, validCreate()); code != http.StatusConflict || resp["fields"] != nil {
		t.Errorf("slug taken by another team: %d %v, want 409 without fields", code, resp)
	}
	other := validCreate()
	other["slug"] = "other-team"
	f.store.Detached = map[uuid.UUID]bool{f.teamB: true}
	if code, resp := f.do(t, http.MethodPost, "/v1/qm/tenants", keyTeamB, other); code != http.StatusConflict || resp["fields"] != nil {
		t.Errorf("team detached by migration: %d %v, want 409", code, resp)
	}
	f.store.Detached = nil
	if code, _ := f.do(t, http.MethodPost, "/v1/qm/tenants", keyTeamB, other); code != http.StatusAccepted {
		t.Errorf("other team's own tenant: %d", code)
	}
}

func TestGetAndListTenant(t *testing.T) {
	f := newFixture(t)
	id := f.create(t)

	code, body := f.do(t, http.MethodGet, "/v1/qm/tenants/"+id, keyTeamA, nil)
	if code != http.StatusOK {
		t.Fatalf("get: %d", code)
	}
	if got := keysOf(body); strings.Join(got, ",") != "events,tenant" {
		t.Errorf("get keys = %v", got)
	}
	events := body["events"].([]any)
	if len(events) != 3 {
		t.Fatalf("events = %v", events)
	}
	ev := events[0].(map[string]any)
	if got := keysOf(ev); strings.Join(got, ",") != "at,detail,id,message,status,step" {
		t.Errorf("event keys = %v", got)
	}
	if _, err := uuid.Parse(ev["id"].(string)); err != nil {
		t.Errorf("event id %v is not a uuid", ev["id"])
	}

	code, body = f.do(t, http.MethodGet, "/v1/qm/tenants", keyTeamA, nil)
	if code != http.StatusOK || len(body["tenants"].([]any)) != 1 {
		t.Errorf("list: %d %v", code, body)
	}
	if code, body := f.do(t, http.MethodGet, "/v1/qm/tenants", keyTeamB, nil); code != http.StatusOK || len(body["tenants"].([]any)) != 0 {
		t.Errorf("other team's list: %d %v", code, body)
	}
	if code, _ := f.do(t, http.MethodGet, "/v1/qm/tenants/"+id, keyTeamB, nil); code != http.StatusNotFound {
		t.Errorf("cross-team get: %d, want 404", code)
	}
	if code, _ := f.do(t, http.MethodGet, "/v1/qm/tenants/not-a-uuid", keyTeamA, nil); code != http.StatusNotFound {
		t.Errorf("bad id: %d, want 404", code)
	}
}

func TestDeleteTenant(t *testing.T) {
	f := newFixture(t)
	id := f.create(t)
	tid := uuid.MustParse(id)

	if code, _ := f.do(t, http.MethodDelete, "/v1/qm/tenants/"+id, keyTeamA, nil); code != http.StatusConflict {
		t.Errorf("delete while provisioning: %d, want 409", code)
	}
	if _, err := f.store.SetStatus(context.Background(), f.teamA, tid, tenantstore.StatusReady); err != nil {
		t.Fatal(err)
	}
	code, body := f.do(t, http.MethodDelete, "/v1/qm/tenants/"+id, keyTeamA, nil)
	if code != http.StatusAccepted || body["tenant"].(map[string]any)["status"] != "deprovisioning" {
		t.Fatalf("delete: %d %v", code, body)
	}
	last := f.trigger.Calls[len(f.trigger.Calls)-1]
	if last.Mode != provisioner.ModeDeprovision || last.TenantID != tid {
		t.Errorf("trigger = %+v", last)
	}
	if code, _ := f.do(t, http.MethodDelete, "/v1/qm/tenants/"+id, keyTeamA, nil); code != http.StatusConflict {
		t.Errorf("delete while deprovisioning: %d, want 409", code)
	}
	if _, err := f.store.SoftDelete(context.Background(), f.teamA, tid); err != nil {
		t.Fatal(err)
	}
	if code, _ := f.do(t, http.MethodGet, "/v1/qm/tenants/"+id, keyTeamA, nil); code != http.StatusNotFound {
		t.Errorf("deleted tenant get: %d, want 404", code)
	}
	if code, _ := f.do(t, http.MethodDelete, "/v1/qm/tenants/"+id, keyTeamA, nil); code != http.StatusNotFound {
		t.Errorf("deleted tenant delete: %d, want 404", code)
	}
}

func TestRetryTenant(t *testing.T) {
	f := newFixture(t)
	id := f.create(t)
	tid := uuid.MustParse(id)
	ctx := context.Background()

	if code, _ := f.do(t, http.MethodPost, "/v1/qm/tenants/"+id+"/retry", keyTeamA, nil); code != http.StatusConflict {
		t.Errorf("retry while provisioning: %d, want 409", code)
	}

	// Failed during a provision run: retry provisions.
	f.store.InsertEvent(ctx, f.teamA, tenantstore.EventParams{TenantID: tid, Step: provisioner.RunStep, Status: tenantstore.EventStarted, Detail: json.RawMessage(`{"mode":"provision"}`)})
	f.store.SetStatus(ctx, f.teamA, tid, tenantstore.StatusFailed)
	code, body := f.do(t, http.MethodPost, "/v1/qm/tenants/"+id+"/retry", keyTeamA, nil)
	if code != http.StatusAccepted || body["tenant"].(map[string]any)["status"] != "provisioning" {
		t.Fatalf("retry: %d %v", code, body)
	}
	if last := f.trigger.Calls[len(f.trigger.Calls)-1]; last.Mode != provisioner.ModeProvision {
		t.Errorf("retry mode = %s", last.Mode)
	}

	// Failed during a deprovision run: retry resumes the teardown.
	f.store.InsertEvent(ctx, f.teamA, tenantstore.EventParams{TenantID: tid, Step: provisioner.RunStep, Status: tenantstore.EventStarted, Detail: json.RawMessage(`{"mode":"deprovision"}`)})
	f.store.SetStatus(ctx, f.teamA, tid, tenantstore.StatusFailed)
	code, body = f.do(t, http.MethodPost, "/v1/qm/tenants/"+id+"/retry", keyTeamA, nil)
	if code != http.StatusAccepted || body["tenant"].(map[string]any)["status"] != "deprovisioning" {
		t.Fatalf("retry deprovision: %d %v", code, body)
	}
	if last := f.trigger.Calls[len(f.trigger.Calls)-1]; last.Mode != provisioner.ModeDeprovision {
		t.Errorf("retry mode = %s", last.Mode)
	}
}

func TestAdminLink(t *testing.T) {
	f := newFixture(t)
	id := f.create(t)
	tid := uuid.MustParse(id)
	ctx := context.Background()
	path := "/v1/qm/tenants/" + id + "/admin-link"

	if code, _ := f.do(t, http.MethodPost, path, keyTeamA, nil); code != http.StatusConflict {
		t.Errorf("admin link before ready: %d, want 409", code)
	}
	publicURL := "https://pilot-team.qm.example.com"
	f.store.UpdateResources(ctx, f.teamA, tid, tenantstore.Resources{PublicURL: &publicURL})
	f.store.SetStatus(ctx, f.teamA, tid, tenantstore.StatusReady)

	if code, _ := f.do(t, http.MethodPost, path, keyTeamA, nil); code != http.StatusBadGateway {
		t.Errorf("admin link without portal secret: %d, want 502", code)
	}
	f.secrets.Put(ctx, "qm-pilot-team-PORTAL_SESSION_SECRET", []byte(fixedSecret))

	code, body := f.do(t, http.MethodPost, path, keyTeamA, nil)
	if code != http.StatusOK {
		t.Fatalf("admin link: %d %v", code, body)
	}
	if got := keysOf(body); strings.Join(got, ",") != "expiresAt,url" {
		t.Errorf("admin link keys = %v", got)
	}
	if body["url"] != fixedLinkURL {
		t.Errorf("url =\n %v\nwant\n %v", body["url"], fixedLinkURL)
	}
	expires, err := time.Parse(time.RFC3339, body["expiresAt"].(string))
	if err != nil || !expires.Equal(fixedNow.Add(adminlink.TTL)) {
		t.Errorf("expiresAt = %v (%v), want %v", body["expiresAt"], err, fixedNow.Add(adminlink.TTL))
	}
	token, err := adminlink.TokenFromURL(body["url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if adminlink.Verify(token, fixedSecret, publicURL, fixedNow.Add(time.Minute)) == nil {
		t.Error("portal verifier rejected the minted link")
	}
	if code, _ := f.do(t, http.MethodGet, path, keyTeamA, nil); code != http.StatusNotFound {
		t.Errorf("GET admin-link: %d, want 404 (POST only)", code)
	}
}

func TestSlugAvailability(t *testing.T) {
	f := newFixture(t)
	f.create(t)
	cases := map[string]bool{"pilot-team": false, "admin": false, "ab": false, "fresh-slug": true}
	for slug, want := range cases {
		code, body := f.do(t, http.MethodGet, "/v1/qm/slugs/"+slug+"/availability", keyTeamB, nil)
		if code != http.StatusOK || body["available"] != want {
			t.Errorf("%s: %d %v, want available=%v", slug, code, body, want)
		}
		if _, hasReason := body["reason"]; hasReason == want {
			t.Errorf("%s: reason presence %v does not match availability %v", slug, hasReason, want)
		}
	}
}

func TestCreateTenantWhenTriggerFails(t *testing.T) {
	f := newFixture(t)
	f.trigger.Err = fmt.Errorf("%w: jobs.run: permission denied", provisioner.ErrTriggerRejected)
	code, body := f.do(t, http.MethodPost, "/v1/qm/tenants", keyTeamA, validCreate())
	if code != http.StatusBadGateway {
		t.Fatalf("status %d body %v", code, body)
	}
	tenants, _ := f.store.ListTenants(context.Background(), f.teamA)
	if len(tenants) != 1 || tenants[0].Status != tenantstore.StatusFailed {
		t.Fatalf("tenants = %+v", tenants)
	}
	events, _ := f.store.ListEvents(context.Background(), f.teamA, tenants[0].ID)
	last := events[len(events)-1]
	if last.Step != stepTrigger || last.Status != tenantstore.EventFailed {
		t.Errorf("last event = %+v", last)
	}
}

func TestCreateTenantWhenSecretStoreFails(t *testing.T) {
	f := newFixture(t)
	f.secrets.Err = errors.New("secret manager unavailable")
	code, _ := f.do(t, http.MethodPost, "/v1/qm/tenants", keyTeamA, validCreate())
	if code != http.StatusBadGateway {
		t.Fatalf("status %d", code)
	}
	tenants, _ := f.store.ListTenants(context.Background(), f.teamA)
	if len(tenants) != 1 || tenants[0].Status != tenantstore.StatusFailed {
		t.Fatalf("tenants = %+v", tenants)
	}
	if len(f.trigger.Calls) != 0 {
		t.Error("a run was triggered without a stored model key")
	}
}

// A delete whose job never started must retry as a deprovision, not a
// provision, and must be marked failed even if the request is gone.
func TestDeleteTriggerFailureRetriesAsDeprovision(t *testing.T) {
	f := newFixture(t)
	id := f.create(t)
	tid := uuid.MustParse(id)
	ctx := context.Background()
	f.store.SetStatus(ctx, f.teamA, tid, tenantstore.StatusReady)

	f.trigger.Err = fmt.Errorf("%w: jobs.run: job not found", provisioner.ErrTriggerRejected)
	if code, _ := f.do(t, http.MethodDelete, "/v1/qm/tenants/"+id, keyTeamA, nil); code != http.StatusBadGateway {
		t.Fatalf("delete with failing trigger: %d", code)
	}
	row, _ := f.store.GetTenant(ctx, f.teamA, tid)
	if row.Status != tenantstore.StatusFailed {
		t.Fatalf("status = %s, want failed", row.Status)
	}
	f.trigger.Err = nil
	code, body := f.do(t, http.MethodPost, "/v1/qm/tenants/"+id+"/retry", keyTeamA, nil)
	if code != http.StatusAccepted || body["tenant"].(map[string]any)["status"] != "deprovisioning" {
		t.Fatalf("retry: %d %v", code, body)
	}
	if last := f.trigger.Calls[len(f.trigger.Calls)-1]; last.Mode != provisioner.ModeDeprovision {
		t.Errorf("retry mode = %s, want deprovision", last.Mode)
	}
}

func TestFailTenantSurvivesCancelledRequest(t *testing.T) {
	f := newFixture(t)
	id := f.create(t)
	tid := uuid.MustParse(id)
	row, _ := f.store.GetTenant(context.Background(), f.teamA, tid)

	h := &Handlers{Store: f.store, Secrets: f.secrets, Trigger: f.trigger, Log: zerolog.Nop()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.failTenant(ctx, row, stepTrigger, "run could not be started", errors.New("client went away"), map[string]any{"mode": "provision"})

	row, _ = f.store.GetTenant(context.Background(), f.teamA, tid)
	if row.Status != tenantstore.StatusFailed {
		t.Errorf("status = %s, want failed", row.Status)
	}
	events, _ := f.store.ListEvents(context.Background(), f.teamA, tid)
	if last := events[len(events)-1]; last.Step != stepTrigger || last.Status != tenantstore.EventFailed || !strings.Contains(string(last.Detail), `"mode":"provision"`) {
		t.Errorf("last event = %+v", last)
	}
}

func TestCreateTenantCleansUpUnreferencedModelKey(t *testing.T) {
	f := newFixture(t)
	// A store that accepts the tenant but cannot record the secret reference.
	f.store.Fail = nil
	h := &Handlers{Store: refFailingStore{f.store}, Secrets: f.secrets, Trigger: f.trigger, Log: zerolog.Nop()}
	f.router = SetupRouter(h, ownerResolver(map[string]Principal{HashAPIKey(keyTeamA): {TeamID: f.teamA}}), zerolog.Nop())
	code, _ := f.do(t, http.MethodPost, "/v1/qm/tenants", keyTeamA, validCreate())
	if code != http.StatusInternalServerError {
		t.Fatalf("status %d", code)
	}
	if f.secrets.Has("qm-pilot-team-ANTHROPIC_API_KEY") {
		t.Error("unreferenced model key left in the secret store")
	}
	tenants, _ := f.store.ListTenants(context.Background(), f.teamA)
	if len(tenants) != 1 || tenants[0].Status != tenantstore.StatusFailed {
		t.Errorf("tenants = %+v", tenants)
	}
	if len(f.trigger.Calls) != 0 {
		t.Error("a run was triggered")
	}
}

type refFailingStore struct {
	*tenantstore.Memory
}

func (refFailingStore) SetSecretRef(context.Context, uuid.UUID, uuid.UUID, string, string) error {
	return errors.New("database unavailable")
}

func TestRetryRefusedWithoutStoredModelKey(t *testing.T) {
	f := newFixture(t)
	f.secrets.Err = errors.New("secret manager unavailable")
	if code, _ := f.do(t, http.MethodPost, "/v1/qm/tenants", keyTeamA, validCreate()); code != http.StatusBadGateway {
		t.Fatalf("create: %d", code)
	}
	f.secrets.Err = nil
	tenants, _ := f.store.ListTenants(context.Background(), f.teamA)
	id := tenants[0].ID.String()
	code, body := f.do(t, http.MethodPost, "/v1/qm/tenants/"+id+"/retry", keyTeamA, nil)
	if code != http.StatusConflict || !strings.Contains(body["error"].(string), "model key") {
		t.Fatalf("retry without a stored key: %d %v", code, body)
	}
	if len(f.trigger.Calls) != 0 {
		t.Error("a run was triggered")
	}
	// Deleting is still the way out.
	if code, _ := f.do(t, http.MethodDelete, "/v1/qm/tenants/"+id, keyTeamA, nil); code != http.StatusAccepted {
		t.Errorf("delete: %d", code)
	}
}

// Of two requests racing for the same failed tenant, the one whose status
// transition wins queues its run; the other gets 409 and triggers nothing.
func TestConcurrentDeleteAndRetryCannotBothWin(t *testing.T) {
	f := newFixture(t)
	id := f.create(t)
	tid := uuid.MustParse(id)
	ctx := context.Background()
	f.store.InsertEvent(ctx, f.teamA, tenantstore.EventParams{TenantID: tid, Step: provisioner.RunStep, Status: tenantstore.EventStarted, Detail: json.RawMessage(`{"mode":"provision"}`)})
	f.store.SetStatus(ctx, f.teamA, tid, tenantstore.StatusFailed)
	calls := len(f.trigger.Calls)

	// The delete lands first at the store; the retry's transition then
	// finds the tenant deprovisioning rather than failed.
	if code, _ := f.do(t, http.MethodDelete, "/v1/qm/tenants/"+id, keyTeamA, nil); code != http.StatusAccepted {
		t.Fatalf("delete: %d", code)
	}
	if code, _ := f.do(t, http.MethodPost, "/v1/qm/tenants/"+id+"/retry", keyTeamA, nil); code != http.StatusConflict {
		t.Fatalf("retry after delete won: %d, want 409", code)
	}
	if len(f.trigger.Calls) != calls+1 || f.trigger.Calls[calls].Mode != provisioner.ModeDeprovision {
		t.Errorf("trigger calls = %+v", f.trigger.Calls[calls:])
	}

	// And the store-level guard itself: a transition from a status the
	// tenant is no longer in is refused.
	if _, err := f.store.TransitionStatus(ctx, f.teamA, tid, []string{tenantstore.StatusFailed}, tenantstore.StatusProvisioning); !errors.Is(err, tenantstore.ErrStatusConflict) {
		t.Errorf("transition from stale status: err = %v", err)
	}
}

// The intent is persisted before a run is started, not as best-effort
// bookkeeping. A delete whose intent cannot be written is undone — the
// tenant goes back to its previous status and the delete is issued again —
// rather than marked failed with a mode that a retry might never see.
func TestQueueRunRequiresIntentEvent(t *testing.T) {
	f := newFixture(t)
	id := f.create(t)
	tid := uuid.MustParse(id)
	ctx := context.Background()
	f.store.SetStatus(ctx, f.teamA, tid, tenantstore.StatusReady)

	failing := &eventFailingStore{Memory: f.store, failNext: 1}
	h := &Handlers{Store: failing, Secrets: f.secrets, Trigger: f.trigger, Log: zerolog.Nop()}
	f.router = SetupRouter(h, ownerResolver(map[string]Principal{HashAPIKey(keyTeamA): {TeamID: f.teamA}}), zerolog.Nop())
	calls := len(f.trigger.Calls)
	if code, _ := f.do(t, http.MethodDelete, "/v1/qm/tenants/"+id, keyTeamA, nil); code != http.StatusInternalServerError {
		t.Fatalf("delete with failing intent write: %d, want 500", code)
	}
	if len(f.trigger.Calls) != calls {
		t.Error("a run was triggered without its intent recorded")
	}
	row, _ := f.store.GetTenant(ctx, f.teamA, tid)
	if row.Status != tenantstore.StatusReady {
		t.Fatalf("status = %s, want ready restored", row.Status)
	}
	if code, _ := f.do(t, http.MethodPost, "/v1/qm/tenants/"+id+"/retry", keyTeamA, nil); code != http.StatusConflict {
		t.Errorf("retry of a ready tenant: %d, want 409", code)
	}
	code, body := f.do(t, http.MethodDelete, "/v1/qm/tenants/"+id, keyTeamA, nil)
	if code != http.StatusAccepted || body["tenant"].(map[string]any)["status"] != "deprovisioning" {
		t.Fatalf("delete again: %d %v", code, body)
	}
	if last := f.trigger.Calls[len(f.trigger.Calls)-1]; last.Mode != provisioner.ModeDeprovision {
		t.Errorf("mode = %s", last.Mode)
	}
}

// eventFailingStore fails the next failNext InsertEvent calls.
type eventFailingStore struct {
	*tenantstore.Memory
	failNext int
}

func (s *eventFailingStore) InsertEvent(ctx context.Context, teamID uuid.UUID, p tenantstore.EventParams) (tenantstore.Event, error) {
	if s.failNext > 0 {
		s.failNext--
		return tenantstore.Event{}, errors.New("database unavailable")
	}
	return s.Memory.InsertEvent(ctx, teamID, p)
}

// An in-flight tenant whose run went quiet is reclaimed on the next retry
// or delete; one that is still producing events is not.
func TestStaleRunIsReclaimed(t *testing.T) {
	f := newFixture(t)
	now := fixedNow
	f.store.Now = func() time.Time { return now }
	id := f.create(t)
	tid := uuid.MustParse(id)
	ctx := context.Background()

	h := &Handlers{Store: f.store, Secrets: f.secrets, Trigger: f.trigger, Log: zerolog.Nop(), StaleAfter: 30 * time.Minute, Now: func() time.Time { return now }}
	f.router = SetupRouter(h, ownerResolver(map[string]Principal{HashAPIKey(keyTeamA): {TeamID: f.teamA}}), zerolog.Nop())

	// Fresh: still provisioning, nothing to reclaim.
	if code, _ := f.do(t, http.MethodPost, "/v1/qm/tenants/"+id+"/retry", keyTeamA, nil); code != http.StatusConflict {
		t.Fatalf("retry while fresh: %d, want 409", code)
	}
	// Quiet for longer than the window: reclaimed and retried as a provision.
	now = fixedNow.Add(31 * time.Minute)
	code, body := f.do(t, http.MethodPost, "/v1/qm/tenants/"+id+"/retry", keyTeamA, nil)
	if code != http.StatusAccepted || body["tenant"].(map[string]any)["status"] != "provisioning" {
		t.Fatalf("retry after stale: %d %v", code, body)
	}
	events, _ := f.store.ListEvents(ctx, f.teamA, tid)
	var sawReclaim bool
	for _, e := range events {
		if e.Step == provisioner.RunStep && e.Status == tenantstore.EventFailed && e.Message != nil && strings.Contains(*e.Message, "lost") {
			sawReclaim = true
		}
	}
	if !sawReclaim {
		t.Errorf("no reclaim event recorded")
	}

	// A run that is slow but alive (recent event) is left alone.
	now = now.Add(29 * time.Minute)
	f.store.InsertEvent(ctx, f.teamA, tenantstore.EventParams{TenantID: tid, Step: "cloud_run", Status: tenantstore.EventStarted})
	now = now.Add(20 * time.Minute)
	if code, _ := f.do(t, http.MethodDelete, "/v1/qm/tenants/"+id, keyTeamA, nil); code != http.StatusConflict {
		t.Errorf("delete while run is active: %d, want 409", code)
	}
	// Quiet past the window but still holding the lock: alive, not reclaimed.
	now = now.Add(time.Hour)
	release, err := f.store.Lock(ctx, f.teamA, tid)
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := f.do(t, http.MethodDelete, "/v1/qm/tenants/"+id, keyTeamA, nil); code != http.StatusConflict {
		t.Errorf("delete while the run holds the lock: %d, want 409", code)
	}
	release()
	// Stale deprovisioning is reclaimed and the delete re-queued.
	f.store.SetStatus(ctx, f.teamA, tid, tenantstore.StatusDeprovisioning)
	now = now.Add(31 * time.Minute)
	code, body = f.do(t, http.MethodDelete, "/v1/qm/tenants/"+id, keyTeamA, nil)
	if code != http.StatusAccepted || body["tenant"].(map[string]any)["status"] != "deprovisioning" {
		t.Errorf("delete after stale deprovision: %d %v", code, body)
	}
}

// A trigger error that does not rule out a started run leaves the tenant
// in flight: retry and delete are refused until the run reports or goes
// stale, so nothing can race an execution that is about to start.
func TestAmbiguousTriggerFailureKeepsTenantInFlight(t *testing.T) {
	f := newFixture(t)
	f.trigger.Err = errors.New("jobs.run: context deadline exceeded")
	code, _ := f.do(t, http.MethodPost, "/v1/qm/tenants", keyTeamA, validCreate())
	if code != http.StatusBadGateway {
		t.Fatalf("status %d", code)
	}
	tenants, _ := f.store.ListTenants(context.Background(), f.teamA)
	if len(tenants) != 1 || tenants[0].Status != tenantstore.StatusProvisioning {
		t.Fatalf("tenants = %+v, want one still provisioning", tenants)
	}
	id := tenants[0].ID.String()
	events, _ := f.store.ListEvents(context.Background(), f.teamA, tenants[0].ID)
	last := events[len(events)-1]
	if last.Step != stepTrigger || last.Status != tenantstore.EventFailed || !strings.Contains(string(last.Detail), `"ambiguous":true`) {
		t.Errorf("last event = %+v", last)
	}
	f.trigger.Err = nil
	if code, _ := f.do(t, http.MethodPost, "/v1/qm/tenants/"+id+"/retry", keyTeamA, nil); code != http.StatusConflict {
		t.Errorf("retry while possibly running: %d, want 409", code)
	}
	if code, _ := f.do(t, http.MethodDelete, "/v1/qm/tenants/"+id, keyTeamA, nil); code != http.StatusConflict {
		t.Errorf("delete while possibly running: %d, want 409", code)
	}
}

// A retry or delete is refused while the previous run still holds the
// tenant lock, so the run it would queue cannot exit as locked and strand
// the tenant in flight.
func TestQueueRunWaitsForPreviousRunToRelease(t *testing.T) {
	f := newFixture(t)
	id := f.create(t)
	tid := uuid.MustParse(id)
	ctx := context.Background()
	f.store.SetStatus(ctx, f.teamA, tid, tenantstore.StatusFailed)
	calls := len(f.trigger.Calls)

	release, err := f.store.Lock(ctx, f.teamA, tid)
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := f.do(t, http.MethodPost, "/v1/qm/tenants/"+id+"/retry", keyTeamA, nil); code != http.StatusConflict {
		t.Errorf("retry while locked: %d, want 409", code)
	}
	if code, _ := f.do(t, http.MethodDelete, "/v1/qm/tenants/"+id, keyTeamA, nil); code != http.StatusConflict {
		t.Errorf("delete while locked: %d, want 409", code)
	}
	row, _ := f.store.GetTenant(ctx, f.teamA, tid)
	if row.Status != tenantstore.StatusFailed || len(f.trigger.Calls) != calls {
		t.Fatalf("locked requests changed state: status=%s triggers=%d", row.Status, len(f.trigger.Calls)-calls)
	}
	release()
	if code, _ := f.do(t, http.MethodPost, "/v1/qm/tenants/"+id+"/retry", keyTeamA, nil); code != http.StatusAccepted {
		t.Errorf("retry after release: %d, want 202", code)
	}
}

// An error from the reference write that nevertheless committed must not
// cost the tenant its model key.
func TestCreateTenantKeepsModelKeyWhenRefWriteCommittedDespiteError(t *testing.T) {
	f := newFixture(t)
	h := &Handlers{Store: ambiguousRefStore{f.store}, Secrets: f.secrets, Trigger: f.trigger, Log: zerolog.Nop()}
	f.router = SetupRouter(h, ownerResolver(map[string]Principal{HashAPIKey(keyTeamA): {TeamID: f.teamA}}), zerolog.Nop())
	code, body := f.do(t, http.MethodPost, "/v1/qm/tenants", keyTeamA, validCreate())
	if code != http.StatusAccepted {
		t.Fatalf("status %d body %v", code, body)
	}
	if !f.secrets.Has("qm-pilot-team-ANTHROPIC_API_KEY") {
		t.Error("model key deleted although its reference was recorded")
	}
	if len(f.trigger.Calls) != 1 {
		t.Errorf("trigger calls = %d", len(f.trigger.Calls))
	}
}

// ambiguousRefStore persists the reference and then reports an error, the
// way a connection dropped after commit looks to the client.
type ambiguousRefStore struct {
	*tenantstore.Memory
}

func (s ambiguousRefStore) SetSecretRef(ctx context.Context, teamID, tenantID uuid.UUID, name, ref string) error {
	if err := s.Memory.SetSecretRef(ctx, teamID, tenantID, name, ref); err != nil {
		return err
	}
	return errors.New("unexpected EOF")
}

// When the reference cannot even be re-read, the key is kept: a wrong
// deletion is unrecoverable, a kept key is cleaned up by teardown.
func TestCreateTenantKeepsModelKeyWhenRefReadFails(t *testing.T) {
	f := newFixture(t)
	h := &Handlers{Store: &refUnreadableStore{Memory: f.store}, Secrets: f.secrets, Trigger: f.trigger, Log: zerolog.Nop()}
	f.router = SetupRouter(h, ownerResolver(map[string]Principal{HashAPIKey(keyTeamA): {TeamID: f.teamA}}), zerolog.Nop())
	if code, _ := f.do(t, http.MethodPost, "/v1/qm/tenants", keyTeamA, validCreate()); code != http.StatusInternalServerError {
		t.Fatalf("status %d", code)
	}
	if !f.secrets.Has("qm-pilot-team-ANTHROPIC_API_KEY") {
		t.Error("model key deleted on an unverifiable reference")
	}
	tenants, _ := f.store.ListTenants(context.Background(), f.teamA)
	if len(tenants) != 1 || tenants[0].Status != tenantstore.StatusFailed {
		t.Errorf("tenants = %+v", tenants)
	}
}

// refUnreadableStore fails the reference write and every read of the
// references after it.
type refUnreadableStore struct {
	*tenantstore.Memory
	broken bool
}

func (s *refUnreadableStore) SetSecretRef(context.Context, uuid.UUID, uuid.UUID, string, string) error {
	s.broken = true
	return errors.New("database unavailable")
}

func (s *refUnreadableStore) ListSecretRefs(ctx context.Context, teamID, tenantID uuid.UUID) ([]tenantstore.SecretRef, error) {
	if s.broken {
		return nil, errors.New("database unavailable")
	}
	return s.Memory.ListSecretRefs(ctx, teamID, tenantID)
}

// A store error while queuing the first run leaves the new tenant failed
// and retryable, not provisioning with nothing behind it.
func TestCreateTenantMarksFailedWhenQueueingAborts(t *testing.T) {
	f := newFixture(t)
	h := &Handlers{Store: &lockFailingStore{Memory: f.store}, Secrets: f.secrets, Trigger: f.trigger, Log: zerolog.Nop()}
	f.router = SetupRouter(h, ownerResolver(map[string]Principal{HashAPIKey(keyTeamA): {TeamID: f.teamA}}), zerolog.Nop())
	if code, _ := f.do(t, http.MethodPost, "/v1/qm/tenants", keyTeamA, validCreate()); code != http.StatusInternalServerError {
		t.Fatalf("status %d", code)
	}
	tenants, _ := f.store.ListTenants(context.Background(), f.teamA)
	if len(tenants) != 1 || tenants[0].Status != tenantstore.StatusFailed {
		t.Fatalf("tenants = %+v, want one failed", tenants)
	}
	if len(f.trigger.Calls) != 0 {
		t.Error("a run was triggered")
	}
}

// lockFailingStore reports a database error from Lock.
type lockFailingStore struct {
	*tenantstore.Memory
}

func (lockFailingStore) Lock(context.Context, uuid.UUID, uuid.UUID) (func(), error) {
	return nil, errors.New("database unavailable")
}
