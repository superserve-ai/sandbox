//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/db"
)

func TestConsoleImpersonation_NormalCustomerKeysStillUseRBAC(t *testing.T) {
	teamID, ownerKey := seedTeamAndKey(t)
	viewerKey := seedKeyForExistingTeamWithRole(t, teamID, "viewer")
	r := newTokenRouter(t)

	createResp := do(r, "POST", "/sandboxes", ownerKey, `{"name":"rbac-sandbox"}`)
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create sandbox: expected 201, got %d: %s", createResp.Code, createResp.Body.String())
	}
	sandboxID := mustJSON(t, createResp)["id"].(string)

	listResp := do(r, "GET", "/sandboxes", viewerKey, "")
	if listResp.Code != http.StatusOK {
		t.Fatalf("viewer list sandboxes: expected 200, got %d: %s", listResp.Code, listResp.Body.String())
	}

	getResp := do(r, "GET", "/sandboxes/"+sandboxID, viewerKey, "")
	if getResp.Code != http.StatusOK {
		t.Fatalf("viewer get sandbox: expected 200, got %d: %s", getResp.Code, getResp.Body.String())
	}
	if token, ok := mustJSON(t, getResp)["access_token"]; ok && token != "" {
		t.Fatalf("viewer sandbox response should not include access_token, got %v", token)
	}
}

func TestConsoleImpersonation_SandboxReadScope(t *testing.T) {
	teamID, _ := seedTeamAndKey(t)
	r := newTokenRouter(t)

	sandboxID := insertSandboxAt(t, teamID, "impersonation-sandbox", "active", time.Now())

	allowedKey := seedConsoleImpersonationKey(t, teamID, []string{"platform:sandbox:read"}, nil)
	listResp := do(r, "GET", "/sandboxes", allowedKey, "")
	if listResp.Code != http.StatusOK {
		t.Fatalf("scoped sandbox list: expected 200, got %d: %s", listResp.Code, listResp.Body.String())
	}
	rows := decodeArray(t, listResp)
	if len(rows) != 1 || rows[0]["id"] != sandboxID.String() {
		t.Fatalf("sandbox list = %v, want single sandbox %s", rows, sandboxID)
	}

	getResp := do(r, "GET", "/sandboxes/"+sandboxID.String(), allowedKey, "")
	if getResp.Code != http.StatusOK {
		t.Fatalf("scoped sandbox get: expected 200, got %d: %s", getResp.Code, getResp.Body.String())
	}
	body := mustJSON(t, getResp)
	if body["id"] != sandboxID.String() {
		t.Fatalf("sandbox id = %v, want %s", body["id"], sandboxID)
	}
	if token, ok := body["access_token"]; ok && token != "" {
		t.Fatalf("impersonation sandbox response should not include access_token, got %v", token)
	}
	if _, ok := body["secrets"]; ok {
		t.Fatalf("impersonation sandbox response should omit secrets, got %v", body["secrets"])
	}

	deniedKey := seedConsoleImpersonationKey(t, teamID, nil, nil)
	deniedResp := do(r, "GET", "/sandboxes", deniedKey, "")
	if deniedResp.Code != http.StatusForbidden {
		t.Fatalf("unscoped sandbox list: expected 403, got %d: %s", deniedResp.Code, deniedResp.Body.String())
	}
}

func TestConsoleImpersonation_TemplateReadScope(t *testing.T) {
	teamID, _ := seedTeamAndKey(t)
	r := newRouter(t)

	templateID := insertTemplateAt(t, teamID, "impersonation-template", time.Now())

	allowedKey := seedConsoleImpersonationKey(t, teamID, []string{"platform:template:read"}, nil)
	listResp := do(r, "GET", "/templates?owner=team", allowedKey, "")
	if listResp.Code != http.StatusOK {
		t.Fatalf("scoped template list: expected 200, got %d: %s", listResp.Code, listResp.Body.String())
	}
	rows := decodeArray(t, listResp)
	if len(rows) != 1 || rows[0]["id"] != templateID.String() {
		t.Fatalf("template list = %v, want single template %s", rows, templateID)
	}

	getResp := do(r, "GET", "/templates/"+templateID.String(), allowedKey, "")
	if getResp.Code != http.StatusOK {
		t.Fatalf("scoped template get: expected 200, got %d: %s", getResp.Code, getResp.Body.String())
	}
	if got := mustJSON(t, getResp)["id"]; got != templateID.String() {
		t.Fatalf("template id = %v, want %s", got, templateID)
	}

	deniedKey := seedConsoleImpersonationKey(t, teamID, nil, nil)
	deniedResp := do(r, "GET", "/templates?owner=team", deniedKey, "")
	if deniedResp.Code != http.StatusForbidden {
		t.Fatalf("unscoped template list: expected 403, got %d: %s", deniedResp.Code, deniedResp.Body.String())
	}
}

func TestConsoleImpersonation_ActivityReadScope(t *testing.T) {
	teamID, _ := seedTeamAndKey(t)
	otherTeamID, _ := seedTeamAndKey(t)
	r := newTokenRouter(t)

	now := time.Now()
	insertSecretActivity(t, teamID, "target-team-event", "target-secret", now)
	insertSecretActivity(t, otherTeamID, "other-team-event", "other-secret", now.Add(time.Second))

	allowedKey := seedConsoleImpersonationKey(t, teamID, []string{"platform:activity:read"}, nil)
	resp := do(r, http.MethodGet, "/activity", allowedKey, "")
	if resp.Code != http.StatusOK {
		t.Fatalf("scoped activity list: expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	rows := decodeArray(t, resp)
	if len(rows) != 1 || rows[0]["action"] != "target-team-event" {
		t.Fatalf("activity list = %v, want only the target team's event", rows)
	}

	deniedKey := seedConsoleImpersonationKey(t, teamID, []string{"platform:sandbox:read"}, nil)
	deniedResp := do(r, http.MethodGet, "/activity", deniedKey, "")
	if deniedResp.Code != http.StatusForbidden {
		t.Fatalf("activity without scope: expected 403, got %d: %s", deniedResp.Code, deniedResp.Body.String())
	}
}

func TestConsoleImpersonation_CannotMutateSandboxes(t *testing.T) {
	teamID, ownerKey := seedTeamAndKey(t)
	r := newTokenRouter(t)

	createResp := do(r, "POST", "/sandboxes", ownerKey, `{"name":"mutate-target"}`)
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create sandbox: expected 201, got %d: %s", createResp.Code, createResp.Body.String())
	}
	sandboxID := mustJSON(t, createResp)["id"].(string)
	impersonationKey := seedConsoleImpersonationKey(t, teamID, []string{"platform:sandbox:read"}, nil)

	cases := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{name: "create", method: http.MethodPost, path: "/sandboxes", body: `{"name":"forbidden"}`},
		{name: "patch", method: http.MethodPatch, path: "/sandboxes/" + sandboxID, body: `{"metadata":{"env":"prod"}}`},
		{name: "delete", method: http.MethodDelete, path: "/sandboxes/" + sandboxID},
		{name: "pause", method: http.MethodPost, path: "/sandboxes/" + sandboxID + "/pause"},
		{name: "resume", method: http.MethodPost, path: "/sandboxes/" + sandboxID + "/resume"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := do(r, tc.method, tc.path, impersonationKey, tc.body)
			if resp.Code != http.StatusForbidden {
				t.Fatalf("%s: expected 403, got %d: %s", tc.name, resp.Code, resp.Body.String())
			}
		})
	}
}

func TestConsoleImpersonation_CannotAccessNonSandboxReadEndpoints(t *testing.T) {
	teamID, _ := seedTeamAndKey(t)
	r := newTokenRouter(t)

	sandboxID := insertSandboxAt(t, teamID, "files-target", "active", time.Now())
	impersonationKey := seedConsoleImpersonationKey(t, teamID, []string{"platform:sandbox:read"}, nil)

	cases := []struct {
		name   string
		method string
		path   string
	}{
		{name: "files", method: http.MethodGet, path: "/sandboxes/" + sandboxID.String() + "/files?path=/"},
		{name: "network", method: http.MethodGet, path: "/sandboxes/" + sandboxID.String() + "/network"},
		{name: "secrets", method: http.MethodGet, path: "/secrets"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := do(r, tc.method, tc.path, impersonationKey, "")
			if resp.Code != http.StatusForbidden {
				t.Fatalf("%s: expected 403, got %d: %s", tc.name, resp.Code, resp.Body.String())
			}
		})
	}
}

func TestConsoleImpersonation_CannotMutateTemplates(t *testing.T) {
	teamID, _ := seedTeamAndKey(t)
	r := newRouter(t)

	templateID := insertTemplateAt(t, teamID, "template-target", time.Now())
	buildID := uuid.New()
	impersonationKey := seedConsoleImpersonationKey(t, teamID, []string{"platform:template:read"}, nil)

	cases := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{
			name:   "create template",
			method: http.MethodPost,
			path:   "/templates",
			body:   `{"name":"forbidden-template","build_spec":{"from":"debian:12-slim","steps":[]}}`,
		},
		{name: "create build", method: http.MethodPost, path: "/templates/" + templateID.String() + "/builds"},
		{name: "delete template", method: http.MethodDelete, path: "/templates/" + templateID.String()},
		{name: "cancel build", method: http.MethodDelete, path: "/templates/" + templateID.String() + "/builds/" + buildID.String()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := do(r, tc.method, tc.path, impersonationKey, tc.body)
			if resp.Code != http.StatusForbidden {
				t.Fatalf("%s: expected 403, got %d: %s", tc.name, resp.Code, resp.Body.String())
			}
		})
	}
}

func TestConsoleImpersonation_ExpiredAndRevokedKeysFailAuth(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedTeamAndKey(t)
	r := newRouter(t)

	expiredAt := time.Now().Add(-1 * time.Minute)
	expiredKey := seedConsoleImpersonationKey(t, teamID, []string{"platform:sandbox:read"}, &expiredAt)
	expiredResp := do(r, "GET", "/sandboxes", expiredKey, "")
	if expiredResp.Code != http.StatusUnauthorized {
		t.Fatalf("expired key: expected 401, got %d: %s", expiredResp.Code, expiredResp.Body.String())
	}

	revokedKey := seedConsoleImpersonationKey(t, teamID, []string{"platform:sandbox:read"}, nil)
	hash := sha256.Sum256([]byte(revokedKey))
	keyHash := hex.EncodeToString(hash[:])
	rec, err := testQueries.GetAPIKeyByHashV2(ctx, keyHash)
	if err != nil {
		t.Fatalf("lookup impersonation key: %v", err)
	}
	if err := testQueries.RevokeAPIKeyV2(ctx, rec.ID); err != nil {
		t.Fatalf("revoke impersonation key: %v", err)
	}

	revokedResp := do(r, "GET", "/sandboxes", revokedKey, "")
	if revokedResp.Code != http.StatusUnauthorized {
		t.Fatalf("revoked key: expected 401, got %d: %s", revokedResp.Code, revokedResp.Body.String())
	}
}

func TestConsoleImpersonation_ScopeIsNarrow(t *testing.T) {
	teamID, _ := seedTeamAndKey(t)
	r := newRouter(t)

	insertSandboxAt(t, teamID, "narrow-sandbox", "active", time.Now())
	insertTemplateAt(t, teamID, "narrow-template", time.Now())

	templateOnlyKey := seedConsoleImpersonationKey(t, teamID, []string{"platform:template:read"}, nil)
	if resp := do(r, "GET", "/sandboxes", templateOnlyKey, ""); resp.Code != http.StatusForbidden {
		t.Fatalf("template-only key listing sandboxes: expected 403, got %d: %s", resp.Code, resp.Body.String())
	}

	sandboxOnlyKey := seedConsoleImpersonationKey(t, teamID, []string{"platform:sandbox:read"}, nil)
	if resp := do(r, "GET", "/templates?owner=team", sandboxOnlyKey, ""); resp.Code != http.StatusForbidden {
		t.Fatalf("sandbox-only key listing templates: expected 403, got %d: %s", resp.Code, resp.Body.String())
	}

	activityOnlyKey := seedConsoleImpersonationKey(t, teamID, []string{"platform:activity:read"}, nil)
	if resp := do(r, "GET", "/sandboxes", activityOnlyKey, ""); resp.Code != http.StatusForbidden {
		t.Fatalf("activity-only key listing sandboxes: expected 403, got %d: %s", resp.Code, resp.Body.String())
	}
	if resp := do(r, "GET", "/templates?owner=team", activityOnlyKey, ""); resp.Code != http.StatusForbidden {
		t.Fatalf("activity-only key listing templates: expected 403, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestConsoleImpersonation_TemplateBuildReadsAllowed(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedTeamAndKey(t)
	r := newRouter(t)

	templateID := insertTemplateAt(t, teamID, "build-read-template", time.Now())
	buildID := uuid.New()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO template_build (id, template_id, team_id, status, build_spec_hash)
		VALUES ($1, $2, $3, 'ready', $4)
	`, buildID, templateID, teamID, []byte("hash")); err != nil {
		t.Fatalf("insert template_build: %v", err)
	}

	impersonationKey := seedConsoleImpersonationKey(t, teamID, []string{"platform:template:read"}, nil)
	if resp := do(r, "GET", "/templates/"+templateID.String()+"/builds", impersonationKey, ""); resp.Code != http.StatusOK {
		t.Fatalf("list builds: expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if resp := do(r, "GET", "/templates/"+templateID.String()+"/builds/"+buildID.String(), impersonationKey, ""); resp.Code != http.StatusOK {
		t.Fatalf("get build: expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestConsoleImpersonation_SandboxReadResponsesRemainScoped(t *testing.T) {
	teamID, ownerKey := seedTeamAndKey(t)
	r := newTokenRouter(t)

	createResp := do(r, "POST", "/sandboxes", ownerKey, `{"name":"scoped-response"}`)
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create sandbox: expected 201, got %d: %s", createResp.Code, createResp.Body.String())
	}
	sandboxID := mustJSON(t, createResp)["id"].(string)

	impersonationKey := seedConsoleImpersonationKey(t, teamID, []string{"platform:sandbox:read"}, nil)
	resp := do(r, "GET", "/sandboxes/"+sandboxID, impersonationKey, "")
	if resp.Code != http.StatusOK {
		t.Fatalf("get sandbox: expected 200, got %d: %s", resp.Code, resp.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode sandbox response: %v", err)
	}
	if _, ok := body["access_token"]; ok {
		t.Fatalf("impersonation sandbox response must omit access_token: %v", body)
	}
}

func TestConsoleImpersonation_AuthMessageStaysGeneric(t *testing.T) {
	teamID, _ := seedTeamAndKey(t)
	r := newRouter(t)

	expiredAt := time.Now().Add(-1 * time.Minute)
	key := seedConsoleImpersonationKey(t, teamID, []string{"platform:sandbox:read"}, &expiredAt)
	resp := do(r, "GET", "/sandboxes", key, "")
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expired key: expected 401, got %d: %s", resp.Code, resp.Body.String())
	}
	errObj := mustJSON(t, resp)["error"].(map[string]any)
	if errObj["code"] != "auth_failed" {
		t.Fatalf("error code = %v, want auth_failed", errObj["code"])
	}
}

func TestConsoleImpersonation_TemporaryKeyNameOnly(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedTeamAndKey(t)
	r := newRouter(t)

	rawKey := "sk-test-" + uuid.New().String()
	hash := sha256.Sum256([]byte(rawKey))
	keyHash := hex.EncodeToString(hash[:])
	if _, err := testQueries.CreateAPIKeyV2(ctx, db.CreateAPIKeyV2Params{
		TeamID:  teamID,
		KeyHash: keyHash,
		Name:    "not-console-impersonation",
		Scopes:  []string{"platform:sandbox:read", "platform:template:read", "platform:activity:read"},
	}); err != nil {
		t.Fatalf("create non-impersonation key: %v", err)
	}

	if resp := do(r, "GET", "/sandboxes", rawKey, ""); resp.Code != http.StatusForbidden {
		t.Fatalf("non-impersonation key with scopes listing sandboxes: expected 403, got %d: %s", resp.Code, resp.Body.String())
	}
	if resp := do(r, "GET", "/templates?owner=team", rawKey, ""); resp.Code != http.StatusForbidden {
		t.Fatalf("non-impersonation key with scopes listing templates: expected 403, got %d: %s", resp.Code, resp.Body.String())
	}
	if resp := do(r, "GET", "/activity", rawKey, ""); resp.Code != http.StatusForbidden {
		t.Fatalf("non-impersonation key with scopes listing activity: expected 403, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestConsoleImpersonation_DoesNotBypassTemplateMutationsWithSandboxScope(t *testing.T) {
	teamID, _ := seedTeamAndKey(t)
	r := newRouter(t)

	templateID := insertTemplateAt(t, teamID, "mixed-scope-template", time.Now())
	key := seedConsoleImpersonationKey(t, teamID, []string{"platform:sandbox:read"}, nil)

	resp := do(r, http.MethodDelete, "/templates/"+templateID.String(), key, "")
	if resp.Code != http.StatusForbidden {
		t.Fatalf("sandbox-read key deleting template: expected 403, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestConsoleImpersonation_DoesNotBypassSandboxMutationsWithTemplateScope(t *testing.T) {
	teamID, _ := seedTeamAndKey(t)
	r := newRouter(t)

	sandboxID := insertSandboxAt(t, teamID, "mixed-scope-sandbox", "active", time.Now())
	key := seedConsoleImpersonationKey(t, teamID, []string{"platform:template:read"}, nil)

	resp := do(r, http.MethodDelete, "/sandboxes/"+sandboxID.String(), key, "")
	if resp.Code != http.StatusForbidden {
		t.Fatalf("template-read key deleting sandbox: expected 403, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestConsoleImpersonation_DoesNotNeedTeamMembershipForAllowedReads(t *testing.T) {
	ctx := context.Background()
	teamID := mustCreateTeam(t, ctx, "impersonation-no-membership-"+uuid.NewString()[:8])
	r := newRouter(t)

	templateID := insertTemplateAt(t, teamID, "membershipless-template", time.Now())
	key := seedConsoleImpersonationKey(t, teamID, []string{"platform:template:read"}, nil)

	resp := do(r, "GET", "/templates/"+templateID.String(), key, "")
	if resp.Code != http.StatusOK {
		t.Fatalf("membershipless impersonation template read: expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestConsoleImpersonation_DoesNotGrantSystemTemplateWrites(t *testing.T) {
	teamID, _ := seedTeamAndKey(t)
	r := newRouter(t)

	key := seedConsoleImpersonationKey(t, teamID, []string{"platform:template:read"}, nil)
	resp := do(r, http.MethodPost, "/templates", key, fmt.Sprintf(`{"name":%q,"build_spec":{"from":"debian:12-slim","steps":[]}}`, "forbidden-system-write"))
	if resp.Code != http.StatusForbidden {
		t.Fatalf("template read key creating template: expected 403, got %d: %s", resp.Code, resp.Body.String())
	}
}
