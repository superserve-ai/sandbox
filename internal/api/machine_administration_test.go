package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/getsentry/sentry-go"
	sentrygin "github.com/getsentry/sentry-go/gin"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/auth"
	"github.com/superserve-ai/sandbox/internal/db"
)

type machineAdminFixture struct {
	calls                                                                 []string
	principalID, teamID, tenantID, templateID, operationID, replacementID uuid.UUID
	generation                                                            int64
	material                                                              string
	err                                                                   error
}

func (f *machineAdminFixture) called(ctx context.Context, name string) error {
	if !authorizedControlPlane(ctx) {
		return errors.New("missing operator authorization")
	}
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("missing bounded operation deadline")
	}
	f.calls = append(f.calls, name)
	return f.err
}
func (f *machineAdminFixture) ResolveMachineCredential(context.Context, string) (auth.CallerContext, error) {
	return auth.CallerContext{}, errors.New("runtime authentication must not be used")
}
func (f *machineAdminFixture) EnsurePrincipal(ctx context.Context, team, tenant, template uuid.UUID, _ string) (auth.MachinePrincipal, error) {
	f.teamID, f.tenantID, f.templateID = team, tenant, template
	return auth.MachinePrincipal{PrincipalID: uuid.New(), TeamID: team, HostedTenantID: tenant, Generation: 1, Status: auth.PrincipalActive}, f.called(ctx, "ensure")
}
func (f *machineAdminFixture) ReadPrincipal(ctx context.Context, principal uuid.UUID) (auth.MachinePrincipal, error) {
	f.principalID = principal
	return auth.MachinePrincipal{PrincipalID: principal, Generation: 7, Status: auth.PrincipalActive}, f.called(ctx, "read")
}
func (f *machineAdminFixture) mutate(ctx context.Context, action string, principal uuid.UUID, material string, generation int64, operation uuid.UUID) (auth.MachineCredential, error) {
	f.principalID, f.material, f.generation, f.operationID = principal, material, generation, operation
	return auth.MachineCredential{CredentialID: uuid.New(), PrincipalID: principal, LineageID: uuid.New(), State: auth.CredentialActive, ExpiresAt: time.Now().Add(time.Hour), RevocationGeneration: uint64(generation)}, f.called(ctx, action)
}
func (f *machineAdminFixture) IssueCredentialFenced(ctx context.Context, principal uuid.UUID, material string, generation int64, operation uuid.UUID) (auth.MachineCredential, error) {
	return f.mutate(ctx, "issue", principal, material, generation, operation)
}
func (f *machineAdminFixture) RotateCredentialFenced(ctx context.Context, principal, replacement uuid.UUID, material string, generation int64, operation uuid.UUID) (auth.MachineCredential, error) {
	f.replacementID = replacement
	return f.mutate(ctx, "rotate", principal, material, generation, operation)
}
func (f *machineAdminFixture) RestorePrincipalFenced(ctx context.Context, principal uuid.UUID, material string, generation int64, operation uuid.UUID) (auth.MachineCredential, error) {
	return f.mutate(ctx, "restore", principal, material, generation, operation)
}
func (f *machineAdminFixture) RevokeCredential(ctx context.Context, credential uuid.UUID, _ string) error {
	f.replacementID = credential
	return f.called(ctx, "revoke")
}
func (f *machineAdminFixture) DisablePrincipalFenced(ctx context.Context, principal uuid.UUID, generation int64, operation uuid.UUID) error {
	f.principalID, f.generation, f.operationID = principal, generation, operation
	return f.called(ctx, "disable")
}

func machineAdminRouter(t *testing.T, resolver MachineCredentialResolver) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	t.Setenv("OPERATOR_API_TOKEN", "test-operator-only")
	t.Setenv("INTERNAL_API_TOKEN", "test-infrastructure-only")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return SetupRouter(ctx, &Handlers{MachineCredentials: resolver}, nil)
}

func machineAdminRequest(router http.Handler, method, path, body, token string, machineHeader bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if machineHeader {
		req.Header.Set("X-QM-Machine-Credential", "")
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	return response
}

func TestMachineAdministrationOperatorBoundary(t *testing.T) {
	fixture := &machineAdminFixture{}
	router := machineAdminRouter(t, fixture)
	id := uuid.New().String()
	routes := []struct{ method, path string }{
		{"POST", "/principals"}, {"GET", "/principals/" + id},
		{"POST", "/principals/" + id + "/credentials/issue"}, {"POST", "/principals/" + id + "/credentials/rotate"},
		{"POST", "/principals/" + id + "/credentials/restore"}, {"POST", "/principals/" + id + "/disable"},
		{"POST", "/credentials/" + id + "/revoke"},
	}
	for _, route := range routes {
		for _, token := range []string{"", "test-infrastructure-only", "test-runtime-key"} {
			response := machineAdminRequest(router, route.method, "/internal/machine-identity"+route.path, `{}`, token, false)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("%s: token %q got %d", route.path, token, response.Code)
			}
		}
		response := machineAdminRequest(router, route.method, "/internal/machine-identity"+route.path, `{}`, "test-operator-only", true)
		if response.Code != http.StatusForbidden {
			t.Fatalf("mixed machine/operator %s got %d", route.path, response.Code)
		}
	}
	if len(fixture.calls) != 0 {
		t.Fatalf("unauthorized calls reached authority: %v", fixture.calls)
	}
}

func TestMachineAdministrationDispatchAndSecretSafety(t *testing.T) {
	fixture := &machineAdminFixture{}
	router := machineAdminRouter(t, fixture)
	principal, team, tenant, template, operation, replacement := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	material := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdefghijklmnopqrstuv"))
	if len([]byte("0123456789abcdefghijklmnopqrstuv")) != 32 {
		t.Fatal("test fixture length")
	}
	ensure, _ := json.Marshal(map[string]any{"team_id": team, "hosted_tenant_id": tenant, "approved_template_id": template})
	response := machineAdminRequest(router, "POST", "/internal/machine-identity/principals", string(ensure), "test-operator-only", false)
	if response.Code != http.StatusOK || fixture.teamID != team || fixture.tenantID != tenant || fixture.templateID != template {
		t.Fatalf("ensure dispatch: %d %s", response.Code, response.Body)
	}
	path := "/internal/machine-identity/principals/" + principal.String()
	response = machineAdminRequest(router, "GET", path, "", "test-operator-only", false)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"generation":7`) {
		t.Fatalf("read fence: %d %s", response.Code, response.Body)
	}
	for _, action := range []string{"issue", "rotate", "restore"} {
		request := machineCredentialRequest{OperationID: operation, ExpectedGeneration: 7, CredentialMaterial: material}
		if action == "rotate" {
			request.ReplacementCredentialID = replacement
		}
		body, _ := json.Marshal(request)
		response = machineAdminRequest(router, "POST", path+"/credentials/"+action, string(body), "test-operator-only", false)
		if response.Code != http.StatusOK || fixture.calls[len(fixture.calls)-1] != action || fixture.principalID != principal || fixture.operationID != operation || fixture.generation != 7 || fixture.material != material {
			t.Fatalf("%s dispatch: %d %s", action, response.Code, response.Body)
		}
		if strings.Contains(response.Body.String(), material) || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("credential material exposed or response cacheable")
		}
	}
	if fixture.replacementID != replacement {
		t.Fatal("rotation target lost")
	}
	disableOperation := uuid.New()
	disableBody, _ := json.Marshal(map[string]any{"operation_id": disableOperation, "expected_generation": 9})
	response = machineAdminRequest(router, "POST", path+"/disable", string(disableBody), "test-operator-only", false)
	if response.Code != http.StatusNoContent || fixture.calls[len(fixture.calls)-1] != "disable" || fixture.principalID != principal || fixture.operationID != disableOperation || fixture.generation != 9 {
		t.Fatal("disable not dispatched")
	}
	response = machineAdminRequest(router, "POST", "/internal/machine-identity/credentials/"+replacement.String()+"/revoke", "", "test-operator-only", false)
	if response.Code != http.StatusNoContent || fixture.calls[len(fixture.calls)-1] != "revoke" {
		t.Fatal("revoke not dispatched")
	}
	fixture.err = errors.New("database failure with secret: " + material)
	response = machineAdminRequest(router, "POST", path+"/disable", string(disableBody), "test-operator-only", false)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), material) {
		t.Fatal("unsafe database error response")
	}
}

func TestMachineAdministrationRejectsInvalidRequests(t *testing.T) {
	fixture := &machineAdminFixture{}
	router := machineAdminRouter(t, fixture)
	path := "/internal/machine-identity/principals/" + uuid.New().String() + "/credentials/issue"
	valid := machineCredentialRequest{OperationID: uuid.New(), ExpectedGeneration: 1, CredentialMaterial: base64.RawURLEncoding.EncodeToString(make([]byte, 32))}
	body, _ := json.Marshal(valid)
	invalid := []string{`{}`, `null`, string(body) + ` {}`, strings.TrimSuffix(string(body), "}") + `,"permissions":["admin"]}`, strings.Repeat(" ", machineAdministrationBodyLimit) + string(body)}
	for _, mutate := range []func(*machineCredentialRequest){
		func(r *machineCredentialRequest) { r.CredentialMaterial = "short" },
		func(r *machineCredentialRequest) { r.ExpectedGeneration = 0 },
		func(r *machineCredentialRequest) { r.OperationID = uuid.Nil },
		func(r *machineCredentialRequest) { r.ReplacementCredentialID = uuid.New() },
	} {
		copy := valid
		mutate(&copy)
		encoded, _ := json.Marshal(copy)
		invalid = append(invalid, string(encoded))
	}
	for _, body := range invalid {
		response := machineAdminRequest(router, "POST", path, body, "test-operator-only", false)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid request got %d", response.Code)
		}
	}
	response := machineAdminRequest(router, "POST", strings.Replace(path, "/issue", "/rotate", 1), string(body), "test-operator-only", false)
	if response.Code != http.StatusBadRequest {
		t.Fatal("rotation without replacement accepted")
	}
	if len(fixture.calls) != 0 {
		t.Fatalf("invalid requests reached authority: %v", fixture.calls)
	}
}

func TestMachineAdministrationUnconfiguredFailsClosed(t *testing.T) {
	for _, resolver := range []MachineCredentialResolver{nil, (*DBMachineAuthority)(nil), NewDBMachineAuthority(nil)} {
		router := machineAdminRouter(t, resolver)
		response := machineAdminRequest(router, "POST", "/internal/machine-identity/principals/"+uuid.New().String()+"/disable", "", "test-operator-only", false)
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("unconfigured authority got %d", response.Code)
		}
	}
}

func TestMachineAdministrationPrivateDiagnostics(t *testing.T) {
	var output bytes.Buffer
	previous := log.Logger
	log.Logger = zerolog.New(&output)
	defer func() { log.Logger = previous }()
	var captured *sentry.Event
	client, err := sentry.NewClient(sentry.ClientOptions{Dsn: "https://example@example.com/1", BeforeSend: func(event *sentry.Event, _ *sentry.EventHint) *sentry.Event { captured = event; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(sentry.SetHubOnContext(c.Request.Context(), sentry.NewHub(client, sentry.NewScope())))
	}, RequestLogger(), ErrorHandler(), sentrygin.New(sentrygin.Options{Repanic: true}), machineAdministrationPrivacy())
	router.POST("/internal/machine-identity/principals", func(c *gin.Context) { data, _ := io.ReadAll(c.Request.Body); panic(string(data)) })
	secret := uuid.NewString()
	request := httptest.NewRequest("POST", "/internal/machine-identity/principals?credential_material="+secret, strings.NewReader(`{"credential_material":"`+secret+`"}`))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError || captured == nil {
		t.Fatal("panic not reported")
	}
	eventJSON, err := json.Marshal(captured)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), secret) || bytes.Contains(eventJSON, []byte(secret)) {
		t.Fatal("diagnostics exposed credential material")
	}
}

func TestMachineAdministrationBoundsRejectedBodyReads(t *testing.T) {
	router := machineAdminRouter(t, &machineAdminFixture{})
	writer := &deadlineTeamWriter{ResponseRecorder: httptest.NewRecorder()}
	request := httptest.NewRequest("POST", "/internal/machine-identity/principals", nil)
	request.Body = &deadlineTeamBody{writer: writer}
	router.ServeHTTP(writer, request)
	if writer.Code != http.StatusUnauthorized || len(writer.deadlines) != 1 || time.Until(writer.deadlines[0]) > 5*time.Second {
		t.Fatal("rejected request lacks bounded socket read deadline")
	}
}

func TestMachineAdministrationDisableRequiresFence(t *testing.T) {
	fixture := &machineAdminFixture{}
	router := machineAdminRouter(t, fixture)
	path := "/internal/machine-identity/principals/" + uuid.NewString() + "/disable"
	operation := uuid.NewString()
	for _, body := range []string{"", "null", "{}", `{"expected_generation":1}`, `{"operation_id":"` + operation + `"}`, `{"operation_id":"` + operation + `","expected_generation":0}`, `{"operation_id":"` + operation + `","expected_generation":-1}`, `{"operation_id":"` + operation + `","expected_generation":1,"credential_material":"unexpected"}`} {
		response := machineAdminRequest(router, "POST", path, body, "test-operator-only", false)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid disable fence got %d", response.Code)
		}
	}
	if len(fixture.calls) != 0 {
		t.Fatal("unfenced disable reached authority")
	}
	for _, failure := range []error{db.ErrMachineLifecycleConflict, pgx.ErrNoRows} {
		fixture.err = failure
		response := machineAdminRequest(router, "POST", path, `{"operation_id":"`+operation+`","expected_generation":1}`, "test-operator-only", false)
		if response.Code != http.StatusConflict {
			t.Fatalf("disable fence conflict got %d", response.Code)
		}
	}
}
