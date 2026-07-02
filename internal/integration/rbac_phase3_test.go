//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/secrets"
)

var phase3TestSandboxAccessTokenSeed = []byte("0123456789abcdef0123456789abcdef")

func TestRbacPhase3SandboxMutationAuthorization(t *testing.T) {
	ownerTeamID, ownerKey := seedTeamAndKey(t)
	_, viewerKey, _ := seedTeamAndKeyWithRole(t, "viewer")
	_, userAdminKey, _ := seedTeamAndKeyWithRole(t, "user_admin")
	r := newTokenRouter(t)

	ownerResp := do(r, "POST", "/sandboxes", ownerKey, `{"name":"phase3-owner-sandbox"}`)
	if ownerResp.Code != 201 {
		t.Fatalf("expected team owner to create sandbox, got %d: %s", ownerResp.Code, ownerResp.Body.String())
	}

	var ownerSandbox map[string]any
	if err := json.Unmarshal(ownerResp.Body.Bytes(), &ownerSandbox); err != nil {
		t.Fatalf("decode owner sandbox response: %v", err)
	}
	sandboxID, ok := ownerSandbox["id"].(string)
	if !ok || sandboxID == "" {
		t.Fatalf("owner sandbox response missing id: %s", ownerResp.Body.String())
	}

	sameTeamViewerKey := seedKeyForExistingTeamWithRole(t, ownerTeamID, "viewer")
	viewerGetResp := do(r, "GET", "/sandboxes/"+sandboxID, sameTeamViewerKey, "")
	if viewerGetResp.Code != 200 {
		t.Fatalf("expected same-team viewer to read sandbox details, got %d: %s", viewerGetResp.Code, viewerGetResp.Body.String())
	}
	var viewerSandbox map[string]any
	if err := json.Unmarshal(viewerGetResp.Body.Bytes(), &viewerSandbox); err != nil {
		t.Fatalf("decode viewer sandbox response: %v", err)
	}
	if token, ok := viewerSandbox["access_token"]; ok && token != "" {
		t.Fatalf("expected same-team viewer sandbox details to omit access_token, got %v", token)
	}

	ownerGetResp := do(r, "GET", "/sandboxes/"+sandboxID, ownerKey, "")
	if ownerGetResp.Code != 200 {
		t.Fatalf("expected team owner to read sandbox details, got %d: %s", ownerGetResp.Code, ownerGetResp.Body.String())
	}
	var ownerGetSandbox map[string]any
	if err := json.Unmarshal(ownerGetResp.Body.Bytes(), &ownerGetSandbox); err != nil {
		t.Fatalf("decode owner sandbox get response: %v", err)
	}
	if token, _ := ownerGetSandbox["access_token"].(string); token == "" {
		t.Fatalf("expected team owner sandbox details to include access_token")
	}

	sameTeamUserAdminKey := seedKeyForExistingTeamWithRole(t, ownerTeamID, "user_admin")
	pauseResp := do(r, "POST", "/sandboxes/"+sandboxID+"/pause", sameTeamUserAdminKey, "")
	if pauseResp.Code != 403 {
		t.Fatalf("expected same-team user_admin sandbox pause to be forbidden, got %d: %s", pauseResp.Code, pauseResp.Body.String())
	}

	viewerResp := do(r, "POST", "/sandboxes", viewerKey, `{"name":"phase3-viewer-sandbox"}`)
	if viewerResp.Code != 403 {
		t.Fatalf("expected viewer sandbox create to be forbidden, got %d: %s", viewerResp.Code, viewerResp.Body.String())
	}

	userAdminResp := do(r, "POST", "/sandboxes", userAdminKey, `{"name":"phase3-user-admin-sandbox"}`)
	if userAdminResp.Code != 403 {
		t.Fatalf("expected user_admin sandbox create to be forbidden, got %d: %s", userAdminResp.Code, userAdminResp.Body.String())
	}

}

func TestRbacPhase3TemplateMutationAuthorization(t *testing.T) {
	_, ownerKey := seedTeamAndKey(t)
	_, viewerKey, _ := seedTeamAndKeyWithRole(t, "viewer")
	r := newRouter(t)

	name := "phase3-template-" + uuid.NewString()[:8]
	body := fmt.Sprintf(`{"name":%q,"build_spec":{"from":"debian:12-slim","steps":[]}}`, name)

	ownerResp := do(r, "POST", "/templates", ownerKey, body)
	if ownerResp.Code != 202 {
		t.Fatalf("expected team owner to create template, got %d: %s", ownerResp.Code, ownerResp.Body.String())
	}

	viewerResp := do(r, "POST", "/templates", viewerKey, body)
	if viewerResp.Code != 403 {
		t.Fatalf("expected viewer template create to be forbidden, got %d: %s", viewerResp.Code, viewerResp.Body.String())
	}
}

func TestRbacPhase3SecretMutationAuthorization(t *testing.T) {
	_, ownerKey := seedTeamAndKey(t)
	_, viewerKey, _ := seedTeamAndKeyWithRole(t, "viewer")
	r := newSecretRouter(t)

	body := `{"name":"phase3_secret","provider":"openai","value":"sk-proj-test-value"}`

	ownerResp := do(r, "POST", "/secrets", ownerKey, body)
	if ownerResp.Code != 201 {
		t.Fatalf("expected team owner to create secret, got %d: %s", ownerResp.Code, ownerResp.Body.String())
	}

	viewerResp := do(r, "POST", "/secrets", viewerKey, body)
	if viewerResp.Code != 403 {
		t.Fatalf("expected viewer secret create to be forbidden, got %d: %s", viewerResp.Code, viewerResp.Body.String())
	}
}

func newTokenRouter(t *testing.T) *gin.Engine {
	t.Helper()
	cfg := &config.Config{
		Port:                   "0",
		VMDAddress:             "localhost:0",
		SystemTeamID:           testSystemTeamID.String(),
		SandboxAccessTokenSeed: phase3TestSandboxAccessTokenSeed,
	}
	h := api.NewHandlers(&stubVMD{}, testQueries, cfg)
	h.Pool = testPool
	registerTestHandlers(h)
	return api.SetupRouter(t.Context(), h, testPool)
}

func newSecretRouter(t *testing.T) *gin.Engine {
	t.Helper()
	cfg := &config.Config{
		Port:         "0",
		VMDAddress:   "localhost:0",
		SystemTeamID: testSystemTeamID.String(),
	}
	h := api.NewHandlers(&stubVMD{}, testQueries, cfg)
	h.Pool = testPool
	h.Encryptor = stubEncryptor{}
	registerTestHandlers(h)
	return api.SetupRouter(t.Context(), h, testPool)
}

type stubEncryptor struct{}

func (stubEncryptor) Encrypt(_ context.Context, plaintext []byte) (secrets.Encrypted, error) {
	return secrets.Encrypted{
		Ciphertext:   append([]byte("cipher-"), plaintext...),
		EncryptedDEK: []byte("wrapped-dek"),
		KEKID:        "fake://kek/v1",
	}, nil
}

func (stubEncryptor) Decrypt(_ context.Context, enc secrets.Encrypted) ([]byte, error) {
	return enc.Ciphertext, nil
}
