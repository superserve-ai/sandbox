package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/config"
)

func signTeamCreationTestAssertion(t *testing.T, payload any, private ed25519.PrivateKey) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"team-creation+jwt","kid":"test"}`))
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(body)
	message := header + "." + encoded
	return message + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(message)))
}

func TestTeamCreationAssertionAuthority(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	keys := map[string]ed25519.PublicKey{"test": public}
	now := time.Unix(1_800_000_000, 0)
	base := map[string]any{
		"v": 1, "iss": "superserve-console", "aud": "superserve-team-creation", "purpose": "team-creation",
		"sub": "53ae930d-e4bd-478a-b64f-82f2b0d7e8e6", "iat": now.Unix(), "exp": now.Unix() + 120,
		"request_id": "42140b1e-ac77-4ab0-9841-d9099ae8265a", "name": "Café ☃", "region": "use", "authorization": "create",
		"policy":   map[string]any{"version": 1, "mode": "first_team", "session": "passed", "captcha": "passed", "preauth": "passed", "google_onboarding": "passed", "additional_team": "not_applicable"},
		"identity": map[string]any{"email": "user@example.com", "email_verified": true},
	}
	valid := signTeamCreationTestAssertion(t, base, private)
	claims, err := verifyTeamCreationAssertion(valid, keys, now)
	if err != nil || claims.Name != "Café ☃" {
		t.Fatalf("valid assertion: %+v %v", claims, err)
	}
	if _, err := verifyTeamCreationAssertion(valid, nil, now); !errors.Is(err, errInvalidTeamAssertion) {
		t.Fatalf("unknown kid: %v", err)
	}
	if _, err := verifyTeamCreationAssertion(valid+"x", keys, now); !errors.Is(err, errInvalidTeamAssertion) {
		t.Fatalf("tampered signature: %v", err)
	}
	if _, err := verifyTeamCreationAssertion(valid, keys, now.Add(151*time.Second)); !errors.Is(err, errExpiredTeamAssertion) {
		t.Fatalf("expired: %v", err)
	}
	base["policy"].(map[string]any)["preauth"] = "failed"
	if _, err := verifyTeamCreationAssertion(signTeamCreationTestAssertion(t, base, private), keys, now); !errors.Is(err, errTeamPolicy) {
		t.Fatalf("policy: %v", err)
	}
	delete(base, "policy")
	delete(base, "identity")
	base["authorization"] = "recover"
	claims, err = verifyTeamCreationAssertion(signTeamCreationTestAssertion(t, base, private), keys, now)
	if err != nil || claims.Authorization != "recover" {
		t.Fatalf("recovery assertion: %v", err)
	}
}

func TestTeamCreationStrictInput(t *testing.T) {
	for _, raw := range []string{
		`{"request_id":"a","request_id":"b","name":"x","region":"use"}`,
		`{"request_id":"a","name":"x","region":"use","other":1}`,
		`{"request_id":"a","name":9,"region":"use"}`,
	} {
		var input teamCreationInput
		if err := decodeUniqueJSON([]byte(raw), &input); err == nil {
			t.Errorf("accepted invalid JSON: %s", raw)
		}
	}
	if trimECMAScript("\uFEFF Café ☃ \u00a0") != "Café ☃" {
		t.Fatal("ECMAScript whitespace not trimmed")
	}
	if trimECMAScript("Ca fé") != "Ca fé" {
		t.Fatal("interior whitespace changed")
	}
	actor := uuid.MustParse("53ae930d-e4bd-478a-b64f-82f2b0d7e8e6")
	if !validTeamCreationRequestID("onboarding-v1:"+actor.String()+":use", actor, "use") ||
		validTeamCreationRequestID("onboarding-v1:"+actor.String()+":usw", actor, "use") ||
		!validTeamCreationRequestID("42140b1e-ac77-4ab0-9841-d9099ae8265a", actor, "use") {
		t.Fatal("request identity validation")
	}
}

func TestTeamCreationStaysClosedWithoutPromotionAuthority(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	keys := map[string]ed25519.PublicKey{"test": private.Public().(ed25519.PublicKey)}
	actor := "53ae930d-e4bd-478a-b64f-82f2b0d7e8e6"
	requestID := "onboarding-v1:" + actor + ":use"
	body := `{"request_id":"` + requestID + `","name":"Example team","region":"use"}`
	claims := map[string]any{
		"v": 1, "iss": "superserve-console", "aud": "superserve-team-creation", "purpose": "team-creation",
		"sub": actor, "iat": time.Now().Unix(), "exp": time.Now().Unix() + 120,
		"request_id": requestID, "name": "Example team", "region": "use", "authorization": "recover",
	}
	h := &Handlers{Config: &config.Config{TeamCreationRegion: "use", TeamCreationKeys: keys}}
	for _, authorization := range []string{"recover", "create"} {
		claims["authorization"] = authorization
		if authorization == "create" {
			claims["policy"] = map[string]any{"version": 1, "mode": "first_team", "session": "passed", "captcha": "passed", "preauth": "passed", "google_onboarding": "passed", "additional_team": "not_applicable"}
			claims["identity"] = map[string]any{"email": nil, "email_verified": false}
		}
		token := signTeamCreationTestAssertion(t, claims, private)
		request := httptest.NewRequest(http.MethodPost, "/internal/teams", strings.NewReader(body))
		request.Header.Set("X-Team-Creation-Assertion", token)
		response := httptest.NewRecorder()
		context, _ := gin.CreateTestContext(response)
		context.Request = request
		h.CreateInternalTeam(context)
		if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "provisioning_unavailable") {
			t.Errorf("%s: status %d body %s", authorization, response.Code, response.Body.String())
		}
	}
}
