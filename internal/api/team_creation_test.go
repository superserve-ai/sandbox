package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/getsentry/sentry-go"
	sentrygin "github.com/getsentry/sentry-go/gin"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/superserve-ai/sandbox/internal/abuse"
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
		"identity": map[string]any{"email": "user@example.com", "email_verified": true, "auth_updated_at": now.UTC().Format(teamCreationIdentityTimeLayout), "observed_at": now.UTC().Format(teamCreationIdentityTimeLayout)},
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

func TestTeamCreationTrustBoundaryRejectionMatrix(t *testing.T) {
	t.Setenv("INTERNAL_API_TOKEN", "internal-test-token")
	now := time.Unix(1_800_000_000, 0)
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	keys := map[string]ed25519.PublicKey{"test": private.Public().(ed25519.PublicKey)}
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"wrong issuer", func(c map[string]any) { c["iss"] = "other-console" }},
		{"wrong audience", func(c map[string]any) { c["aud"] = "other-service" }},
		{"unknown policy mode", func(c map[string]any) { c["policy"].(map[string]any)["mode"] = "bypass" }},
		{"first team missing preauth", func(c map[string]any) { c["policy"].(map[string]any)["preauth"] = "not_applicable" }},
		{"additional team with first-team proof", func(c map[string]any) {
			p := c["policy"].(map[string]any)
			p["mode"], p["additional_team"] = "additional_team", "passed"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := teamCreationTestClaims(now)
			tc.change(claims)
			if _, err := verifyTeamCreationAssertion(signTeamCreationTestAssertion(t, claims, private), keys, now); err == nil {
				t.Fatal("accepted trust-boundary violation")
			}
		})
	}
	// Algorithm confusion must fail even when the attacker can produce a valid
	// Ed25519 signature over a header naming a different algorithm.
	claims := teamCreationTestClaims(now)
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	for _, algorithm := range []string{"HS256", "Ed25519"} {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"` + algorithm + `","typ":"team-creation+jwt","kid":"test"}`))
		encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
		message := header + "." + encodedPayload
		assertion := message + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(message)))
		if _, err := verifyTeamCreationAssertion(assertion, keys, now); err == nil {
			t.Fatalf("accepted algorithm %s", algorithm)
		}
	}

	// Unknown regions are rejected by the registered route before any pool
	// access, while the internal legacy route remains usable with its token.
	h := &Handlers{Config: &config.Config{TeamCreationRegion: "use", TeamCreationKeys: keys}, SignupRestrictions: &abuse.SignupEvaluator{Source: abuse.NewConfigComputeSource("", nil, nil)}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	router := SetupRouter(ctx, h, nil)
	claims = teamCreationTestClaims(time.Now())
	claims["region"] = "moon"
	body := `{"request_id":"42140b1e-ac77-4ab0-9841-d9099ae8265a","name":"Café ☃","region":"moon"}`
	req := httptest.NewRequest(http.MethodPost, "/internal/teams", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer internal-test-token")
	req.Header.Set("X-Team-Creation-Assertion", signTeamCreationTestAssertion(t, claims, private))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown region route status=%d body=%s", w.Code, w.Body.String())
	}
	legacy := httptest.NewRequest(http.MethodPost, "/internal/signup/evaluate", strings.NewReader(`{"subjects":[{"type":"fingerprint","value":"visitor-example"}]}`))
	legacy.Header.Set("Authorization", "Bearer internal-test-token")
	legacyResponse := httptest.NewRecorder()
	router.ServeHTTP(legacyResponse, legacy)
	if legacyResponse.Code != http.StatusOK {
		t.Fatalf("legacy route disabled by team verifier rejection: %d %s", legacyResponse.Code, legacyResponse.Body.String())
	}
}

func TestTeamCreationMissingVerifierConfigurationOnlyDisablesNewRoute(t *testing.T) {
	t.Setenv("INTERNAL_API_TOKEN", "internal-test-token")
	for _, tc := range []struct {
		name string
		keys map[string]ed25519.PublicKey
	}{
		{name: "missing", keys: nil},
		{name: "malformed", keys: map[string]ed25519.PublicKey{"bad": []byte("short")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handlers{
				Config:             &config.Config{TeamCreationRegion: "use", TeamCreationKeys: tc.keys},
				SignupRestrictions: &abuse.SignupEvaluator{Source: abuse.NewConfigComputeSource("", nil, nil)},
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			router := SetupRouter(ctx, h, nil)
			teamRequest := httptest.NewRequest(http.MethodPost, "/internal/teams", strings.NewReader(`{"request_id":"42140b1e-ac77-4ab0-9841-d9099ae8265a","name":"Example team","region":"use"}`))
			teamRequest.Header.Set("Authorization", "Bearer internal-test-token")
			teamResponse := httptest.NewRecorder()
			router.ServeHTTP(teamResponse, teamRequest)
			if teamResponse.Code != http.StatusServiceUnavailable || !strings.Contains(teamResponse.Body.String(), "provisioning_unavailable") {
				t.Fatalf("verifier configuration status=%d body=%s", teamResponse.Code, teamResponse.Body.String())
			}
			legacyRequest := httptest.NewRequest(http.MethodPost, "/internal/signup/evaluate", strings.NewReader(`{"subjects":[{"type":"fingerprint","value":"visitor-example"}]}`))
			legacyRequest.Header.Set("Authorization", "Bearer internal-test-token")
			legacyResponse := httptest.NewRecorder()
			router.ServeHTTP(legacyResponse, legacyRequest)
			if legacyResponse.Code != http.StatusOK {
				t.Fatalf("verifier configuration disabled legacy route: %d %s", legacyResponse.Code, legacyResponse.Body.String())
			}
		})
	}
}

func TestTeamCreationStrictInput(t *testing.T) {
	for _, raw := range []string{
		`{"request_id":"a","request_id":"b","name":"x","region":"use"}`,
		`{"request_id":"a","name":"x","region":"use","other":1}`,
		`{"request_id":"a","name":9,"region":"use"}`,
		`{"request_id":"a","name":"x","Name":"y","region":"use"}`,
		`{"request_id":"a","name":null,"region":"use"}`,
		`{"request_id":"a","name":"x","region":"use"} {}`,
		`null`,
		`{"request_id":"a","name":"\uD800","region":"use"}`,
		`{"request_id":"a","name":"\uDC00","region":"use"}`,
		`{"request_id":"a","name":"\uD800\u0061","region":"use"}`,
	} {
		var input teamCreationInput
		if err := decodeUniqueJSON([]byte(raw), &input); err == nil {
			t.Errorf("accepted invalid JSON: %s", raw)
		}
	}
	var unicodeInput teamCreationInput
	if err := decodeUniqueJSON([]byte(`{"request_id":"a","name":"\uD83D\uDE00","region":"use"}`), &unicodeInput); err != nil || unicodeInput.Name != "😀" {
		t.Fatalf("valid Unicode pair: %q %v", unicodeInput.Name, err)
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
			claims["identity"] = map[string]any{"email": nil, "email_verified": false, "auth_updated_at": time.Now().UTC().Format(teamCreationIdentityTimeLayout), "observed_at": time.Now().UTC().Format(teamCreationIdentityTimeLayout)}
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

func teamCreationTestClaims(now time.Time) map[string]any {
	return map[string]any{
		"v": 1, "iss": "superserve-console", "aud": "superserve-team-creation", "purpose": "team-creation",
		"sub": "53ae930d-e4bd-478a-b64f-82f2b0d7e8e6", "iat": now.Unix(), "exp": now.Unix() + 120,
		"request_id": "42140b1e-ac77-4ab0-9841-d9099ae8265a", "name": "Café ☃", "region": "use", "authorization": "create",
		"policy":   map[string]any{"version": 1, "mode": "first_team", "session": "passed", "captcha": "passed", "preauth": "passed", "google_onboarding": "passed", "additional_team": "not_applicable"},
		"identity": map[string]any{"email": "user@example.com", "email_verified": true, "auth_updated_at": now.UTC().Format(teamCreationIdentityTimeLayout), "observed_at": now.UTC().Format(teamCreationIdentityTimeLayout)},
	}
}

func TestTeamCreationExactAssertionSchema(t *testing.T) {
	now := time.Unix(1800000000, 0)
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	keys := map[string]ed25519.PublicKey{"test": private.Public().(ed25519.PublicKey)}
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"case collision", func(c map[string]any) { c["Name"] = "replacement" }},
		{"nested case collision", func(c map[string]any) { c["identity"].(map[string]any)["Email"] = "replacement@example.com" }},
		{"null iat", func(c map[string]any) { c["iat"] = nil }},
		{"overflow lifetime", func(c map[string]any) { c["iat"] = int64(math.MinInt64); c["exp"] = int64(math.MaxInt64) }},
		{"overflow future", func(c map[string]any) { c["iat"] = int64(math.MaxInt64) - 100; c["exp"] = int64(math.MaxInt64) }},
		{"fractional iat", func(c map[string]any) { c["iat"] = 1800000000.5 }},
		{"missing revision", func(c map[string]any) { delete(c["identity"].(map[string]any), "auth_updated_at") }},
		{"null verified", func(c map[string]any) { c["identity"].(map[string]any)["email_verified"] = nil }},
		{"unknown identity", func(c map[string]any) { c["identity"].(map[string]any)["canonical_identity"] = "injected" }},
		{"null recovery evidence", func(c map[string]any) { c["authorization"] = "recover"; delete(c, "policy"); c["identity"] = nil }},
		{"future issuance", func(c map[string]any) { c["iat"] = now.Unix() + 31; c["exp"] = now.Unix() + 151 }},
		{"excess lifetime", func(c map[string]any) { c["exp"] = now.Unix() + 121 }},
		{"empty lifetime", func(c map[string]any) { c["exp"] = now.Unix() }},
		{"missing policy check", func(c map[string]any) { delete(c["policy"].(map[string]any), "captcha") }},
		{"first team exemption", func(c map[string]any) { c["policy"].(map[string]any)["captcha"] = "not_applicable" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := teamCreationTestClaims(now)
			tc.change(claims)
			if _, err := verifyTeamCreationAssertion(signTeamCreationTestAssertion(t, claims, private), keys, now); err == nil {
				t.Fatal("accepted invalid assertion")
			}
		})
	}
	for _, raw := range []string{"2027-01-15T08:00:00Z", "2027-01-15T08:00:00.000Z", "2027-01-15T08:00:00.0000000Z", "2027-01-15T08:00:00.000000+00:00", "0000-01-01T00:00:00.000000Z", "infinity", "2027-01-15T08:00:00,000000Z"} {
		claims := teamCreationTestClaims(now)
		claims["identity"].(map[string]any)["auth_updated_at"] = raw
		if _, err := verifyTeamCreationAssertion(signTeamCreationTestAssertion(t, claims, private), keys, now); err == nil {
			t.Errorf("accepted timestamp %q", raw)
		}
	}
	for _, seconds := range []int64{-30, 30} {
		claims := teamCreationTestClaims(now)
		claims["iat"] = now.Unix() + seconds
		claims["exp"] = now.Unix() + seconds + 120
		if seconds < 0 {
			claims["iat"] = now.Unix() - 150
			claims["exp"] = now.Unix() - 30
		}
		if _, err := verifyTeamCreationAssertion(signTeamCreationTestAssertion(t, claims, private), keys, now); err != nil {
			t.Errorf("skew boundary %d: %v", seconds, err)
		}
	}
}

func TestTeamCreationRegisteredAuthentication(t *testing.T) {
	t.Setenv("INTERNAL_API_TOKEN", "internal-test-token")
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	h := &Handlers{Config: &config.Config{TeamCreationRegion: "use", TeamCreationKeys: map[string]ed25519.PublicKey{"test": private.Public().(ed25519.PublicKey)}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	router := SetupRouter(ctx, h, nil)
	assertion := signTeamCreationTestAssertion(t, teamCreationTestClaims(time.Now()), private)
	for _, tc := range []struct {
		name, credential, assertion, actor string
		status                             int
	}{
		{"no credentials", "", "", "", 401},
		{"actor only", "", "", "53ae930d-e4bd-478a-b64f-82f2b0d7e8e6", 401},
		{"internal only", "Bearer internal-test-token", "", "", 401},
		{"assertion only", "", assertion, "", 401},
		{"wrong credential", "Bearer wrong-token", assertion, "", 401},
		{"both", "Bearer internal-test-token", assertion, "", 503},
		{"actor is ignored", "Bearer internal-test-token", assertion, uuid.NewString(), 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/internal/teams", strings.NewReader(`{"request_id":"42140b1e-ac77-4ab0-9841-d9099ae8265a","name":"Café ☃","region":"use"}`))
			r.Header.Set("Authorization", tc.credential)
			r.Header.Set("X-Team-Creation-Assertion", tc.assertion)
			r.Header.Set("X-Actor-User-Id", tc.actor)
			w := &deadlineTeamWriter{ResponseRecorder: httptest.NewRecorder()}
			router.ServeHTTP(w, r)
			if len(w.deadlines) == 0 || w.deadlines[0].IsZero() {
				t.Fatal("rejected request has no socket deadline")
			}
			if w.Code != tc.status {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

type deadlineTeamWriter struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
}

func (w *deadlineTeamWriter) SetReadDeadline(d time.Time) error {
	w.deadlines = append(w.deadlines, d)
	return nil
}

type deadlineTeamBody struct {
	writer *deadlineTeamWriter
	reads  int
}

func (b *deadlineTeamBody) Read(_ []byte) (int, error) {
	b.reads++
	if len(b.writer.deadlines) == 0 {
		panic("body read without deadline")
	}
	return 0, os.ErrDeadlineExceeded
}
func (b *deadlineTeamBody) Close() error { return nil }

func TestTeamCreationBoundedBody(t *testing.T) {
	now := time.Now()
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	h := &Handlers{Config: &config.Config{TeamCreationRegion: "use", TeamCreationKeys: map[string]ed25519.PublicKey{"test": private.Public().(ed25519.PublicKey)}}}
	for _, valid := range []bool{false, true} {
		w := &deadlineTeamWriter{ResponseRecorder: httptest.NewRecorder()}
		body := &deadlineTeamBody{writer: w}
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("POST", "/internal/teams", nil)
		c.Request.Body = body
		if valid {
			c.Request.Header.Set("X-Team-Creation-Assertion", signTeamCreationTestAssertion(t, teamCreationTestClaims(now), private))
		}
		h.createInternalTeam(c, now)
		if valid {
			if w.Code != 400 || body.reads != 1 || len(w.deadlines) != 1 || !w.deadlines[0].Equal(now.Add(5*time.Second)) {
				t.Fatalf("body deadline not enforced: %+v", w)
			}
		} else if body.reads != 0 || w.Code != 401 {
			t.Fatal("unverified assertion read body")
		}
	}
	for _, knownLength := range []bool{false, true} {
		reader := &io.LimitedReader{R: strings.NewReader(strings.Repeat(" ", teamCreationBodyLimit*2)), N: teamCreationBodyLimit * 2}
		response := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(response)
		c.Request = httptest.NewRequest("POST", "/internal/teams", reader)
		if knownLength {
			c.Request.ContentLength = teamCreationBodyLimit * 2
		}
		c.Request.Header.Set("X-Team-Creation-Assertion", signTeamCreationTestAssertion(t, teamCreationTestClaims(now), private))
		h.createInternalTeam(c, now)
		if response.Code != 413 || reader.N < teamCreationBodyLimit-1 {
			t.Fatalf("unbounded read: %d remaining=%d", response.Code, reader.N)
		}
	}
}

func TestTeamCreationPrivateDiagnostics(t *testing.T) {
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
	}, RequestLogger(), ErrorHandler(), sentrygin.New(sentrygin.Options{Repanic: true}))
	email := uuid.NewString() + "@example.com"
	assertion := uuid.NewString()
	router.POST("/internal/teams", TeamCreationPrivacy(), func(c *gin.Context) { panic(c.GetHeader("X-Team-Creation-Assertion")) })
	request := httptest.NewRequest("POST", "/internal/teams?email="+email, strings.NewReader(`{"email":"`+email+`"}`))
	request.Header.Set("X-Team-Creation-Assertion", assertion)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != 500 || captured == nil {
		t.Fatal("panic was not reported")
	}
	eventJSON, err := json.Marshal(captured)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{email, assertion} {
		if strings.Contains(output.String(), secret) || bytes.Contains(eventJSON, []byte(secret)) {
			t.Fatalf("diagnostics leaked %q", secret)
		}
	}
}

func TestTeamCreationProtocolFixtures(t *testing.T) {
	data, err := os.ReadFile("testdata/team_creation_protocol.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Now            int64  `json:"now"`
		Seed           string `json:"signing_seed_hex"`
		PublicKey      string `json:"public_key_base64"`
		NextSeed       string `json:"next_signing_seed_hex"`
		NextPublicKey  string `json:"next_public_key_base64"`
		ResponseShapes struct {
			Success teamCreationResult `json:"success"`
			Error   json.RawMessage    `json:"error"`
		} `json:"response_shapes"`
		Requests []struct {
			Name          string `json:"case"`
			Assertion     string `json:"assertion"`
			Claims        string `json:"claims_json"`
			Body          string `json:"body_json"`
			Cell          string `json:"receiving_cell"`
			Status        int    `json:"prewrite_status"`
			Code          string `json:"prewrite_code"`
			VerifierError string `json:"verifier_error"`
			Tampered      bool   `json:"tampered"`
		} `json:"requests"`
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(fixture.Seed)
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	if base64.StdEncoding.EncodeToString(public) != fixture.PublicKey {
		t.Fatal("fixture public key mismatch")
	}
	nextSeed, err := hex.DecodeString(fixture.NextSeed)
	if err != nil {
		t.Fatal(err)
	}
	nextPrivate := ed25519.NewKeyFromSeed(nextSeed)
	nextPublic := nextPrivate.Public().(ed25519.PublicKey)
	if base64.StdEncoding.EncodeToString(nextPublic) != fixture.NextPublicKey {
		t.Fatal("next fixture public key mismatch")
	}
	keys := map[string]ed25519.PublicKey{"test": public, "next": nextPublic}
	shape, err := json.Marshal(fixture.ResponseShapes.Success)
	if err != nil {
		t.Fatal(err)
	}
	var successFields map[string]any
	if json.Unmarshal(shape, &successFields) != nil || len(successFields) != 3 || successFields["region"] != "use" {
		t.Fatal("success fixture shape changed")
	}
	shapeResponse := httptest.NewRecorder()
	shapeContext, _ := gin.CreateTestContext(shapeResponse)
	respondErrorMsg(shapeContext, "result_not_found", "No completed result exists", http.StatusNotFound)
	var actualShape, expectedShape any
	if json.Unmarshal(shapeResponse.Body.Bytes(), &actualShape) != nil || json.Unmarshal(fixture.ResponseShapes.Error, &expectedShape) != nil || !reflect.DeepEqual(actualShape, expectedShape) {
		t.Fatal("error fixture shape changed")
	}
	for _, v := range fixture.Requests {
		t.Run(v.Name, func(t *testing.T) {
			parts := strings.Split(v.Assertion, ".")
			payload, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil || !bytes.Equal(payload, []byte(v.Claims)) {
				t.Fatal("fixture claims differ from signed payload")
			}
			if !v.Tampered {
				signer := private
				var header struct {
					KeyID string `json:"kid"`
				}
				rawHeader, _ := base64.RawURLEncoding.DecodeString(parts[0])
				if json.Unmarshal(rawHeader, &header) != nil {
					t.Fatal("invalid fixture header")
				}
				if header.KeyID == "next" {
					signer = nextPrivate
				}
				expected := ed25519.Sign(signer, []byte(parts[0]+"."+parts[1]))
				sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
				if !bytes.Equal(expected, sig) {
					t.Fatal("signature differs from fixture")
				}
			}
			_, err = verifyTeamCreationAssertion(v.Assertion, keys, time.Unix(fixture.Now, 0))
			got := ""
			if err != nil {
				got = err.Error()
			}
			if got != v.VerifierError {
				t.Fatalf("verifier: got %q want %q", got, v.VerifierError)
			}
			response := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(response)
			c.Request = httptest.NewRequest("POST", "/internal/teams", strings.NewReader(v.Body))
			c.Request.Header.Set("X-Team-Creation-Assertion", v.Assertion)
			h := &Handlers{Config: &config.Config{TeamCreationRegion: v.Cell, TeamCreationKeys: keys}}
			h.createInternalTeam(c, time.Unix(fixture.Now, 0))
			var result struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err = json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if response.Code != v.Status || result.Error.Code != v.Code || result.Error.Message == "" {
				t.Fatalf("response: %d %s", response.Code, response.Body.String())
			}
		})
	}
}
