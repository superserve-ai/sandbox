package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type qmAuthorityFake struct {
	identity     qmKeyIdentity
	err          error
	allowed      bool
	actor        uuid.UUID
	calls        int
	deniedActor  uuid.UUID
	allowedErr   error
	panicAllowed bool
}

func (f *qmAuthorityFake) Resolve(context.Context, string) (qmKeyIdentity, error) {
	return f.identity, f.err
}
func (f *qmAuthorityFake) Allowed(_ context.Context, a, _ uuid.UUID, _ string) (bool, error) {
	if f.panicAllowed {
		panic("SYNTHETIC_AUTHORITY_SECRET")
	}
	f.actor = a
	f.calls++
	return f.allowed && a != f.deniedActor, f.allowedErr
}
func TestQMAuthorizationIdentityAndDenial(t *testing.T) {
	logs := captureRequestLogs(t)
	gin.SetMode(gin.TestMode)
	for _, allowed := range []bool{true, false} {
		f := &qmAuthorityFake{identity: qmKeyIdentity{KeyID: uuid.New(), TeamID: uuid.New(), OwnerID: uuid.New()}, allowed: allowed}
		r := gin.New()
		r.Use(RequestLogger())
		r.POST("/internal/qm/authorize", qmAuthorizationHandler(f, strings.Repeat("s", 32), nil))
		request := httptest.NewRequest("POST", "/internal/qm/authorize", strings.NewReader(`{"action":"write"}`))
		request.Header.Set("X-QM-Service-Token", strings.Repeat("s", 32))
		request.Header.Set("X-API-Key", "test-key")
		request.Header.Set("X-Actor-User-Id", uuid.NewString())
		out := httptest.NewRecorder()
		r.ServeHTTP(out, request)
		if out.Code != 200 {
			t.Fatal(out.Body)
		}
		entry := lastRequestLog(t, logs)
		var result qmAuthorization
		_ = json.Unmarshal(out.Body.Bytes(), &result)
		if result.ActorID != f.identity.KeyID.String() || result.CredentialID != result.ActorID || result.UserID != "" || result.OwnerID != f.identity.OwnerID.String() || result.Allowed != allowed || result.AuthOutcome != "authenticated" || f.actor != f.identity.OwnerID {
			t.Fatalf("wrong attribution %+v", result)
		}
		outcome := "denied"
		if allowed {
			outcome = "allowed"
		}
		for field, want := range map[string]any{"actor_type": "api_key", "actor_id": result.ActorID, "credential_id": result.CredentialID, "team_id": result.TeamID, "auth_outcome": "authenticated", "authorization_outcome": outcome, "status": float64(200)} {
			if entry[field] != want {
				t.Errorf("%s = %v, want %v", field, entry[field], want)
			}
		}
		if entry["user_id"] != nil || entry["owner_id"] != nil {
			t.Fatal("key owner logged as caller", entry)
		}
	}
}
func TestQMHumanProofBindsVerifiedCaller(t *testing.T) {
	pub, private, _ := ed25519.GenerateKey(nil)
	i := qmKeyIdentity{KeyID: uuid.New(), TeamID: uuid.New(), OwnerID: uuid.New()}
	human := uuid.New()
	claims := qmHumanClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: "console-auth-adapter", Audience: jwt.ClaimStrings{"qm-management"}, Subject: human.String(), IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Second)), ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * time.Second))}, CredentialID: i.KeyID.String(), TeamID: i.TeamID.String(), Action: "admin-link"}
	token, e := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(private)
	if e != nil {
		t.Fatal(e)
	}
	got, e := qmHuman(token, pub, i, "admin-link")
	if e != nil || got != human {
		t.Fatal(got, e)
	}
	if _, e = qmHuman(token, pub, i, "write"); e == nil {
		t.Fatal("action substitution")
	}
	i.KeyID = uuid.New()
	if _, e = qmHuman(token, pub, i, "admin-link"); e == nil {
		t.Fatal("credential substitution")
	}
}
func TestQMAuthFailuresAndSecretSafety(t *testing.T) {
	var logs bytes.Buffer
	previous := log.Logger
	log.Logger = zerolog.New(&logs)
	defer func() { log.Logger = previous }()
	for _, tc := range []struct {
		token   string
		err     error
		status  int
		outcome string
	}{{"", nil, 503, "missing"}, {strings.Repeat("s", 32), pgx.ErrNoRows, 401, "invalid"}, {strings.Repeat("s", 32), errors.New("db-secret-marker"), 503, "error"}} {
		f := &qmAuthorityFake{err: tc.err}
		r := gin.New()
		r.Use(RequestLogger())
		r.POST("/internal/qm/authorize", qmAuthorizationHandler(f, strings.Repeat("s", 32), nil))
		req := httptest.NewRequest("POST", "/internal/qm/authorize?key=query-secret-marker", strings.NewReader(`{"action":"read"}`))
		req.Header.Set("X-QM-Service-Token", tc.token)
		req.Header.Set("X-API-Key", "key-secret-marker")
		out := httptest.NewRecorder()
		r.ServeHTTP(out, req)
		if out.Code != tc.status || f.calls != 0 {
			t.Fatal(out.Code, f.calls)
		}
		entry := lastRequestLog(t, &logs)
		if entry["auth_outcome"] != tc.outcome || entry["actor_id"] != nil || entry["authorization_outcome"] != "not_evaluated" {
			t.Fatal(entry)
		}
		if strings.Contains(out.Body.String(), "secret-marker") {
			t.Fatal(out.Body)
		}
	}
	if strings.Contains(logs.String(), "secret-marker") {
		t.Fatal(logs.String())
	}
}

func TestQMHumanAuthorizationRetainsIdentityAndCannotElevateKey(t *testing.T) {
	logs := captureRequestLogs(t)
	pub, private, _ := ed25519.GenerateKey(nil)
	identity := qmKeyIdentity{KeyID: uuid.New(), TeamID: uuid.New(), OwnerID: uuid.New()}
	human := uuid.New()
	claims := qmHumanClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: "console-auth-adapter", Audience: jwt.ClaimStrings{"qm-management"}, Subject: human.String(), IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Second)), ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * time.Second))}, CredentialID: identity.KeyID.String(), TeamID: identity.TeamID.String(), Action: "admin-link"}
	proof, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(private)
	if err != nil {
		t.Fatal(err)
	}
	for _, denied := range []uuid.UUID{uuid.Nil, human, identity.OwnerID} {
		f := &qmAuthorityFake{identity: identity, allowed: true, deniedActor: denied}
		r := gin.New()
		r.Use(RequestLogger())
		r.POST("/internal/qm/authorize", qmAuthorizationHandler(f, strings.Repeat("s", 32), pub))
		req := httptest.NewRequest("POST", "/internal/qm/authorize", strings.NewReader(`{"action":"admin-link"}`))
		req.Header.Set("X-QM-Service-Token", strings.Repeat("s", 32))
		req.Header.Set("X-API-Key", "test-key")
		req.Header.Set("X-QM-Human-Assertion", proof)
		out := httptest.NewRecorder()
		r.ServeHTTP(out, req)
		var result qmAuthorization
		if err := json.Unmarshal(out.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if out.Code != 200 || result.ActorType != "human" || result.ActorID != human.String() || result.UserID != human.String() || result.CredentialID != identity.KeyID.String() || result.AuthOutcome != "authenticated" || result.Allowed != (denied == uuid.Nil) {
			t.Fatalf("wrong verified denial %+v", result)
		}
		entry := lastRequestLog(t, logs)
		outcome := "denied"
		if denied == uuid.Nil {
			outcome = "allowed"
		}
		for field, want := range map[string]any{"actor_type": "human", "actor_id": human.String(), "user_id": human.String(), "credential_id": identity.KeyID.String(), "team_id": identity.TeamID.String(), "delegated_by": "api_key", "auth_outcome": "authenticated", "authorization_outcome": outcome} {
			if entry[field] != want {
				t.Errorf("%s = %v, want %v", field, entry[field], want)
			}
		}
		if strings.Contains(logs.String(), proof) {
			t.Fatal("human proof leaked")
		}
	}
}

func TestQMRequestLoggingRejectsUnverifiedClaimsAndRetainsVerifiedFailures(t *testing.T) {
	logs := captureRequestLogs(t)
	identity := qmKeyIdentity{KeyID: uuid.New(), TeamID: uuid.New(), OwnerID: uuid.New()}
	for _, tc := range []struct {
		name, proof, authOutcome, authzOutcome string
		status                                 int
		fail, panicAuthz                       bool
	}{
		{name: "invalid proof", proof: "SYNTHETIC_PROOF_SECRET", authOutcome: "invalid", authzOutcome: "not_evaluated", status: 401},
		{name: "authorization unavailable", authOutcome: "authenticated", authzOutcome: "error", status: 503, fail: true},
		{name: "authorization panic", authOutcome: "authenticated", authzOutcome: "error", status: 500, panicAuthz: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs.Reset()
			f := &qmAuthorityFake{identity: identity, allowed: true, panicAllowed: tc.panicAuthz}
			if tc.fail {
				f.allowedErr = errors.New("SYNTHETIC_AUTHORITY_SECRET")
			}
			r := gin.New()
			r.Use(RequestLogger())
			r.POST("/internal/qm/authorize", qmAuthorizationHandler(f, strings.Repeat("s", 32), nil))
			req := httptest.NewRequest("POST", "/internal/qm/authorize", strings.NewReader(`{"action":"write"}`))
			req.Header.Set("X-QM-Service-Token", strings.Repeat("s", 32))
			req.Header.Set("X-API-Key", "SYNTHETIC_KEY_SECRET")
			req.Header.Set("X-QM-Human-Assertion", tc.proof)
			out := httptest.NewRecorder()
			r.ServeHTTP(out, req)
			entry := lastRequestLog(t, logs)
			if out.Code != tc.status || entry["auth_outcome"] != tc.authOutcome || entry["authorization_outcome"] != tc.authzOutcome {
				t.Fatal(out.Code, entry)
			}
			if tc.authOutcome == "authenticated" {
				if entry["actor_id"] != identity.KeyID.String() || entry["credential_id"] != identity.KeyID.String() || entry["team_id"] != identity.TeamID.String() {
					t.Fatal(entry)
				}
			} else if entry["actor_id"] != nil || entry["credential_id"] != nil || entry["team_id"] != nil || f.calls != 0 {
				t.Fatal(entry)
			}
			if entry["user_id"] != nil || strings.Contains(logs.String(), "SYNTHETIC") {
				t.Fatal("unverified identity or secret logged", entry)
			}
		})
	}
}
