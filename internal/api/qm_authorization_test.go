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
	identity    qmKeyIdentity
	err         error
	allowed     bool
	actor       uuid.UUID
	calls       int
	deniedActor uuid.UUID
}

func (f *qmAuthorityFake) Resolve(context.Context, string) (qmKeyIdentity, error) {
	return f.identity, f.err
}
func (f *qmAuthorityFake) Allowed(_ context.Context, a, _ uuid.UUID, _ string) (bool, error) {
	f.actor = a
	f.calls++
	return f.allowed && a != f.deniedActor, nil
}
func TestQMAuthorizationIdentityAndDenial(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, allowed := range []bool{true, false} {
		f := &qmAuthorityFake{identity: qmKeyIdentity{KeyID: uuid.New(), TeamID: uuid.New(), OwnerID: uuid.New()}, allowed: allowed}
		r := gin.New()
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
		var result qmAuthorization
		_ = json.Unmarshal(out.Body.Bytes(), &result)
		if result.ActorID != f.identity.KeyID.String() || result.CredentialID != result.ActorID || result.UserID != "" || result.OwnerID != f.identity.OwnerID.String() || result.Allowed != allowed || result.AuthOutcome != "authenticated" || f.actor != f.identity.OwnerID {
			t.Fatalf("wrong attribution %+v", result)
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
		token  string
		err    error
		status int
	}{{"", nil, 503}, {strings.Repeat("s", 32), pgx.ErrNoRows, 401}, {strings.Repeat("s", 32), errors.New("db-secret-marker"), 503}} {
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
		if strings.Contains(out.Body.String(), "secret-marker") {
			t.Fatal(out.Body)
		}
	}
	if strings.Contains(logs.String(), "secret-marker") {
		t.Fatal(logs.String())
	}
}

func TestQMHumanAuthorizationRetainsIdentityAndCannotElevateKey(t *testing.T) {
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
	}
}
