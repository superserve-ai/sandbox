//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/config"
)

func TestIntegration_TeamCreationReplayAndRecovery(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	actor := canonicalStripeActor(t, "team-creation-"+uuid.NewString()+"@example.com", true)
	requestID := uuid.NewString()
	originalRequestID := requestID
	name := "Example " + uuid.NewString()
	h := &api.Handlers{Pool: testPool, Config: &config.Config{
		TeamCreationRegion: "use",
		TeamCreationKeys:   map[string]ed25519.PublicKey{"test": private.Public().(ed25519.PublicKey)},
	}}
	call := func(authorization, requestName string) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(map[string]any{"request_id": requestID, "name": requestName, "region": "use"})
		if err != nil {
			t.Fatal(err)
		}
		claims := map[string]any{
			"v": 1, "iss": "superserve-console", "aud": "superserve-team-creation", "purpose": "team-creation",
			"sub": actor.String(), "iat": time.Now().Unix(), "exp": time.Now().Unix() + 120,
			"request_id": requestID, "name": requestName, "region": "use", "authorization": authorization,
		}
		if authorization == "create" {
			claims["policy"] = map[string]any{"version": 1, "mode": "first_team", "session": "passed", "captcha": "passed", "preauth": "passed", "google_onboarding": "passed", "additional_team": "not_applicable"}
			claims["identity"] = map[string]any{"email": "team-creation@example.com", "email_verified": true}
		}
		payload, err := json.Marshal(claims)
		if err != nil {
			t.Fatal(err)
		}
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"team-creation+jwt","kid":"test"}`))
		message := header + "." + base64.RawURLEncoding.EncodeToString(payload)
		assertion := message + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(message)))
		req := httptest.NewRequest(http.MethodPost, "/internal/teams", strings.NewReader(string(body)))
		req.Header.Set("X-Team-Creation-Assertion", assertion)
		response := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(response)
		ctx.Request = req
		h.CreateInternalTeam(ctx)
		return response
	}

	missing := call("recover", name)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("recovery miss: %d %s", missing.Code, missing.Body.String())
	}
	var beforeCreate int
	if err := testPool.QueryRow(context.Background(), `SELECT count(*) FROM team WHERE name=$1`, name).Scan(&beforeCreate); err != nil || beforeCreate != 0 {
		t.Fatalf("recovery created a team: count=%d err=%v", beforeCreate, err)
	}
	var concurrent [2]*httptest.ResponseRecorder
	var wg sync.WaitGroup
	for i := range concurrent {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			concurrent[i] = call("create", name)
		}(i)
	}
	wg.Wait()
	created := concurrent[0]
	if created.Code != http.StatusOK {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	if concurrent[1].Code != http.StatusOK || concurrent[1].Body.String() != created.Body.String() {
		t.Fatalf("concurrent retry: %d %s", concurrent[1].Code, concurrent[1].Body.String())
	}
	replayed := call("create", name)
	recovered := call("recover", name)
	if replayed.Code != http.StatusOK || recovered.Code != http.StatusOK || created.Body.String() != replayed.Body.String() || created.Body.String() != recovered.Body.String() {
		t.Fatalf("unstable result: create=%s replay=%s recover=%s", created.Body.String(), replayed.Body.String(), recovered.Body.String())
	}
	conflict := call("create", name+" changed")
	if conflict.Code != http.StatusConflict || !strings.Contains(conflict.Body.String(), "idempotency_conflict") {
		t.Fatalf("parameter conflict: %d %s", conflict.Code, conflict.Body.String())
	}
	var result struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	var memberships, roles, grants, requests int
	ctx := context.Background()
	for _, check := range []struct {
		query  string
		target *int
	}{
		{`SELECT count(*) FROM team_memberships WHERE team_id=$1 AND user_id=$2 AND status='active'`, &memberships},
		{`SELECT count(*) FROM user_role_assignments WHERE team_id=$1 AND user_id=$2 AND revoked_at IS NULL`, &roles},
		{`SELECT count(*) FROM team_credit_grant WHERE team_id=$1 AND created_by=$2 AND reason='signup trial credit'`, &grants},
		{`SELECT count(*) FROM team_creation_requests WHERE team_id=$1 AND actor_id=$2`, &requests},
	} {
		if err := testPool.QueryRow(ctx, check.query, result.ID, actor).Scan(check.target); err != nil {
			t.Fatal(err)
		}
	}
	if memberships != 1 || roles != 1 || grants != 1 || requests != 1 {
		t.Fatalf("incomplete result: membership=%d role=%d grant=%d request=%d", memberships, roles, grants, requests)
	}
	requestID = uuid.NewString()
	second := call("create", name+" second")
	if second.Code != http.StatusOK {
		t.Fatalf("later creation: %d %s", second.Code, second.Body.String())
	}
	var secondResult struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.Unmarshal(second.Body.Bytes(), &secondResult); err != nil {
		t.Fatal(err)
	}
	if secondResult.ID == result.ID {
		t.Fatal("new intent reused the original team")
	}
	var secondGrants int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM team_credit_grant WHERE team_id=$1 AND reason='signup trial credit'`, secondResult.ID).Scan(&secondGrants); err != nil || secondGrants != 0 {
		t.Fatalf("later creation granted another trial: count=%d err=%v", secondGrants, err)
	}
	if _, err := testPool.Exec(ctx, `ALTER TABLE promotion_identity_enforcement DISABLE TRIGGER promotion_identity_enforcement_irreversible;
		UPDATE promotion_identity_enforcement SET enabled=false, enabled_at=NULL, readiness_reference=NULL WHERE singleton;
		ALTER TABLE promotion_identity_enforcement ENABLE TRIGGER promotion_identity_enforcement_irreversible;`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := testPool.Exec(context.Background(), `ALTER TABLE promotion_identity_enforcement DISABLE TRIGGER promotion_identity_enforcement_irreversible;
			UPDATE promotion_identity_enforcement SET enabled=true, enabled_at=now(), readiness_reference='synthetic integration authority' WHERE singleton;
			ALTER TABLE promotion_identity_enforcement ENABLE TRIGGER promotion_identity_enforcement_irreversible;`); err != nil {
			t.Errorf("restore canonical promotion gate: %v", err)
		}
	}()
	requestID = uuid.NewString()
	closedName := name + " gate closed"
	closed := call("create", closedName)
	if closed.Code != http.StatusServiceUnavailable || !strings.Contains(closed.Body.String(), "provisioning_unavailable") {
		t.Fatalf("closed promotion gate: %d %s", closed.Code, closed.Body.String())
	}
	var closedTeams int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM team WHERE name=$1`, closedName).Scan(&closedTeams); err != nil || closedTeams != 0 {
		t.Fatalf("closed gate created a team: count=%d err=%v", closedTeams, err)
	}
	requestID = originalRequestID
	recoveredWhileClosed := call("recover", name)
	if recoveredWhileClosed.Code != http.StatusOK || recoveredWhileClosed.Body.String() != created.Body.String() {
		t.Fatalf("recovery during promotion pause: %d %s", recoveredWhileClosed.Code, recoveredWhileClosed.Body.String())
	}
}
