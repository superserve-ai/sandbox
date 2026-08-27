//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

func TestPlatformAbuseControlPlaneRoutes(t *testing.T) {
	ctx := context.Background()
	teamID := mustCreateTeam(t, ctx, "abuse-control-"+uuid.NewString()[:8])
	adminID := seedPlatformAdminProfile(t)
	nonAdminID := seedSuperserveEmailProfile(t)
	r := newInternalRouter(t)

	// Internal authentication and the dedicated permission are both required,
	// even for read-only abuse-control operations.
	if w := doInternal(r, http.MethodGet, "/internal/abuse/teams/"+teamID.String()+"/trust", nonAdminID.String(), ""); w.Code != http.StatusForbidden {
		t.Fatalf("non-admin trust read status = %d, want 403: %s", w.Code, w.Body.String())
	}

	trustPath := "/internal/abuse/teams/" + teamID.String() + "/trust"
	if w := doInternal(r, http.MethodPut, trustPath, nonAdminID.String(), `{"verified":true}`); w.Code != http.StatusForbidden {
		t.Fatalf("non-admin trust write status = %d, want 403: %s", w.Code, w.Body.String())
	}
	if w := doInternal(r, http.MethodPut, trustPath, adminID.String(), `{"verified":true,"reason":"approved team","evidence":{"source":"review"}}`); w.Code != http.StatusNoContent {
		t.Fatalf("set team trust status = %d, want 204: %s", w.Code, w.Body.String())
	}
	trustRead := doInternal(r, http.MethodGet, trustPath, adminID.String(), "")
	if trustRead.Code != http.StatusOK {
		t.Fatalf("get team trust status = %d, want 200: %s", trustRead.Code, trustRead.Body.String())
	}
	var trust struct {
		Verified bool `json:"verified"`
	}
	if err := json.Unmarshal(trustRead.Body.Bytes(), &trust); err != nil {
		t.Fatalf("decode team trust: %v", err)
	}
	if !trust.Verified {
		t.Fatal("team trust readback is not verified")
	}
	if auditEventCount(t, ctx, teamID, "abuse.team_trust.changed") == 0 {
		t.Fatal("expected team trust audit row")
	}

	create := doInternal(r, http.MethodPost, "/internal/abuse/restrictions", adminID.String(), `{"subject_type":"ip","subject_value":"192.0.2.10","action":"create","reason":"test restriction","evidence":{"case":"integration"}}`)
	if create.Code != http.StatusCreated {
		t.Fatalf("create restriction status = %d, want 201: %s", create.Code, create.Body.String())
	}
	var created struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.Unmarshal(create.Body.Bytes(), &created); err != nil || created.ID == uuid.Nil {
		t.Fatalf("decode created restriction: %v, body=%s", err, create.Body.String())
	}
	list := doInternal(r, http.MethodGet, "/internal/abuse/restrictions", adminID.String(), "")
	var activeRestrictions []struct {
		ID uuid.UUID `json:"id"`
	}
	if list.Code != http.StatusOK || json.Unmarshal(list.Body.Bytes(), &activeRestrictions) != nil || len(activeRestrictions) == 0 {
		t.Fatalf("restriction list status/body = %d/%s, want active restriction", list.Code, list.Body.String())
	}
	var restrictionAudit int
	if err := testPool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_logs WHERE actor_user_id=$1 AND event_type='abuse.restriction.created'`, adminID).Scan(&restrictionAudit); err != nil {
		t.Fatalf("count restriction audit rows: %v", err)
	}
	if restrictionAudit == 0 {
		t.Fatal("expected restriction creation audit row")
	}

	releasePath := "/internal/abuse/restrictions/" + created.ID.String() + "/release"
	if w := doInternal(r, http.MethodPost, releasePath, adminID.String(), ""); w.Code != http.StatusNoContent {
		t.Fatalf("release restriction status = %d, want 204: %s", w.Code, w.Body.String())
	}
	listAfterRelease := doInternal(r, http.MethodGet, "/internal/abuse/restrictions", adminID.String(), "")
	var releasedRestrictions []struct {
		ID uuid.UUID `json:"id"`
	}
	if listAfterRelease.Code != http.StatusOK || json.Unmarshal(listAfterRelease.Body.Bytes(), &releasedRestrictions) != nil || len(releasedRestrictions) != 0 {
		t.Fatalf("released restriction list = %d/%s, want empty", listAfterRelease.Code, listAfterRelease.Body.String())
	}
	var releaseAudit int
	if err := testPool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_logs WHERE actor_user_id=$1 AND event_type='abuse.restriction.released'`, adminID).Scan(&releaseAudit); err != nil {
		t.Fatalf("count release audit rows: %v", err)
	}
	if releaseAudit == 0 {
		t.Fatal("expected restriction release audit row")
	}

	identity := doInternal(r, http.MethodPost, "/internal/abuse/trusted-identities", adminID.String(), `{"auth_provider":"Google","domain":"example.test","evidence":{"approved":true}}`)
	if identity.Code != http.StatusCreated {
		t.Fatalf("add trusted identity status = %d, want 201: %s", identity.Code, identity.Body.String())
	}
	var createdIdentity struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.Unmarshal(identity.Body.Bytes(), &createdIdentity); err != nil || createdIdentity.ID == uuid.Nil {
		t.Fatalf("decode trusted identity: %v, body=%s", err, identity.Body.String())
	}
	if w := doInternal(r, http.MethodPost, "/internal/abuse/trusted-identities/"+createdIdentity.ID.String()+"/revoke", adminID.String(), ""); w.Code != http.StatusNoContent {
		t.Fatalf("revoke trusted identity status = %d, want 204: %s", w.Code, w.Body.String())
	}
	if w := doInternal(r, http.MethodPost, "/internal/abuse/refresh", adminID.String(), fmt.Sprintf(`{"team_id":%q,"reason":"refresh after change"}`, teamID)); w.Code != http.StatusNoContent {
		t.Fatalf("record refresh status = %d, want 204: %s", w.Code, w.Body.String())
	}
	var refreshAudit int
	if err := testPool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_logs WHERE team_id=$1 AND event_type='abuse.state.refresh_requested'`, teamID).Scan(&refreshAudit); err != nil {
		t.Fatalf("count refresh audit rows: %v", err)
	}
	if refreshAudit == 0 {
		t.Fatal("expected refresh audit row")
	}
}
