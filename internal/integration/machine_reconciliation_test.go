//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/auth"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestMachineCredentialReconciliation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	team, _ := seedTeamAndKey(t)
	otherTeam, _ := seedTeamAndKey(t)
	principal := machineRepairPrincipal(t, testQueries, team)
	other := machineRepairPrincipal(t, testQueries, otherTeam)
	credential := machineRepairIssue(t, testQueries, principal, uuid.New(), uuid.New(), "reconciliation-fixture")
	authority := api.NewDBMachineAuthority(testQueries)
	// Issuance is deliberately disabled: reads and revocation remain available.
	if _, err := authority.ReadCredential(ctx, principal.ID, credential.ID); !errors.Is(err, auth.ErrMachineCapabilityDenied) {
		t.Fatalf("unprotected metadata read: %v", err)
	}
	if err := authority.RevokeCredentialScoped(ctx, principal.ID, credential.ID, credential.RevocationGeneration); !errors.Is(err, auth.ErrMachineCapabilityDenied) {
		t.Fatalf("unprotected revoke: %v", err)
	}
	t.Setenv("OPERATOR_API_TOKEN", "reconciliation-operator-fixture")
	router := api.SetupRouter(ctx, &api.Handlers{MachineCredentials: authority}, nil)
	request := func(method string, owner uuid.UUID, suffix, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, "/internal/machine-identity/principals/"+owner.String()+"/credentials/"+suffix, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer reconciliation-operator-fixture")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		return response
	}
	read := func(id uuid.UUID, wantState string) {
		t.Helper()
		response := request("GET", principal.ID, id.String(), "")
		var body map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || response.Code != http.StatusOK {
			t.Fatalf("metadata read: %d %s %v", response.Code, response.Body, err)
		}
		if len(body) != 6 || body["principal_id"] != principal.ID.String() || body["credential_id"] != id.String() || body["state"] != wantState || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("metadata response: %v", body)
		}
		for _, key := range []string{"lineage_id", "expires_at", "revocation_generation"} {
			if _, ok := body[key]; !ok {
				t.Fatalf("missing %s", key)
			}
		}
	}
	read(credential.ID, "active")
	if response := request("GET", other.ID, credential.ID.String(), ""); response.Code != http.StatusNotFound {
		t.Fatalf("foreign principal read: %d", response.Code)
	}
	if response := request("GET", principal.ID, uuid.NewString(), ""); response.Code != http.StatusNotFound {
		t.Fatalf("absent credential read: %d", response.Code)
	}
	revoke := func(owner, id uuid.UUID, generation int64, want int) {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"credential_id": id, "expected_generation": generation})
		response := request("POST", owner, "revoke", string(body))
		if response.Code != want {
			t.Fatalf("revoke status %d, want %d: %s", response.Code, want, response.Body)
		}
	}
	revoke(other.ID, credential.ID, credential.RevocationGeneration, http.StatusConflict)
	revoke(principal.ID, credential.ID, credential.RevocationGeneration+1, http.StatusConflict)
	revoke(principal.ID, uuid.New(), credential.RevocationGeneration, http.StatusConflict)
	read(credential.ID, "active")
	revoke(principal.ID, credential.ID, credential.RevocationGeneration, http.StatusNoContent)
	read(credential.ID, "revoked")
	var firstRevokedAt, replayRevokedAt pgtype.Timestamptz
	if err := testPool.QueryRow(ctx, `SELECT revoked_at FROM machine_credential WHERE id=$1`, credential.ID).Scan(&firstRevokedAt); err != nil {
		t.Fatal(err)
	}
	revoke(principal.ID, credential.ID, credential.RevocationGeneration, http.StatusNoContent)
	if err := testPool.QueryRow(ctx, `SELECT revoked_at FROM machine_credential WHERE id=$1`, credential.ID).Scan(&replayRevokedAt); err != nil || !firstRevokedAt.Valid || firstRevokedAt != replayRevokedAt {
		t.Fatalf("replay changed revoke evidence: %v", err)
	}

	if err := testQueries.DisableMachinePrincipalFenced(ctx, principal.ID, db.LifecycleOptions{ExpectedGeneration: &principal.Generation, OperationID: uuid.New()}); err != nil {
		t.Fatal(err)
	}
	disabled, err := testQueries.GetMachinePrincipal(ctx, principal.ID)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := testQueries.RestoreMachineCredentialFenced(ctx, principal.ID, uuid.New(), []byte("reconciliation-restored-fixture"), time.Now().Add(time.Hour), []string{"sandbox:read"}, "sandbox-api", db.LifecycleOptions{ExpectedGeneration: &disabled.Generation, OperationID: uuid.New()})
	if err != nil {
		t.Fatal(err)
	}
	// A delayed revoke retry cleans up only its original target across restore.
	revoke(principal.ID, credential.ID, credential.RevocationGeneration, http.StatusNoContent)
	revoke(principal.ID, credential.ID, restored.RevocationGeneration, http.StatusConflict)
	read(credential.ID, "revoked")
	read(restored.ID, "active")
}

func TestMachineDisableFencesCredentialAcrossRotation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	team, _ := seedTeamAndKey(t)
	principal := machineRepairPrincipal(t, testQueries, team)
	credential := machineRepairIssue(t, testQueries, principal, uuid.New(), uuid.New(), "disable-predecessor-fixture")
	connection, err := testPool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	authority := api.NewDBMachineAuthority(db.New(connection))
	t.Setenv("OPERATOR_API_TOKEN", "disable-operator-fixture")
	router := api.SetupRouter(ctx, &api.Handlers{MachineCredentials: authority}, nil)
	disable := func(operation uuid.UUID, target *uuid.UUID) *httptest.ResponseRecorder {
		body := map[string]any{"operation_id": operation, "expected_generation": principal.Generation}
		if target != nil {
			body["expected_credential_id"] = *target
		}
		encoded, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/internal/machine-identity/principals/"+principal.ID.String()+"/disable", strings.NewReader(string(encoded))).WithContext(ctx)
		req.Header.Set("Authorization", "Bearer disable-operator-fixture")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		return response
	}

	// Rotation commits after the caller observed its predecessor, while disable
	// is already waiting on the same principal lock. Nested lifecycle work keeps
	// the real rotation transaction open until this test releases it.
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	successor, err := db.New(tx).RotateMachineCredentialTargeted(ctx, principal.ID, credential.ID, uuid.New(), []byte("disable-successor-fixture"), time.Now().Add(time.Hour), []string{"sandbox:read"}, "sandbox-api", db.LifecycleOptions{ExpectedGeneration: &principal.Generation, OperationID: uuid.New()})
	if err != nil {
		t.Fatal(err)
	}
	operation := uuid.New()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- disable(operation, &credential.ID) }()
	waitCtx, stopWait := context.WithTimeout(ctx, 3*time.Second)
	defer stopWait()
	for {
		var blocked bool
		if err := testPool.QueryRow(waitCtx, `SELECT cardinality(pg_blocking_pids($1)) > 0`, int32(connection.Conn().PgConn().PID())).Scan(&blocked); err != nil {
			t.Fatalf("disable did not wait for rotation lock: %v", err)
		}
		if blocked {
			break
		}
		select {
		case response := <-done:
			t.Fatalf("disable completed before rotation commit: %d", response.Code)
		case <-waitCtx.Done():
			t.Fatal("disable did not reach principal lock")
		case <-time.After(5 * time.Millisecond):
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	response := <-done
	if response.Code != http.StatusConflict {
		t.Fatalf("stale predecessor disabled successor: %d %s", response.Code, response.Body)
	}
	current, err := testQueries.GetMachinePrincipal(ctx, principal.ID)
	if err != nil || current.Status != "active" || current.Generation != principal.Generation {
		t.Fatalf("failed disable mutated principal: %+v %v", current, err)
	}
	row, err := testQueries.ReadMachineCredential(ctx, principal.ID, successor.ID)
	if err != nil || row.State != "active" {
		t.Fatalf("successor was revoked: %+v %v", row, err)
	}
	// A rejected attempt consumes no operation ID. A new observation can use it.
	response = disable(operation, &successor.ID)
	if response.Code != http.StatusNoContent {
		t.Fatalf("current credential disable: %d %s", response.Code, response.Body)
	}
	disabled, err := testQueries.GetMachinePrincipal(ctx, principal.ID)
	if err != nil || disabled.Status != "disabled" || disabled.Generation != principal.Generation+1 {
		t.Fatalf("disable result: %+v %v", disabled, err)
	}
	if response := disable(operation, &successor.ID); response.Code != http.StatusNoContent {
		t.Fatalf("exact replay after revoke: %d", response.Code)
	}
	for _, target := range []*uuid.UUID{&credential.ID, nil} {
		if response := disable(operation, target); response.Code != http.StatusConflict {
			t.Fatalf("changed replay target accepted: %d", response.Code)
		}
	}
	restored, err := testQueries.RestoreMachineCredentialFenced(ctx, principal.ID, uuid.New(), []byte("disable-restored-fixture"), time.Now().Add(time.Hour), []string{"sandbox:read"}, "sandbox-api", db.LifecycleOptions{ExpectedGeneration: &disabled.Generation, OperationID: uuid.New()})
	if err != nil {
		t.Fatal(err)
	}
	if response := disable(operation, &successor.ID); response.Code != http.StatusNoContent {
		t.Fatalf("exact replay after restore: %d", response.Code)
	}
	current, err = testQueries.GetMachinePrincipal(ctx, principal.ID)
	if err != nil || current.Status != "active" || current.Generation != restored.RevocationGeneration {
		t.Fatalf("replay disabled restored principal: %+v %v", current, err)
	}
}
