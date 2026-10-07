//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/auth"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/preview"
)

func machineRepairPrincipal(t *testing.T, q *db.Queries, teamID uuid.UUID) db.MachinePrincipalRow {
	t.Helper()
	row, err := q.EnsureMachinePrincipal(context.Background(), teamID, uuid.New(), pgtype.UUID{})
	if err != nil {
		t.Fatalf("ensure machine principal: %v", err)
	}
	return row
}

func machineRepairIssue(t *testing.T, q *db.Queries, principal db.MachinePrincipalRow, operationID, lineageID uuid.UUID, secret string) db.MachineCredentialRow {
	t.Helper()
	row, err := q.IssueMachineCredentialFenced(context.Background(), principal.ID, lineageID, []byte(secret), time.Unix(2_000_000_000, 0), []string{"sandbox:read", "command:run"}, "sandbox-api", db.LifecycleOptions{
		ExpectedGeneration: &principal.Generation,
		OperationID:        operationID,
	})
	if err != nil {
		t.Fatalf("issue machine credential: %v", err)
	}
	return row
}

func TestMachineRepairDurableAuthoritySQL(t *testing.T) {
	ctx := context.Background()
	q := db.New(testPool)
	teamID, _ := seedTeamAndKey(t)
	if _, err := testPool.Exec(ctx, `UPDATE team SET max_sandboxes = 1000 WHERE id = $1`, teamID); err != nil {
		t.Fatalf("raise test team sandbox limit: %v", err)
	}

	principal := machineRepairPrincipal(t, q, teamID)
	if again, err := q.EnsureMachinePrincipal(ctx, teamID, principal.HostedTenantID, pgtype.UUID{}); err != nil || again.ID != principal.ID {
		t.Fatalf("idempotent principal ensure = %#v, err=%v", again, err)
	}
	otherTeam, _ := seedTeamAndKey(t)
	if _, err := q.EnsureMachinePrincipal(ctx, otherTeam, principal.HostedTenantID, pgtype.UUID{}); err == nil {
		t.Fatal("tenant was reassigned to a different team")
	}

	issueOp := uuid.New()
	credential := machineRepairIssue(t, q, principal, issueOp, uuid.New(), "issue-secret-1")
	replay := machineRepairIssue(t, q, principal, issueOp, credential.LineageID, "issue-secret-1")
	if replay.ID != credential.ID {
		t.Fatalf("response-loss replay returned credential %s, want %s", replay.ID, credential.ID)
	}
	if _, err := q.IssueMachineCredentialFenced(ctx, principal.ID, uuid.New(), []byte("conflicting-secret"), time.Now().Add(time.Hour), []string{"sandbox:read", "command:run"}, "sandbox-api", db.LifecycleOptions{ExpectedGeneration: &principal.Generation, OperationID: issueOp}); err == nil {
		t.Fatal("conflicting operation reuse succeeded")
	}

	var operationsBefore, credentialsBefore int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM machine_lifecycle_operation WHERE principal_id=$1`, principal.ID).Scan(&operationsBefore); err != nil {
		t.Fatalf("count lifecycle operations: %v", err)
	}
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM machine_credential WHERE principal_id=$1`, principal.ID).Scan(&credentialsBefore); err != nil {
		t.Fatalf("count credentials: %v", err)
	}
	if _, err := q.IssueMachineCredentialFenced(ctx, principal.ID, uuid.New(), []byte("rollback-secret"), time.Now().Add(time.Hour), nil, "sandbox-api", db.LifecycleOptions{ExpectedGeneration: &principal.Generation, OperationID: uuid.New()}); err == nil {
		t.Fatal("invalid empty permission set was accepted")
	}
	var operationsAfter, credentialsAfter int
	_ = testPool.QueryRow(ctx, `SELECT count(*) FROM machine_lifecycle_operation WHERE principal_id=$1`, principal.ID).Scan(&operationsAfter)
	_ = testPool.QueryRow(ctx, `SELECT count(*) FROM machine_credential WHERE principal_id=$1`, principal.ID).Scan(&credentialsAfter)
	if operationsAfter != operationsBefore || credentialsAfter != credentialsBefore {
		t.Fatalf("failed issuance wrote durable state: operations %d->%d credentials %d->%d", operationsBefore, operationsAfter, credentialsBefore, credentialsAfter)
	}

	// Two callers using the same operation key must converge on one durable
	// result, even when the response to the first caller is lost.
	duplicateOp := uuid.New()
	duplicateLineage := uuid.New()
	secret := []byte("duplicate-secret")
	var wg sync.WaitGroup
	rows := make([]db.MachineCredentialRow, 2)
	errs := make([]error, 2)
	for i := range rows {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rows[i], errs[i] = q.IssueMachineCredentialFenced(ctx, principal.ID, duplicateLineage, secret, time.Unix(2_000_000_000, 0), []string{"sandbox:read"}, "sandbox-api", db.LifecycleOptions{ExpectedGeneration: &principal.Generation, OperationID: duplicateOp})
		}(i)
	}
	wg.Wait()
	if errs[0] != nil || errs[1] != nil || rows[0].ID == uuid.Nil || rows[0].ID != rows[1].ID {
		t.Fatalf("concurrent duplicate issuance rows=%#v errors=%v", rows, errs)
	}
	var duplicateCount int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM machine_credential WHERE principal_id=$1 AND secret_hash=$2`, principal.ID, secret).Scan(&duplicateCount); err != nil {
		t.Fatalf("count duplicate credentials: %v", err)
	}
	if duplicateCount != 1 {
		t.Fatalf("duplicate issuance created %d credentials", duplicateCount)
	}

	second := machineRepairIssue(t, q, principal, uuid.New(), uuid.New(), "sibling-secret")
	rotated := func() db.MachineCredentialRow {
		row, err := q.RotateMachineCredentialTargeted(ctx, principal.ID, credential.ID, uuid.New(), []byte("rotated-secret"), time.Now().Add(time.Hour), []string{"sandbox:read"}, "sandbox-api", db.LifecycleOptions{ExpectedGeneration: &principal.Generation, OperationID: uuid.New()})
		if err != nil {
			t.Fatalf("targeted rotation: %v", err)
		}
		return row
	}()
	if rotated.ID == credential.ID {
		t.Fatal("targeted rotation reused the revoked credential row")
	}
	var oldState, siblingState string
	if err := testPool.QueryRow(ctx, `SELECT state FROM machine_credential WHERE id=$1`, credential.ID).Scan(&oldState); err != nil {
		t.Fatal(err)
	}
	if err := testPool.QueryRow(ctx, `SELECT state FROM machine_credential WHERE id=$1`, second.ID).Scan(&siblingState); err != nil {
		t.Fatal(err)
	}
	if oldState != "revoked" || siblingState != "active" {
		t.Fatalf("rotation states old=%q sibling=%q", oldState, siblingState)
	}

	if err := q.DisableMachinePrincipalFenced(ctx, principal.ID, db.LifecycleOptions{ExpectedGeneration: &principal.Generation, OperationID: uuid.New()}); err != nil {
		t.Fatalf("disable principal: %v", err)
	}
	if _, err := q.LookupMachineCredentialByHash(ctx, []byte("issue-secret-1")); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("disabled credential lookup err=%v, want no rows", err)
	}
	if _, err := q.IssueMachineCredentialFenced(ctx, principal.ID, uuid.New(), []byte("disabled-secret"), time.Now().Add(time.Hour), []string{"sandbox:read"}, "sandbox-api", db.LifecycleOptions{ExpectedGeneration: &principal.Generation, OperationID: uuid.New()}); err == nil {
		t.Fatal("issuance succeeded against disabled generation")
	}

	disabled, err := q.GetMachinePrincipal(ctx, principal.ID)
	if err != nil {
		t.Fatal(err)
	}
	restoreOp := uuid.New()
	restoreLineage := uuid.New()
	restoreExpiry := time.Unix(2_000_100_000, 0)
	restored, err := q.RestoreMachineCredentialFenced(ctx, principal.ID, restoreLineage, []byte("restored-secret"), restoreExpiry, []string{"sandbox:read"}, "sandbox-api", db.LifecycleOptions{ExpectedGeneration: &disabled.Generation, OperationID: restoreOp})
	if err != nil {
		t.Fatalf("restore credential: %v", err)
	}
	restoredReplay, err := q.RestoreMachineCredentialFenced(ctx, principal.ID, restoreLineage, []byte("restored-secret"), restoreExpiry, []string{"sandbox:read"}, "sandbox-api", db.LifecycleOptions{ExpectedGeneration: &disabled.Generation, OperationID: restoreOp})
	if err != nil || restoredReplay.ID != restored.ID {
		t.Fatalf("restore replay row=%#v err=%v", restoredReplay, err)
	}
	if err := q.DisableMachinePrincipalFenced(ctx, principal.ID, db.LifecycleOptions{ExpectedGeneration: &restored.RevocationGeneration, OperationID: uuid.New()}); err != nil {
		t.Fatalf("disable after restore: %v", err)
	}
	stale, err := q.RestoreMachineCredentialFenced(ctx, principal.ID, restoreLineage, []byte("restored-secret"), restoreExpiry, []string{"sandbox:read"}, "sandbox-api", db.LifecycleOptions{ExpectedGeneration: &disabled.Generation, OperationID: restoreOp})
	if err != nil || stale.State != "revoked" {
		t.Fatalf("stale restore replay row=%#v err=%v; newer disable must remain authoritative", stale, err)
	}
	latest, err := q.GetMachinePrincipal(ctx, principal.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE machine_principal SET restore_until=now()-interval '1 second' WHERE id=$1`, principal.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := q.RestoreMachineCredentialFenced(ctx, principal.ID, uuid.New(), []byte("expired-restore"), time.Now().Add(time.Hour), []string{"sandbox:read"}, "sandbox-api", db.LifecycleOptions{ExpectedGeneration: &latest.Generation, OperationID: uuid.New()}); err == nil {
		t.Fatal("restore succeeded after recovery deadline")
	}

	// An issue racing a disable either observes the old generation and is
	// revoked by the disable, or observes the new generation and is rejected;
	// it must never leave an active credential behind the durable disable.
	racePrincipal := machineRepairPrincipal(t, q, teamID)
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	raceTx, err := testPool.Begin(raceCtx)
	if err != nil {
		t.Fatalf("begin issue/disable fence transaction: %v", err)
	}
	if _, err := raceTx.Exec(raceCtx, `SELECT generation FROM machine_principal WHERE id=$1 FOR UPDATE`, racePrincipal.ID); err != nil {
		raceTx.Rollback(raceCtx)
		t.Fatalf("lock principal for issue/disable fence: %v", err)
	}
	issueStarted := make(chan struct{})
	disableStarted := make(chan struct{})
	issueDone := make(chan error, 1)
	disableDone := make(chan error, 1)
	go func() {
		close(issueStarted)
		_, err := q.IssueMachineCredentialFenced(raceCtx, racePrincipal.ID, uuid.New(), []byte("race-secret"), time.Unix(2_000_000_000, 0), []string{"sandbox:read"}, "sandbox-api", db.LifecycleOptions{ExpectedGeneration: &racePrincipal.Generation, OperationID: uuid.New()})
		issueDone <- err
	}()
	go func() {
		close(disableStarted)
		disableDone <- q.DisableMachinePrincipalFenced(raceCtx, racePrincipal.ID, db.LifecycleOptions{ExpectedGeneration: &racePrincipal.Generation, OperationID: uuid.New()})
	}()
	<-issueStarted
	<-disableStarted
	if err := raceTx.Commit(raceCtx); err != nil {
		t.Fatalf("release issue/disable fence lock: %v", err)
	}
	<-issueDone
	if err := <-disableDone; err != nil {
		t.Fatalf("disable in issue/disable race: %v", err)
	}
	var activeAfterDisable int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM machine_credential WHERE principal_id=$1 AND state='active'`, racePrincipal.ID).Scan(&activeAfterDisable); err != nil || activeAfterDisable != 0 {
		t.Fatalf("issue/disable race left active durable credential: count=%d err=%v", activeAfterDisable, err)
	}
	if _, err := q.LookupMachineCredentialByHash(ctx, []byte("race-secret")); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("issue/disable race left usable credential: %v", err)
	}
}

func TestMachineRepairOwnerPagination(t *testing.T) {
	ctx := context.Background()
	q := db.New(testPool)
	teamID, _ := seedTeamAndKey(t)
	if _, err := testPool.Exec(ctx, `UPDATE team SET max_sandboxes = 1000 WHERE id = $1`, teamID); err != nil {
		t.Fatalf("raise test team sandbox limit: %v", err)
	}
	ownerA := machineRepairPrincipal(t, q, teamID)
	ownerB := machineRepairPrincipal(t, q, teamID)
	const total = 220
	for i := 0; i < total; i++ {
		sandboxID := uuid.New()
		if _, err := q.CreateSandbox(ctx, db.CreateSandboxParams{ID: sandboxID, TeamID: teamID, Name: fmt.Sprintf("machine-repair-%03d", i), Status: db.SandboxStatusActive, VcpuCount: 1, MemoryMib: 1, HostID: testDefaultHostID, Metadata: []byte(`{}`), PreviewAccess: preview.AccessPublic}); err != nil {
			t.Fatalf("create sandbox %d: %v", i, err)
		}
		owner := ownerA.ID
		if i%2 == 1 {
			owner = ownerB.ID
		}
		if err := q.CreateMachineSandboxOwner(ctx, sandboxID, owner, teamID); err != nil {
			t.Fatalf("publish owner %d: %v", i, err)
		}
	}
	firstRows, err := q.ListSandboxesByMachineOwner(ctx, db.ListSandboxesByMachineOwnerParams{TeamID: teamID, OwnerPrincipalID: ownerA.ID, Metadata: []byte(`{}`), SortBy: "name", SortDir: "asc", RowLimit: func() *int64 { n := int64(1); return &n }()})
	if err != nil || len(firstRows) != 1 {
		t.Fatalf("find owner row for immutability checks: rows=%d err=%v", len(firstRows), err)
	}
	if err := q.CreateMachineSandboxOwner(ctx, firstRows[0].Sandbox.ID, ownerB.ID, teamID); err == nil {
		t.Fatal("machine ownership row was reassigned")
	}
	foreignTeam, _ := seedTeamAndKey(t)
	foreignPrincipal := machineRepairPrincipal(t, q, foreignTeam)
	if err := q.CreateMachineSandboxOwner(ctx, firstRows[0].Sandbox.ID, foreignPrincipal.ID, foreignTeam); err == nil {
		t.Fatal("cross-team sandbox ownership row was accepted")
	}

	pageSize := int64(25)
	rows, err := q.ListSandboxesByMachineOwner(ctx, db.ListSandboxesByMachineOwnerParams{TeamID: teamID, OwnerPrincipalID: ownerA.ID, Metadata: []byte(`{}`), SortBy: "name", SortDir: "asc", RowLimit: &pageSize})
	if err != nil {
		t.Fatalf("owner page: %v", err)
	}
	if len(rows) != int(pageSize) {
		t.Fatalf("owner page size=%d, want %d", len(rows), pageSize)
	}
	for _, row := range rows {
		var owner uuid.UUID
		if err := testPool.QueryRow(ctx, `SELECT owner_principal_id FROM sandbox_machine_owner WHERE sandbox_id=$1`, row.Sandbox.ID).Scan(&owner); err != nil {
			t.Fatal(err)
		}
		if owner != ownerA.ID {
			t.Fatalf("page returned sandbox owned by %s, want %s", owner, ownerA.ID)
		}
	}
	totalOwned, err := q.CountSandboxesByMachineOwner(ctx, db.CountSandboxesByMachineOwnerParams{TeamID: teamID, OwnerPrincipalID: ownerA.ID, Metadata: []byte(`{}`)})
	if err != nil || totalOwned != total/2 {
		t.Fatalf("owned total=%d err=%v, want %d", totalOwned, err, total/2)
	}
	offset := int64(100)
	rows, err = q.ListSandboxesByMachineOwner(ctx, db.ListSandboxesByMachineOwnerParams{TeamID: teamID, OwnerPrincipalID: ownerA.ID, Metadata: []byte(`{}`), SortBy: "name", SortDir: "asc", RowOffset: &offset, RowLimit: &pageSize})
	if err != nil || len(rows) != 10 {
		t.Fatalf("owner offset page len=%d err=%v, want 10", len(rows), err)
	}
	rows, err = q.ListSandboxesByMachineOwner(ctx, db.ListSandboxesByMachineOwnerParams{TeamID: teamID, OwnerPrincipalID: ownerA.ID, Metadata: []byte(`{}`), SortBy: "name", SortDir: "asc"})
	if err != nil || len(rows) != total/2 {
		t.Fatalf("omitted-limit owner rows=%d err=%v, want %d", len(rows), err, total/2)
	}
	// Human team queries still see both principals' rows; machine ownership is
	// an additional relation, not a change to ordinary team authorization.
	humanRows, err := q.ListSandboxesByTeamCreatedDesc(ctx, db.ListSandboxesByTeamCreatedDescParams{TeamID: teamID, Metadata: []byte(`{}`)})
	if err != nil || len(humanRows) != total {
		t.Fatalf("human team rows=%d err=%v, want %d", len(humanRows), err, total)
	}
}

// Advancing the adapter clock models a response lost across expiry boundaries
// without delaying the test or changing the durable database clock.
func TestMachineRepairLifecycleRetryBoundaries(t *testing.T) {
	ctx := api.WithControlPlaneAuthorization(context.Background())
	q := db.New(testPool)
	teamID, _ := seedTeamAndKey(t)
	principal := machineRepairPrincipal(t, q, teamID)
	authority := api.NewDBMachineAuthority(q)
	authority.Enable()
	authority.SetEligibility(api.AuthorityEligibility{ContractRevision: "machine-identity-v1", Environment: "test", ConfiguredEnvironment: "test", SchemaReady: true, OwnershipReady: true, VerifierReady: true, OperatorReady: true})
	now := time.Now().UTC()
	authority.Now = func() time.Time { return now }
	issueOp, rotateOp, restoreOp := uuid.New(), uuid.New(), uuid.New()
	issued, err := authority.IssueCredentialFenced(ctx, principal.ID, "retry-issue-secret", principal.Generation, issueOp)
	if err != nil {
		t.Fatal(err)
	}
	assertSame := func(want, got auth.MachineCredential, err error) {
		t.Helper()
		if err != nil || got.CredentialID != want.CredentialID || !got.ExpiresAt.Equal(want.ExpiresAt) || got.RevocationGeneration != want.RevocationGeneration {
			t.Fatalf("retry changed persisted result: want=%+v got=%+v err=%v", want, got, err)
		}
	}
	for _, advance := range []time.Duration{time.Hour, 25 * time.Hour} {
		now = now.Add(advance)
		got, err := authority.IssueCredentialFenced(ctx, principal.ID, "retry-issue-secret", principal.Generation, issueOp)
		assertSame(issued, got, err)
	}
	if _, err := authority.IssueCredentialFenced(ctx, principal.ID, "conflicting-retry-secret", principal.Generation, issueOp); !errors.Is(err, db.ErrMachineLifecycleConflict) {
		t.Fatalf("conflicting issue retry: %v", err)
	}
	rotated, err := authority.RotateCredentialFenced(ctx, principal.ID, issued.CredentialID, "retry-rotate-secret", principal.Generation, rotateOp)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(25 * time.Hour)
	got, err := authority.RotateCredentialFenced(ctx, principal.ID, issued.CredentialID, "retry-rotate-secret", principal.Generation, rotateOp)
	assertSame(rotated, got, err)
	if err := authority.DisablePrincipalFenced(ctx, principal.ID, principal.Generation, uuid.New()); err != nil {
		t.Fatal(err)
	}
	got, err = authority.IssueCredentialFenced(ctx, principal.ID, "retry-issue-secret", principal.Generation, issueOp)
	assertSame(issued, got, err)
	if got.State != auth.CredentialState("revoked") {
		t.Fatalf("post-disable issue replay state=%s", got.State)
	}
	got, err = authority.RotateCredentialFenced(ctx, principal.ID, issued.CredentialID, "retry-rotate-secret", principal.Generation, rotateOp)
	assertSame(rotated, got, err)
	if got.State != auth.CredentialState("revoked") {
		t.Fatalf("post-disable rotation replay state=%s", got.State)
	}
	disabled, err := q.GetMachinePrincipal(ctx, principal.ID)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := authority.RestorePrincipalFenced(ctx, principal.ID, "retry-restore-secret", disabled.Generation, restoreOp)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(25 * time.Hour)
	got, err = authority.RestorePrincipalFenced(ctx, principal.ID, "retry-restore-secret", disabled.Generation, restoreOp)
	assertSame(restored, got, err)
	if err := authority.DisablePrincipalFenced(ctx, principal.ID, int64(restored.RevocationGeneration), uuid.New()); err != nil {
		t.Fatal(err)
	}
	got, err = authority.RestorePrincipalFenced(ctx, principal.ID, "retry-restore-secret", disabled.Generation, restoreOp)
	assertSame(restored, got, err)
	if got.State != auth.CredentialState("revoked") {
		t.Fatalf("post-disable restore replay state=%s", got.State)
	}
}

type machineNontransactionDB struct{ db.DBTX }

func TestMachineLifecycleAtomicRollbackAndTransactionRequirement(t *testing.T) {
	ctx := context.Background()
	q := db.New(testPool)
	teamID, _ := seedTeamAndKey(t)
	principal := machineRepairPrincipal(t, q, teamID)
	credential := machineRepairIssue(t, q, principal, uuid.New(), uuid.New(), "atomic-source")
	expires := time.Now().Add(time.Hour)
	rotateOp := uuid.New()
	if _, err := q.RotateMachineCredentialTargeted(ctx, principal.ID, credential.ID, uuid.New(), []byte("atomic-rotation"), expires, nil, "sandbox-api", db.LifecycleOptions{ExpectedGeneration: &principal.Generation, OperationID: rotateOp}); err == nil {
		t.Fatal("invalid rotation succeeded")
	}
	if _, err := q.LookupMachineCredentialByHash(ctx, []byte("atomic-source")); err != nil {
		t.Fatalf("failed rotation revoked source: %v", err)
	}
	if err := q.DisableMachinePrincipalFenced(ctx, principal.ID, db.LifecycleOptions{ExpectedGeneration: &principal.Generation, OperationID: uuid.New()}); err != nil {
		t.Fatal(err)
	}
	disabled, err := q.GetMachinePrincipal(ctx, principal.ID)
	if err != nil {
		t.Fatal(err)
	}
	restoreOp := uuid.New()
	if _, err := q.RestoreMachineCredentialFenced(ctx, principal.ID, uuid.New(), []byte("atomic-restore"), expires, nil, "sandbox-api", db.LifecycleOptions{ExpectedGeneration: &disabled.Generation, OperationID: restoreOp}); err == nil {
		t.Fatal("invalid restore succeeded")
	}
	after, err := q.GetMachinePrincipal(ctx, principal.ID)
	if err != nil || after.Status != "disabled" || after.Generation != disabled.Generation {
		t.Fatalf("failed restore changed principal: %+v %v", after, err)
	}
	var count int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM machine_lifecycle_operation WHERE principal_id=$1 AND operation_id IN ($2,$3)`, principal.ID, rotateOp, restoreOp).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed operations persisted: %d %v", count, err)
	}

	unsupported := db.New(machineNontransactionDB{DBTX: testPool})
	fence := db.LifecycleOptions{ExpectedGeneration: &disabled.Generation, OperationID: uuid.New()}
	if _, err := unsupported.IssueMachineCredentialFenced(ctx, principal.ID, uuid.New(), []byte("unsupported"), expires, []string{"sandbox:read"}, "sandbox-api", fence); err == nil {
		t.Fatal("issue without transaction succeeded")
	}
	if _, err := unsupported.RotateMachineCredentialTargeted(ctx, principal.ID, credential.ID, uuid.New(), []byte("unsupported"), expires, []string{"sandbox:read"}, "sandbox-api", fence); err == nil {
		t.Fatal("rotate without transaction succeeded")
	}
	if _, err := unsupported.RestoreMachineCredentialFenced(ctx, principal.ID, uuid.New(), []byte("unsupported"), expires, []string{"sandbox:read"}, "sandbox-api", fence); err == nil {
		t.Fatal("restore without transaction succeeded")
	}
}

func TestMachineLifecycleConcurrentRetries(t *testing.T) {
	ctx := context.Background()
	q := db.New(testPool)
	teamID, _ := seedTeamAndKey(t)
	principal := machineRepairPrincipal(t, q, teamID)
	original := machineRepairIssue(t, q, principal, uuid.New(), uuid.New(), "concurrent-original")
	expires := time.Now().Add(time.Hour).Truncate(time.Microsecond)
	rotateOp, rotateLineage := uuid.New(), uuid.New()
	concurrent := func(invoke func() (db.MachineCredentialRow, error)) db.MachineCredentialRow {
		t.Helper()
		start := make(chan struct{})
		rows := make([]db.MachineCredentialRow, 2)
		errs := make([]error, 2)
		var wg sync.WaitGroup
		for i := range rows {
			wg.Add(1)
			go func(i int) { defer wg.Done(); <-start; rows[i], errs[i] = invoke() }(i)
		}
		close(start)
		wg.Wait()
		if errs[0] != nil || errs[1] != nil || rows[0].ID == uuid.Nil || rows[0].ID != rows[1].ID {
			t.Fatalf("concurrent retries disagree: rows=%+v errors=%v", rows, errs)
		}
		return rows[0]
	}
	rotate := func(expiry time.Time) (db.MachineCredentialRow, error) {
		return q.RotateMachineCredentialTargeted(ctx, principal.ID, original.ID, rotateLineage, []byte("concurrent-rotated"), expiry, []string{"sandbox:read"}, "sandbox-api", db.LifecycleOptions{ExpectedGeneration: &principal.Generation, OperationID: rotateOp})
	}
	concurrent(func() (db.MachineCredentialRow, error) { return rotate(expires) })
	if _, err := rotate(expires.Add(time.Hour)); !errors.Is(err, db.ErrMachineLifecycleConflict) {
		t.Fatalf("changed caller expiry accepted: %v", err)
	}
	if err := q.DisableMachinePrincipalFenced(ctx, principal.ID, db.LifecycleOptions{ExpectedGeneration: &principal.Generation, OperationID: uuid.New()}); err != nil {
		t.Fatal(err)
	}
	disabled, err := q.GetMachinePrincipal(ctx, principal.ID)
	if err != nil {
		t.Fatal(err)
	}
	restoreOp, restoreLineage := uuid.New(), uuid.New()
	restored := concurrent(func() (db.MachineCredentialRow, error) {
		return q.RestoreMachineCredentialFenced(ctx, principal.ID, restoreLineage, []byte("concurrent-restored"), expires, []string{"sandbox:read"}, "sandbox-api", db.LifecycleOptions{ExpectedGeneration: &disabled.Generation, OperationID: restoreOp})
	})
	if restored.RevocationGeneration != disabled.Generation+1 {
		t.Fatalf("restore incremented generation more than once: %+v", restored)
	}
}

func TestMachineDisableRetryCannotDisableRestoredGeneration(t *testing.T) {
	ctx := context.Background()
	q := db.New(testPool)
	teamID, _ := seedTeamAndKey(t)
	principal := machineRepairPrincipal(t, q, teamID)
	issueOp := uuid.New()
	machineRepairIssue(t, q, principal, issueOp, uuid.New(), "disable-original")
	disableOp := uuid.New()
	fence := db.LifecycleOptions{ExpectedGeneration: &principal.Generation, OperationID: disableOp}
	if err := q.DisableMachinePrincipalFenced(ctx, principal.ID, fence); err != nil {
		t.Fatal(err)
	}
	if err := q.DisableMachinePrincipalFenced(ctx, principal.ID, fence); err != nil {
		t.Fatalf("immediate replay: %v", err)
	}
	disabled, err := q.GetMachinePrincipal(ctx, principal.ID)
	if err != nil || disabled.Generation != principal.Generation+1 {
		t.Fatalf("disable repeated transition: %+v %v", disabled, err)
	}
	restored, err := q.RestoreMachineCredentialFenced(ctx, principal.ID, uuid.New(), []byte("disable-restored"), time.Now().Add(time.Hour), []string{"sandbox:read"}, "sandbox-api", db.LifecycleOptions{ExpectedGeneration: &disabled.Generation, OperationID: uuid.New()})
	if err != nil {
		t.Fatal(err)
	}
	// Re-delivering the original disable after restore only acknowledges its
	// committed operation. It must not apply to the new principal generation.
	if err := q.DisableMachinePrincipalFenced(ctx, principal.ID, fence); err != nil {
		t.Fatalf("delayed disable replay: %v", err)
	}
	current, err := q.GetMachinePrincipal(ctx, principal.ID)
	if err != nil || current.Status != "active" || current.Generation != restored.RevocationGeneration {
		t.Fatalf("delayed disable changed restored principal: %+v %v", current, err)
	}
	if _, err := q.LookupMachineCredentialByHash(ctx, []byte("disable-restored")); err != nil {
		t.Fatalf("delayed disable revoked restored credential: %v", err)
	}
	if err := q.DisableMachinePrincipalFenced(ctx, principal.ID, db.LifecycleOptions{ExpectedGeneration: &current.Generation, OperationID: disableOp}); !errors.Is(err, db.ErrMachineLifecycleConflict) {
		t.Fatalf("reusing operation for new generation: %v", err)
	}
	if err := q.DisableMachinePrincipalFenced(ctx, principal.ID, db.LifecycleOptions{ExpectedGeneration: &current.Generation, OperationID: issueOp}); !errors.Is(err, db.ErrMachineLifecycleConflict) {
		t.Fatalf("reusing issue operation as disable: %v", err)
	}
	if err := q.DisableMachinePrincipalFenced(ctx, principal.ID, db.LifecycleOptions{ExpectedGeneration: &principal.Generation, OperationID: uuid.New()}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("fresh operation with stale generation: %v", err)
	}
	if err := q.DisableMachinePrincipal(ctx, principal.ID); err == nil {
		t.Fatal("unfenced disable succeeded")
	}
	if _, err := q.LookupMachineCredentialByHash(ctx, []byte("disable-restored")); err != nil {
		t.Fatalf("conflicting disable revoked credential: %v", err)
	}
}
