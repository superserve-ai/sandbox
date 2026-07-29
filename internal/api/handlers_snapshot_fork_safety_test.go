package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/db"
)

type forkSecretIDRows struct {
	ids []uuid.UUID
	idx int
}

func (r *forkSecretIDRows) Close()                                       {}
func (r *forkSecretIDRows) Err() error                                   { return nil }
func (r *forkSecretIDRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *forkSecretIDRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *forkSecretIDRows) Next() bool {
	if r.idx >= len(r.ids) {
		return false
	}
	r.idx++
	return true
}
func (r *forkSecretIDRows) Scan(dest ...any) error {
	*dest[0].(*uuid.UUID) = r.ids[r.idx-1]
	return nil
}
func (r *forkSecretIDRows) Values() ([]any, error) { return nil, nil }
func (r *forkSecretIDRows) RawValues() [][]byte    { return nil }
func (r *forkSecretIDRows) Conn() *pgx.Conn        { return nil }

func forkUUIDRow(id uuid.UUID) pgx.Row {
	return &mockRow{scanFn: func(dest ...any) error {
		*dest[0].(*uuid.UUID) = id
		return nil
	}}
}

func TestFailedForkCleanupRevocationPersistenceFailureFailsClosed(t *testing.T) {
	snapshotID := uuid.New()
	sandbox := db.Sandbox{
		ID:               uuid.New(),
		TeamID:           uuid.New(),
		SourceSnapshotID: pgtype.UUID{Bytes: snapshotID, Valid: true},
	}
	revocationErr := errors.New("revocation store unavailable")
	var (
		destroyCalled       bool
		directRevokeCalled  bool
		markedFailed        bool
		bindingsDeleted     bool
		pinReleaseAttempted bool
	)
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if strings.Contains(sql, "ReleaseDestroyedSandboxSnapshotPin") {
				pinReleaseAttempted = true
			}
			return notFoundRow()
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			switch {
			case strings.Contains(sql, "UpsertSandboxRevocation"):
				return pgconn.CommandTag{}, revocationErr
			case strings.Contains(sql, "MarkSandboxFailedInTeam"):
				markedFailed = true
				return pgconn.NewCommandTag("UPDATE 1"), nil
			case strings.Contains(sql, "DeleteSandboxSecrets"):
				bindingsDeleted = true
				return pgconn.NewCommandTag("DELETE 1"), nil
			default:
				t.Fatalf("unexpected DB exec during fail-closed cleanup: %s", sql)
				return pgconn.CommandTag{}, nil
			}
		},
	}
	vmd := &stubSavedSnapshotVMD{stubVMD: &stubVMD{
		revokeSandboxFn: func(_ context.Context, gotID string) error {
			if gotID != sandbox.ID.String() {
				t.Errorf("direct revoke sandbox ID = %q, want %q", gotID, sandbox.ID)
			}
			directRevokeCalled = true
			return nil
		},
		destroyFn: func(context.Context, string, bool) error {
			destroyCalled = true
			return nil
		},
	}}

	(&Handlers{DB: db.New(mock)}).cleanupFailedSavedSnapshotFork(context.Background(), vmd, sandbox)

	if !directRevokeCalled {
		t.Fatal("direct sandbox revocation was not attempted after persistence failure")
	}
	if !markedFailed {
		t.Fatal("failed fork was not retained and marked failed")
	}
	if destroyCalled {
		t.Fatal("host teardown ran without a durable revocation")
	}
	if bindingsDeleted {
		t.Fatal("secret bindings were deleted without a durable revocation")
	}
	if pinReleaseAttempted {
		t.Fatal("snapshot dependency pin was released without a durable revocation")
	}
}

func TestLockSavedSnapshotForkSecretsDeduplicatesIDsAndReportsMissingEnvKeys(t *testing.T) {
	teamID := uuid.New()
	availableID := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	missingID := uuid.MustParse("00000000-0000-0000-0000-000000000002")
	bindings := []db.AddSandboxSecretParams{
		{SecretID: missingID, EnvKey: "SECOND_TOKEN"},
		{SecretID: availableID, EnvKey: "AVAILABLE_TOKEN"},
		{SecretID: missingID, EnvKey: "FIRST_TOKEN"},
	}
	meta := []SecretBindingMeta{
		{SecretID: missingID, EnvKey: "SECOND_TOKEN"},
		{SecretID: availableID, EnvKey: "AVAILABLE_TOKEN"},
		{SecretID: missingID, EnvKey: "FIRST_TOKEN"},
	}
	var lockedArgs []uuid.UUID
	mock := &mockDBTX{
		queryFn: func(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
			if !strings.Contains(sql, "LockActiveTeamSecretIDs") {
				t.Fatalf("unexpected DB query: %s", sql)
			}
			if got := args[0].(uuid.UUID); got != teamID {
				t.Errorf("lock team ID = %s, want %s", got, teamID)
			}
			lockedArgs = append([]uuid.UUID(nil), args[1].([]uuid.UUID)...)
			return &forkSecretIDRows{ids: []uuid.UUID{availableID}}, nil
		},
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			t.Fatalf("unexpected DB row query: %s", sql)
			return notFoundRow()
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			t.Fatalf("unexpected DB exec: %s", sql)
			return pgconn.CommandTag{}, nil
		},
	}

	err := lockSavedSnapshotForkSecrets(context.Background(), db.New(mock), teamID, bindings, meta)
	var unavailable *savedSnapshotSecretUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("lock error = %v, want savedSnapshotSecretUnavailableError", err)
	}
	if want := []uuid.UUID{availableID, missingID}; !slices.Equal(lockedArgs, want) {
		t.Fatalf("locked secret IDs = %v, want deduplicated deterministic IDs %v", lockedArgs, want)
	}
	if want := []string{"FIRST_TOKEN", "SECOND_TOKEN"}; !slices.Equal(unavailable.EnvKeys, want) {
		t.Fatalf("missing env keys = %v, want %v", unavailable.EnvKeys, want)
	}
}

func TestCreateSandboxFromSavedSnapshotActivationFailureCompensatesBeforeTeardown(t *testing.T) {
	teamID := uuid.New()
	sourceID := uuid.New()
	snapshotID := uuid.New()
	hostID := "host-a"
	manifestPath := "/var/lib/superserve/snapshots/saved/" + sourceID.String() + "/" + snapshotID.String() + "/manifest.json"
	manifestDigest := strings.Repeat("b", 64)
	vcpu, memoryMiB, diskMiB := int32(2), int32(2048), int32(8192)
	saved := db.Snapshot{
		ID:             snapshotID,
		SandboxID:      sourceID,
		TeamID:         teamID,
		Kind:           db.SnapshotKindSaved,
		Status:         db.SnapshotStatusReady,
		Trigger:        "api",
		HostID:         &hostID,
		ManifestPath:   &manifestPath,
		ManifestDigest: &manifestDigest,
		VcpuCount:      &vcpu,
		MemoryMib:      &memoryMiB,
		DiskMib:        &diskMiB,
		SecretBindings: []byte(`[]`),
		CreatedAt:      time.Now().Add(-time.Minute),
		UpdatedAt:      time.Now(),
	}
	activationErr := errors.New("activation write failed")
	var (
		child       db.Sandbox
		events      []string
		bindingsNil bool
		pinReleased bool
	)
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "IsFeatureEnabledForTeam"):
				return boolRow(true)
			case strings.Contains(sql, "GetSavedSnapshot"):
				return savedSnapshotRow(saved)
			case strings.Contains(sql, "HostHasCapabilities"):
				return boolRow(true)
			case strings.Contains(sql, "CreateSandboxFromSnapshot"):
				child = db.Sandbox{
					ID:               args[2].(uuid.UUID),
					TeamID:           teamID,
					Name:             "forked",
					Status:           db.SandboxStatusStarting,
					VcpuCount:        vcpu,
					MemoryMib:        memoryMiB,
					DiskMib:          diskMiB,
					HostID:           hostID,
					SourceSnapshotID: pgtype.UUID{Bytes: snapshotID, Valid: true},
					CreatedAt:        time.Now(),
					UpdatedAt:        time.Now(),
				}
				return sandboxRow(child)
			case strings.Contains(sql, "ReleaseDestroyedSandboxSnapshotPin"):
				events = append(events, "release-pin")
				pinReleased = true
				return forkUUIDRow(child.ID)
			case strings.Contains(sql, "DestroySandbox"):
				events = append(events, "soft-delete")
				return forkUUIDRow(child.ID)
			default:
				t.Fatalf("unexpected DB row query: %s", sql)
				return notFoundRow()
			}
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			switch {
			case strings.Contains(sql, "ActivateSandbox"):
				events = append(events, "activate")
				return pgconn.CommandTag{}, activationErr
			case strings.Contains(sql, "UpsertSandboxRevocation"):
				events = append(events, "persist-revocation")
				return pgconn.NewCommandTag("INSERT 1"), nil
			case strings.Contains(sql, "DeleteSandboxSecrets"):
				events = append(events, "delete-bindings")
				bindingsNil = true
				return pgconn.NewCommandTag("DELETE 0"), nil
			case strings.Contains(sql, "MarkSandboxFailedInTeam"):
				t.Fatal("successfully compensated fork should not be marked failed")
				return pgconn.CommandTag{}, nil
			default:
				t.Fatalf("unexpected DB exec: %s", sql)
				return pgconn.CommandTag{}, nil
			}
		},
	}
	vmd := &stubSavedSnapshotVMD{stubVMD: &stubVMD{
		revokeSandboxFn: func(_ context.Context, gotID string) error {
			if gotID != child.ID.String() {
				t.Errorf("direct revoke sandbox ID = %q, want %q", gotID, child.ID)
			}
			events = append(events, "direct-revoke")
			return nil
		},
		destroyFn: func(_ context.Context, gotID string, force bool) error {
			if gotID != child.ID.String() || !force {
				t.Errorf("teardown = (%q, %v), want (%q, true)", gotID, force, child.ID)
			}
			events = append(events, "host-teardown")
			return nil
		},
	}}
	h := &Handlers{VMD: vmd, DB: db.New(mock)}

	w := httptest.NewRecorder()
	body := `{"name":"forked","from_snapshot":"` + snapshotID.String() + `"}`
	setupTestRouter(h, teamID.String()).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/sandboxes", strings.NewReader(body)))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", w.Code, w.Body.String())
	}
	if got := errorCode(parseJSON(t, w)); got != "internal_error" {
		t.Fatalf("error code = %q, want internal_error", got)
	}
	wantEvents := []string{
		"activate",
		"persist-revocation",
		"direct-revoke",
		"host-teardown",
		"soft-delete",
		"delete-bindings",
		"release-pin",
	}
	if !slices.Equal(events, wantEvents) {
		t.Fatalf("compensation events = %v, want %v", events, wantEvents)
	}
	if !bindingsNil || !pinReleased {
		t.Fatalf("completed compensation bindings_deleted=%v pin_released=%v, want both true", bindingsNil, pinReleased)
	}
}
