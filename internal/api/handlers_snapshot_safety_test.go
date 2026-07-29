package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/preview"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

type savedSnapshotTestVMD struct {
	*stubVMD
	checkFn   func(context.Context) error
	restoreFn func(context.Context, string, string, string, string, string, vmdclient.SavedSnapshotNetwork, []string, string, map[int32]vmdclient.PortPolicy, int64) (string, uint32, uint32, error)
	deleteFn  func(context.Context, string, string) error
	measureFn func(context.Context, string) (int64, int64, error)
	revokeFn  func(context.Context, string) error
}

func (s *savedSnapshotTestVMD) CheckSavedSnapshotSupport(ctx context.Context) error {
	if s.checkFn != nil {
		return s.checkFn(ctx)
	}
	return nil
}

func (s *savedSnapshotTestVMD) CreateSavedSnapshot(context.Context, string, string) (vmdclient.SavedSnapshotArtifacts, error) {
	return vmdclient.SavedSnapshotArtifacts{}, nil
}

func (s *savedSnapshotTestVMD) RestoreSavedSnapshot(
	ctx context.Context,
	instanceID, manifestPath, manifestDigest, teamID, ownerID string,
	network vmdclient.SavedSnapshotNetwork,
	clearEnvKeys []string,
	previewAccess string,
	previewPorts map[int32]vmdclient.PortPolicy,
	previewPolicyRevision int64,
) (string, uint32, uint32, error) {
	if s.restoreFn != nil {
		return s.restoreFn(
			ctx, instanceID, manifestPath, manifestDigest, teamID, ownerID,
			network, clearEnvKeys, previewAccess, previewPorts, previewPolicyRevision,
		)
	}
	return "10.0.0.8", 2, 2048, nil
}

func (s *savedSnapshotTestVMD) DeleteSavedSnapshot(ctx context.Context, sourceID, snapshotID string) error {
	if s.deleteFn != nil {
		return s.deleteFn(ctx, sourceID, snapshotID)
	}
	return nil
}

func (s *savedSnapshotTestVMD) MeasureSandboxWritableLayer(ctx context.Context, instanceID string) (int64, int64, error) {
	if s.measureFn != nil {
		return s.measureFn(ctx, instanceID)
	}
	return 0, 0, nil
}

func (s *savedSnapshotTestVMD) RevokeSandbox(ctx context.Context, sandboxID string) error {
	if s.revokeFn != nil {
		return s.revokeFn(ctx, sandboxID)
	}
	return nil
}

type exactSnapshotHostRegistry struct {
	clients   map[string]vmdclient.Client
	requested []string
}

func savedSnapshotDBRow(s db.Snapshot) pgx.Row {
	return &mockRow{scanFn: func(dest ...any) error {
		*dest[0].(*uuid.UUID) = s.ID
		*dest[1].(*uuid.UUID) = s.SandboxID
		*dest[2].(*uuid.UUID) = s.TeamID
		*dest[3].(*string) = s.Path
		*dest[4].(*int64) = s.SizeBytes
		*dest[5].(*string) = s.Trigger
		*dest[6].(*time.Time) = s.CreatedAt
		*dest[7].(**string) = s.MemPath
		*dest[8].(*db.SnapshotKind) = s.Kind
		*dest[9].(*db.SnapshotStatus) = s.Status
		*dest[10].(**string) = s.Name
		*dest[11].(**string) = s.IdempotencyKey
		*dest[12].(*pgtype.UUID) = s.ParentSnapshotID
		*dest[13].(*db.NullSandboxStatus) = s.SourceStatus
		*dest[14].(*pgtype.UUID) = s.TemplateID
		*dest[15].(**string) = s.TemplateSnapshotPath
		*dest[16].(**string) = s.TemplateMemPath
		*dest[17].(**string) = s.BasePath
		*dest[18].(**string) = s.DeltaPath
		*dest[19].(**string) = s.HostID
		*dest[20].(**int32) = s.VcpuCount
		*dest[21].(**int32) = s.MemoryMib
		*dest[22].(**int32) = s.DiskMib
		*dest[23].(**string) = s.ManifestPath
		*dest[24].(**string) = s.ManifestDigest
		*dest[25].(*[]byte) = s.ArtifactMetadata
		*dest[26].(*int64) = s.LogicalSizeBytes
		*dest[27].(*int64) = s.ExclusiveSizeBytes
		*dest[28].(*[]byte) = s.NetworkConfig
		*dest[29].(**int32) = s.TimeoutSeconds
		*dest[30].(**int32) = s.AutoDeleteSeconds
		*dest[31].(*[]byte) = s.SecretBindings
		*dest[32].(*[]byte) = s.SecretEnvKeys
		*dest[33].(**string) = s.FailureReason
		*dest[34].(*time.Time) = s.UpdatedAt
		*dest[35].(*pgtype.Timestamptz) = s.FinalizedAt
		*dest[36].(*pgtype.Timestamptz) = s.DeletedAt
		return nil
	}}
}

func validSavedSnapshotForkFixture(snapshotID, sourceID, teamID uuid.UUID, hostID string) db.Snapshot {
	vcpu, memoryMiB, diskMiB := int32(2), int32(2048), int32(8192)
	manifestPath := "/var/lib/superserve/saved/manifest.json"
	manifestDigest := strings.Repeat("a", 64)
	now := time.Now()
	return db.Snapshot{
		ID:                 snapshotID,
		SandboxID:          sourceID,
		TeamID:             teamID,
		Kind:               db.SnapshotKindSaved,
		Status:             db.SnapshotStatusReady,
		HostID:             &hostID,
		VcpuCount:          &vcpu,
		MemoryMib:          &memoryMiB,
		DiskMib:            &diskMiB,
		ManifestPath:       &manifestPath,
		ManifestDigest:     &manifestDigest,
		NetworkConfig:      []byte(`{}`),
		SecretBindings:     []byte(`[]`),
		SecretEnvKeys:      []byte(`[]`),
		CreatedAt:          now,
		UpdatedAt:          now,
		ArtifactMetadata:   []byte(`{}`),
		LogicalSizeBytes:   1,
		ExclusiveSizeBytes: 1,
	}
}

func (r *exactSnapshotHostRegistry) ClientFor(_ context.Context, hostID string) (vmdclient.Client, error) {
	r.requested = append(r.requested, hostID)
	client, ok := r.clients[hostID]
	if !ok {
		return nil, pgx.ErrNoRows
	}
	return client, nil
}

func TestSnapshotVMDForHostUsesRecordedHostWithoutDefaultFallback(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var recordedDeletes, defaultDeletes int
	recorded := &savedSnapshotTestVMD{
		stubVMD: &stubVMD{},
		deleteFn: func(context.Context, string, string) error {
			recordedDeletes++
			return nil
		},
	}
	fallback := &savedSnapshotTestVMD{
		stubVMD: &stubVMD{},
		deleteFn: func(context.Context, string, string) error {
			defaultDeletes++
			return nil
		},
	}
	registry := &exactSnapshotHostRegistry{clients: map[string]vmdclient.Client{"host-recorded": recorded}}
	h := &Handlers{VMD: fallback, Hosts: registry}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodDelete, "/snapshots/example", nil)
	client, ok := h.snapshotVMDForHost(c, "host-recorded", false)
	if !ok {
		t.Fatalf("recorded host lookup failed: status=%d body=%s", w.Code, w.Body.String())
	}
	if err := client.DeleteSavedSnapshot(c.Request.Context(), "source", "snapshot"); err != nil {
		t.Fatalf("DeleteSavedSnapshot: %v", err)
	}
	if recordedDeletes != 1 || defaultDeletes != 0 {
		t.Fatalf("delete routing recorded=%d default=%d, want 1/0", recordedDeletes, defaultDeletes)
	}

	missingW := httptest.NewRecorder()
	missing, _ := gin.CreateTestContext(missingW)
	missing.Request = httptest.NewRequest(http.MethodDelete, "/snapshots/example", nil)
	if client, ok := h.snapshotVMDForHost(missing, "host-missing", false); ok || client != nil {
		t.Fatal("missing recorded host fell back to the default VMD")
	}
	if missingW.Code != http.StatusServiceUnavailable || defaultDeletes != 0 {
		t.Fatalf("missing host response=%d defaultDeletes=%d, want 503/0", missingW.Code, defaultDeletes)
	}
	if want := []string{"host-recorded", "host-missing"}; !reflect.DeepEqual(registry.requested, want) {
		t.Fatalf("host lookups=%v, want %v", registry.requested, want)
	}
}

func TestInitializeSavedSnapshotForkAttestsPreviewBeforeEnvInjection(t *testing.T) {
	var events []string
	vmd := &savedSnapshotTestVMD{stubVMD: &stubVMD{
		updatePreviewFn: func(_ context.Context, _ string, access string, ports map[int32]vmdclient.PortPolicy, revision int64) error {
			if access != preview.AccessPrivate || ports != nil || revision != 0 {
				t.Fatalf("preview attestation = (%q, %#v, %d), want private/nil/0", access, ports, revision)
			}
			events = append(events, "preview-attested")
			return nil
		},
		injectEnvFn: func(context.Context, string, map[string]string, string) error {
			events = append(events, "env-injected")
			return nil
		},
	}}
	if err := initializeSavedSnapshotFork(context.Background(), vmd, uuid.NewString(), preview.AccessPrivate, map[string]string{"A": "B"}, "jwt"); err != nil {
		t.Fatalf("initializeSavedSnapshotFork: %v", err)
	}
	if want := []string{"preview-attested", "env-injected"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("initialization order=%v, want %v", events, want)
	}

	injected := false
	vmd.updatePreviewFn = func(context.Context, string, string, map[int32]vmdclient.PortPolicy, int64) error {
		return errors.New("preview policy unavailable")
	}
	vmd.injectEnvFn = func(context.Context, string, map[string]string, string) error {
		injected = true
		return nil
	}
	if err := initializeSavedSnapshotFork(context.Background(), vmd, uuid.NewString(), preview.AccessPrivate, nil, ""); err == nil {
		t.Fatal("preview attestation failure was ignored")
	}
	if injected {
		t.Fatal("environment was injected after preview attestation failed")
	}
}

func TestCreateSandboxFromSavedSnapshotPreservesPrivatePreviewPolicy(t *testing.T) {
	teamID, snapshotID, sourceID := uuid.New(), uuid.New(), uuid.New()
	const hostID = "snapshot-host"
	saved := validSavedSnapshotForkFixture(snapshotID, sourceID, teamID, hostID)

	var (
		requiredCapabilities []string
		persistedAccess      string
		restoredAccess       string
		attestedAccess       string
	)
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			switch {
			case containsSQL(sql, "IsFeatureEnabledForTeam"):
				return boolRow(true)
			case containsSQL(sql, "GetSavedSnapshot"):
				return savedSnapshotDBRow(saved)
			case containsSQL(sql, "HostHasCapabilities"):
				requiredCapabilities = append([]string(nil), args[0].([]string)...)
				return boolRow(true)
			case containsSQL(sql, "CreateSandboxFromSnapshot"):
				persistedAccess = args[14].(string)
				childID := args[2].(uuid.UUID)
				return sandboxRow(db.Sandbox{
					ID:               childID,
					TeamID:           teamID,
					Name:             "private-fork",
					Status:           db.SandboxStatusStarting,
					VcpuCount:        2,
					MemoryMib:        2048,
					DiskMib:          8192,
					HostID:           hostID,
					Metadata:         []byte(`{}`),
					SourceSnapshotID: pgtype.UUID{Bytes: snapshotID, Valid: true},
					CreatedAt:        time.Now(),
					UpdatedAt:        time.Now(),
				})
			case containsSQL(sql, "GetSandbox"):
				return sandboxRow(db.Sandbox{
					ID:               args[0].(uuid.UUID),
					TeamID:           teamID,
					Name:             "private-fork",
					Status:           db.SandboxStatusActive,
					VcpuCount:        2,
					MemoryMib:        2048,
					DiskMib:          8192,
					HostID:           hostID,
					Metadata:         []byte(`{}`),
					SourceSnapshotID: pgtype.UUID{Bytes: snapshotID, Valid: true},
					CreatedAt:        time.Now(),
					UpdatedAt:        time.Now(),
				})
			case containsSQL(sql, "CreateActivity"):
				return activityRow()
			default:
				return errorRow(fmt.Errorf("unexpected private fork query: %s", sql))
			}
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			if containsSQL(sql, "ActivateSandbox") {
				return pgconn.NewCommandTag("UPDATE 1"), nil
			}
			return pgconn.CommandTag{}, fmt.Errorf("unexpected private fork exec: %s", sql)
		},
	}
	vmd := &savedSnapshotTestVMD{
		stubVMD: &stubVMD{
			updatePreviewFn: func(_ context.Context, _ string, access string, ports map[int32]vmdclient.PortPolicy, revision int64) error {
				attestedAccess = access
				if ports != nil || revision != 0 {
					t.Fatalf("attested private policy ports/revision = %#v/%d, want nil/0", ports, revision)
				}
				return nil
			},
		},
		restoreFn: func(_ context.Context, _, _, _, _, _ string, _ vmdclient.SavedSnapshotNetwork, _ []string, access string, ports map[int32]vmdclient.PortPolicy, revision int64) (string, uint32, uint32, error) {
			restoredAccess = access
			if ports != nil || revision != 0 {
				t.Fatalf("restored private policy ports/revision = %#v/%d, want nil/0", ports, revision)
			}
			return "10.0.0.8", 2, 2048, nil
		},
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, createSandboxReq(
		fmt.Sprintf(`{"name":"private-fork","from_snapshot":%q,"preview_access":"private"}`, snapshotID),
	))

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", w.Code, w.Body.String())
	}
	if want := previewBrowserCapabilities(); !reflect.DeepEqual(requiredCapabilities, want) {
		t.Fatalf("host capability admission = %#v, want %#v", requiredCapabilities, want)
	}
	if persistedAccess != preview.AccessPrivate || restoredAccess != preview.AccessPrivate || attestedAccess != preview.AccessPrivate {
		t.Fatalf("private policy persistence/restore/attestation = %q/%q/%q", persistedAccess, restoredAccess, attestedAccess)
	}
	if got := parseJSON(t, w)["preview_access"]; got != preview.AccessPrivate {
		t.Fatalf("response preview_access = %#v, want private", got)
	}
}

func TestCreateSandboxFromSavedSnapshotPrivateRequiresBrowserAuthCapability(t *testing.T) {
	teamID, snapshotID, sourceID := uuid.New(), uuid.New(), uuid.New()
	const hostID = "old-snapshot-host"
	saved := validSavedSnapshotForkFixture(snapshotID, sourceID, teamID, hostID)
	var requiredCapabilities []string
	restoreCalls := 0
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			switch {
			case containsSQL(sql, "IsFeatureEnabledForTeam"):
				return boolRow(true)
			case containsSQL(sql, "GetSavedSnapshot"):
				return savedSnapshotDBRow(saved)
			case containsSQL(sql, "HostHasCapabilities"):
				requiredCapabilities = append([]string(nil), args[0].([]string)...)
				return boolRow(false)
			default:
				return errorRow(fmt.Errorf("unexpected query after private capability rejection: %s", sql))
			}
		},
	}
	vmd := &savedSnapshotTestVMD{
		stubVMD: &stubVMD{},
		restoreFn: func(context.Context, string, string, string, string, string, vmdclient.SavedSnapshotNetwork, []string, string, map[int32]vmdclient.PortPolicy, int64) (string, uint32, uint32, error) {
			restoreCalls++
			return "10.0.0.8", 2, 2048, nil
		},
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, createSandboxReq(
		fmt.Sprintf(`{"name":"private-fork","from_snapshot":%q,"preview_access":"private"}`, snapshotID),
	))

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body: %s", w.Code, w.Body.String())
	}
	if want := previewBrowserCapabilities(); !reflect.DeepEqual(requiredCapabilities, want) {
		t.Fatalf("host capability admission = %#v, want %#v", requiredCapabilities, want)
	}
	if restoreCalls != 0 {
		t.Fatalf("RestoreSavedSnapshot calls = %d, want 0 without browser-auth capability", restoreCalls)
	}
}

func TestFailedForkCleanupRequiresDurableRevocationBeforeTeardown(t *testing.T) {
	sandbox := db.Sandbox{ID: uuid.New(), TeamID: uuid.New()}
	revocationErr := errors.New("revocation store unavailable")
	var events []string
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row {
			t.Fatal("cleanup must not issue row queries after revocation persistence fails")
			return notFoundRow()
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			switch {
			case containsSQL(sql, "UpsertSandboxRevocation"):
				events = append(events, "persist-revocation")
				return pgconn.CommandTag{}, revocationErr
			case containsSQL(sql, "MarkSandboxFailedInTeam"):
				events = append(events, "mark-failed")
				return pgconn.NewCommandTag("UPDATE 1"), nil
			default:
				t.Fatalf("unexpected cleanup write: %s", sql)
				return pgconn.CommandTag{}, nil
			}
		},
	}
	vmd := &savedSnapshotTestVMD{
		stubVMD: &stubVMD{destroyFn: func(context.Context, string, bool) error {
			events = append(events, "destroy")
			return nil
		}},
		revokeFn: func(context.Context, string) error {
			events = append(events, "direct-revoke")
			return nil
		},
	}

	(&Handlers{DB: db.New(mock)}).cleanupFailedSavedSnapshotFork(context.Background(), vmd, sandbox)

	if want := []string{"persist-revocation", "direct-revoke", "mark-failed"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("cleanup order=%v, want %v", events, want)
	}
}

func TestFailedForkCleanupRefreshesDBDeadlineAfterSlowHostTeardown(t *testing.T) {
	const (
		dbTimeout   = 40 * time.Millisecond
		hostTimeout = time.Second
		hostDelay   = 60 * time.Millisecond
	)
	sourceSnapshotID := uuid.New()
	sandbox := db.Sandbox{
		ID:               uuid.New(),
		TeamID:           uuid.New(),
		SourceSnapshotID: pgtype.UUID{Bytes: sourceSnapshotID, Valid: true},
	}
	var events []string
	recordLiveDBContext := func(ctx context.Context, event string) {
		t.Helper()
		if err := ctx.Err(); err != nil {
			t.Fatalf("%s received expired DB context: %v", event, err)
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatalf("%s received an unbounded DB context", event)
		}
		events = append(events, event)
	}
	mock := &mockDBTX{
		queryRowFn: func(ctx context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case containsSQL(sql, "DestroySandbox"):
				recordLiveDBContext(ctx, "soft-delete")
			case containsSQL(sql, "ReleaseDestroyedSandboxSnapshotPin"):
				recordLiveDBContext(ctx, "release-parent-pin")
			default:
				t.Fatalf("unexpected cleanup query: %s", sql)
			}
			return &mockRow{scanFn: func(dest ...any) error {
				*(dest[0].(*uuid.UUID)) = sandbox.ID
				return nil
			}}
		},
		execFn: func(ctx context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			switch {
			case containsSQL(sql, "UpsertSandboxRevocation"):
				recordLiveDBContext(ctx, "persist-revocation")
			case containsSQL(sql, "DeleteSandboxSecrets"):
				recordLiveDBContext(ctx, "delete-secrets")
			default:
				t.Fatalf("unexpected cleanup write: %s", sql)
			}
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}
	delayHostCall := func(ctx context.Context, event string) error {
		events = append(events, event)
		timer := time.NewTimer(hostDelay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		}
	}
	vmd := &savedSnapshotTestVMD{
		stubVMD: &stubVMD{destroyFn: func(ctx context.Context, _ string, _ bool) error {
			return delayHostCall(ctx, "destroy")
		}},
		revokeFn: func(ctx context.Context, _ string) error {
			return delayHostCall(ctx, "direct-revoke")
		},
	}

	(&Handlers{DB: db.New(mock)}).cleanupFailedSavedSnapshotForkWithTimeouts(
		context.Background(), vmd, sandbox, dbTimeout, hostTimeout,
	)

	if want := []string{
		"persist-revocation",
		"direct-revoke",
		"destroy",
		"soft-delete",
		"delete-secrets",
		"release-parent-pin",
	}; !reflect.DeepEqual(events, want) {
		t.Fatalf("cleanup order=%v, want %v", events, want)
	}
}

func TestCreateSandboxRequestValidatesSnapshotSourceShape(t *testing.T) {
	for _, field := range []string{"from_template", "from_snapshot", "network", "secrets"} {
		var req createSandboxRequest
		body := []byte(`{"name":"sandbox","` + field + `":null}`)
		if err := json.Unmarshal(body, &req); err == nil {
			t.Errorf("explicit null %s was accepted", field)
		}
	}

	for _, body := range []string{
		`{"name":"sandbox","from_template":"base","from_snapshot":"00000000-0000-0000-0000-000000000001"}`,
		`{"name":"sandbox","from_snapshot":" "}`,
	} {
		w := httptest.NewRecorder()
		setupTestRouter(&Handlers{}, uuid.NewString()).ServeHTTP(w, createSandboxReq(body))
		if w.Code != http.StatusBadRequest {
			t.Errorf("request %s returned %d, want 400: %s", body, w.Code, w.Body.String())
		}
	}
}

func containsSQL(sql, operation string) bool {
	// Generated sqlc text keeps the query name in its first comment.
	return strings.Contains(sql, operation)
}
