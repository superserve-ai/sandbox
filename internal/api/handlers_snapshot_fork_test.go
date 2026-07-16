package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

type stubSavedSnapshotVMD struct {
	*stubVMD
	checkSavedFn   func(context.Context) error
	createSavedFn  func(context.Context, string, string) (vmdclient.SavedSnapshotArtifacts, error)
	restoreSavedFn func(context.Context, string, string, string, string, string, vmdclient.SavedSnapshotNetwork, []string) (string, uint32, uint32, error)
	deleteSavedFn  func(context.Context, string, string) error
	measureSavedFn func(context.Context, string) (int64, int64, error)
}

func (s *stubSavedSnapshotVMD) CheckSavedSnapshotSupport(ctx context.Context) error {
	if s.checkSavedFn != nil {
		return s.checkSavedFn(ctx)
	}
	return nil
}

func (s *stubSavedSnapshotVMD) CreateSavedSnapshot(ctx context.Context, sourceID, snapshotID string) (vmdclient.SavedSnapshotArtifacts, error) {
	if s.createSavedFn != nil {
		return s.createSavedFn(ctx, sourceID, snapshotID)
	}
	return vmdclient.SavedSnapshotArtifacts{}, nil
}

func (s *stubSavedSnapshotVMD) RestoreSavedSnapshot(ctx context.Context, instanceID, manifestPath, manifestDigest, teamID, ownerID string, network vmdclient.SavedSnapshotNetwork, clearEnvKeys []string) (string, uint32, uint32, error) {
	if s.restoreSavedFn != nil {
		return s.restoreSavedFn(ctx, instanceID, manifestPath, manifestDigest, teamID, ownerID, network, clearEnvKeys)
	}
	return "10.0.0.8", 2, 2048, nil
}

func (s *stubSavedSnapshotVMD) DeleteSavedSnapshot(ctx context.Context, sourceID, snapshotID string) error {
	if s.deleteSavedFn != nil {
		return s.deleteSavedFn(ctx, sourceID, snapshotID)
	}
	return nil
}

func (s *stubSavedSnapshotVMD) MeasureSandboxWritableLayer(ctx context.Context, instanceID string) (int64, int64, error) {
	if s.measureSavedFn != nil {
		return s.measureSavedFn(ctx, instanceID)
	}
	return 0, 0, nil
}

func TestCreateSandboxRequestRejectsExplicitNullInheritanceFields(t *testing.T) {
	for _, field := range []string{"from_template", "from_snapshot", "network", "secrets"} {
		t.Run(field, func(t *testing.T) {
			var req createSandboxRequest
			body := []byte(`{"name":"sandbox","` + field + `":null}`)
			if err := json.Unmarshal(body, &req); err == nil {
				t.Fatalf("explicit null %s was accepted", field)
			}
		})
	}

	var omitted createSandboxRequest
	if err := json.Unmarshal([]byte(`{"name":"sandbox"}`), &omitted); err != nil {
		t.Fatalf("omitted inheritance fields should remain valid: %v", err)
	}
}

func TestCapturedSnapshotSecretEnvKeysScrubsProxyDefaultsAfterSecretUse(t *testing.T) {
	keys := capturedSnapshotSecretEnvKeys(nil, []string{"DETACHED_TOKEN"})
	if !slices.Contains(keys, "DETACHED_TOKEN") {
		t.Error("detached secret env key was not retained for scrubbing")
	}
	if keys := capturedSnapshotSecretEnvKeys(nil, nil); len(keys) != 0 {
		t.Errorf("source with no secret history clears unrelated env defaults: %v", keys)
	}
	for _, want := range capturedSecretProxyEnvKeys {
		if !slices.Contains(keys, want) {
			t.Errorf("proxy default %q was not scrubbed without active bindings", want)
		}
	}
}

func TestSnapshotVMDForHostFailsClosedWhenCapabilityRPCIsUnimplemented(t *testing.T) {
	gin.SetMode(gin.TestMode)
	checks := 0
	vmd := &stubSavedSnapshotVMD{
		stubVMD: &stubVMD{},
		checkSavedFn: func(context.Context) error {
			checks++
			return status.Error(codes.Unimplemented, "unknown method GetCapabilities")
		},
	}
	h := &Handlers{VMD: vmd}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/sandboxes/example/snapshots", nil)

	client, ok := h.snapshotVMDForHost(c, "host-a", true)
	if ok || client != nil {
		t.Fatal("old VMD unexpectedly passed saved snapshot capability check")
	}
	if checks != 1 {
		t.Fatalf("capability checks = %d, want 1", checks)
	}
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "5" {
		t.Fatalf("response = %d retry-after=%q, want 503 and 5", w.Code, w.Header().Get("Retry-After"))
	}
}

func TestSnapshotVMDForHostLogDoesNotExposeHostArtifactPath(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const hostPath = "/var/lib/superserve/private/snapshots/source/snapshot/manifest.json"
	vmd := &stubSavedSnapshotVMD{
		stubVMD: &stubVMD{},
		checkSavedFn: func(context.Context) error {
			return status.Error(codes.Unavailable, "stat "+hostPath+": input/output error")
		},
	}
	var output bytes.Buffer
	previousLogger := log.Logger
	log.Logger = zerolog.New(&output)
	defer func() { log.Logger = previousLogger }()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/sandboxes/example/snapshots", nil)
	client, ok := (&Handlers{VMD: vmd}).snapshotVMDForHost(c, "host-a", true)
	if ok || client != nil {
		t.Fatal("failed capability check unexpectedly returned a client")
	}
	if strings.Contains(output.String(), hostPath) {
		t.Fatalf("API log exposed host artifact path: %s", output.String())
	}
	if !strings.Contains(output.String(), "saved snapshot capability check failed") {
		t.Fatalf("API log lost safe operation context: %s", output.String())
	}
}

func TestSavedSnapshotOperationsMapUnimplementedVMDToHostUnavailable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	oldVMDErr := status.Error(codes.Unimplemented, "unknown saved snapshot operation")

	t.Run("capture", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/sandboxes/example/snapshots", nil)
		(&Handlers{}).respondSavedSnapshotCaptureError(c, db.Snapshot{}, &stubSavedSnapshotVMD{stubVMD: &stubVMD{}}, oldVMDErr)
		if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "5" {
			t.Fatalf("capture response = %d retry-after=%q, want 503 and 5", w.Code, w.Header().Get("Retry-After"))
		}
	})

	t.Run("restore", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/sandboxes", nil)
		if !(&Handlers{}).respondSavedSnapshotRestoreError(c, db.Snapshot{}, oldVMDErr) {
			t.Fatal("Unimplemented restore was not handled")
		}
		if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "5" {
			t.Fatalf("restore response = %d retry-after=%q, want 503 and 5", w.Code, w.Header().Get("Retry-After"))
		}
	})
}

func TestSavedSnapshotForkCapacityErrorIncludesRetryAfter(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/sandboxes", nil)

	(&Handlers{}).respondSavedSnapshotForkInsertError(c, db.Snapshot{}, &pgconn.PgError{
		Code: savedSnapshotHostCapacityErrCode,
	})

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d: %s", w.Code, http.StatusServiceUnavailable, w.Body.String())
	}
	if got := w.Header().Get("Retry-After"); got != "5" {
		t.Fatalf("Retry-After = %q, want 5", got)
	}
}

func savedSnapshotRow(s db.Snapshot) pgx.Row {
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

func TestCreateSandboxFromSavedSnapshot_InheritsPoliciesAndReturnsLineage(t *testing.T) {
	teamID := uuid.New()
	sourceID := uuid.New()
	snapshotID := uuid.New()
	hostID := "host-a"
	manifestPath := "/var/lib/superserve/snapshots/saved/" + sourceID.String() + "/" + snapshotID.String() + "/manifest.json"
	manifestDigest := strings.Repeat("a", 64)
	vcpu, memoryMiB, diskMiB := int32(2), int32(2048), int32(8192)
	timeout, autoDelete := int32(900), int32(3600)
	networkJSON := []byte(`{"egress":{"allowed_cidrs":["10.0.0.0/8"],"denied_cidrs":["10.4.0.0/16"],"allowed_domains":["api.example.com"]}}`)
	saved := db.Snapshot{
		ID:                snapshotID,
		SandboxID:         sourceID,
		TeamID:            teamID,
		Kind:              db.SnapshotKindSaved,
		Status:            db.SnapshotStatusReady,
		Trigger:           "api",
		HostID:            &hostID,
		ManifestPath:      &manifestPath,
		ManifestDigest:    &manifestDigest,
		VcpuCount:         &vcpu,
		MemoryMib:         &memoryMiB,
		DiskMib:           &diskMiB,
		TimeoutSeconds:    &timeout,
		AutoDeleteSeconds: &autoDelete,
		NetworkConfig:     networkJSON,
		SecretBindings:    []byte(`[]`),
		CreatedAt:         time.Now().Add(-time.Minute),
		UpdatedAt:         time.Now(),
	}

	var insertedID uuid.UUID
	var insertedSandbox db.Sandbox
	var insertArgs []any
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "feature_enabled") && !strings.Contains(sql, "WITH snap AS"):
				return boolRow(true)
			case strings.Contains(sql, "WITH snap AS"):
				insertArgs = append([]any(nil), args...)
				insertedID = args[0].(uuid.UUID)
				insertedSandbox = db.Sandbox{
					ID:                insertedID,
					TeamID:            teamID,
					Name:              "forked",
					Status:            db.SandboxStatusStarting,
					VcpuCount:         vcpu,
					MemoryMib:         memoryMiB,
					DiskMib:           diskMiB,
					HostID:            hostID,
					TimeoutSeconds:    &timeout,
					AutoDeleteSeconds: &autoDelete,
					NetworkConfig:     networkJSON,
					Metadata:          []byte(`{"run":"test"}`),
					SourceSnapshotID:  pgtype.UUID{Bytes: snapshotID, Valid: true},
					CreatedAt:         time.Now(),
				}
				return sandboxRow(insertedSandbox)
			case strings.Contains(sql, "FROM sandbox") && strings.Contains(sql, "destroyed_at IS NULL"):
				insertedSandbox.Status = db.SandboxStatusActive
				addr := netip.MustParseAddr("10.0.0.8")
				insertedSandbox.IpAddress = &addr
				return sandboxRow(insertedSandbox)
			case strings.Contains(sql, "kind = 'saved'"):
				return savedSnapshotRow(saved)
			default:
				return activityRow()
			}
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}

	var restoredNetwork vmdclient.SavedSnapshotNetwork
	var restoredManifest string
	var restoredManifestDigest string
	var restoredID string
	vmd := &stubSavedSnapshotVMD{
		stubVMD: &stubVMD{},
		restoreSavedFn: func(_ context.Context, instanceID, manifest, digest, gotTeamID, _ string, network vmdclient.SavedSnapshotNetwork, clear []string) (string, uint32, uint32, error) {
			restoredID = instanceID
			restoredManifest = manifest
			restoredManifestDigest = digest
			restoredNetwork = network
			if gotTeamID != teamID.String() {
				t.Errorf("team ID = %q, want %q", gotTeamID, teamID)
			}
			if len(clear) != 0 {
				t.Errorf("clear env keys = %v, want none for snapshot without secret history", clear)
			}
			return "10.0.0.8", uint32(vcpu), uint32(memoryMiB), nil
		},
	}
	h := &Handlers{VMD: vmd, DB: db.New(mock)}

	w := httptest.NewRecorder()
	body := `{"name":"forked","from_snapshot":"` + snapshotID.String() + `","metadata":{"run":"test"},"env_vars":{"RUN_ID":"child"}}`
	setupTestRouter(h, teamID.String()).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/sandboxes", strings.NewReader(body)))
	h.WaitAsyncBookkeeping()

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", w.Code, w.Body.String())
	}
	if restoredID != insertedID.String() || restoredManifest != manifestPath {
		t.Fatalf("restore = (%q, %q), want (%q, %q)", restoredID, restoredManifest, insertedID, manifestPath)
	}
	if restoredManifestDigest != manifestDigest {
		t.Fatalf("restore manifest digest = %q, want %q", restoredManifestDigest, manifestDigest)
	}
	wantNetwork := vmdclient.SavedSnapshotNetwork{
		AllowedCIDRs:   []string{"10.0.0.0/8"},
		DeniedCIDRs:    []string{"10.4.0.0/16"},
		AllowedDomains: []string{"api.example.com"},
	}
	if !reflect.DeepEqual(restoredNetwork, wantNetwork) {
		t.Errorf("restore network = %#v, want %#v", restoredNetwork, wantNetwork)
	}
	if len(insertArgs) != 14 {
		t.Fatalf("fork insert args = %d, want 14", len(insertArgs))
	}
	if inherited, _ := insertArgs[6].(bool); !inherited {
		t.Error("timeout policy was not inherited")
	}
	if inherited, _ := insertArgs[9].(bool); !inherited {
		t.Error("auto-delete policy was not inherited")
	}
	if inherited, _ := insertArgs[11].(bool); !inherited {
		t.Error("network policy was not inherited")
	}
	if got := insertArgs[13].(uuid.UUID); got != snapshotID {
		t.Errorf("source snapshot insert arg = %s, want %s", got, snapshotID)
	}

	var response sandboxResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.SourceSnapshotID == nil || *response.SourceSnapshotID != snapshotID {
		t.Errorf("source_snapshot_id = %v, want %s", response.SourceSnapshotID, snapshotID)
	}
	if response.TimeoutSeconds == nil || *response.TimeoutSeconds != timeout {
		t.Errorf("timeout_seconds = %v, want %d", response.TimeoutSeconds, timeout)
	}
	if response.Metadata["run"] != "test" {
		t.Errorf("metadata = %#v, want request metadata", response.Metadata)
	}
}

func TestCapturedSnapshotSecretEnvKeysScrubsTokensAndProxyIdentity(t *testing.T) {
	bindings := []savedSnapshotSecretBinding{
		{EnvKey: "Z_TOKEN", SecretID: uuid.New()},
		{EnvKey: "A_TOKEN", SecretID: uuid.New()},
	}
	got := capturedSnapshotSecretEnvKeys(bindings, nil)
	want := []string{
		"A_TOKEN",
		"CURL_CA_BUNDLE",
		"HTTPS_PROXY",
		"NODE_EXTRA_CA_CERTS",
		"REQUESTS_CA_BUNDLE",
		"SSL_CERT_DIR",
		"SSL_CERT_FILE",
		"Z_TOKEN",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("clear env keys = %v, want %v", got, want)
	}
}

func TestSavedSnapshotReadyForFork_UnavailableIsGone(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/sandboxes", nil)
	if savedSnapshotReadyForFork(c, db.Snapshot{Status: db.SnapshotStatusUnavailable}) {
		t.Fatal("unavailable snapshot unexpectedly accepted")
	}
	if w.Code != http.StatusGone {
		t.Fatalf("status = %d, want 410; body: %s", w.Code, w.Body.String())
	}
	if got := errorCode(parseJSON(t, w)); got != "snapshot_unavailable" {
		t.Fatalf("error code = %q, want snapshot_unavailable", got)
	}
}

func TestCapSandboxIDsUsesPublicIDFormat(t *testing.T) {
	t.Setenv("SANDBOX_ID_REGION", "use")
	first := uuid.MustParse("1b4e28ba-2fa1-11d2-883f-0016d3cca427")
	second := uuid.MustParse("2b4e28ba-2fa1-11d2-883f-0016d3cca427")

	got := capSandboxIDs([]uuid.UUID{first, second}, 1)
	want := []string{"sb-use-" + first.String()}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("capSandboxIDs() = %#v, want %#v", got, want)
	}
}

func TestFailedForkCleanupRetainsDependencyWhenHostTeardownFails(t *testing.T) {
	sandbox := db.Sandbox{ID: uuid.New(), TeamID: uuid.New()}
	var destroyClaimed bool
	var markedFailed bool
	var revocationPersisted bool
	var revokeDelivered bool
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row {
			destroyClaimed = true
			return notFoundRow()
		},
		execFn: func(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
			if strings.Contains(sql, "INSERT INTO sandbox_revocation") {
				revocationPersisted = true
			}
			if strings.Contains(sql, "SET status = 'failed'") {
				markedFailed = true
			}
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}
	vmd := &stubSavedSnapshotVMD{stubVMD: &stubVMD{
		destroyFn: func(context.Context, string, bool) error {
			if !revocationPersisted || !revokeDelivered {
				t.Fatal("host teardown ran before durable and direct revocation")
			}
			return status.Error(codes.Unavailable, "host unavailable")
		},
		revokeSandboxFn: func(context.Context, string) error {
			revokeDelivered = true
			return nil
		},
	}}

	(&Handlers{DB: db.New(mock)}).cleanupFailedSavedSnapshotFork(context.Background(), vmd, sandbox)

	if destroyClaimed {
		t.Fatal("sandbox was soft-deleted while host teardown outcome was unknown")
	}
	if !markedFailed {
		t.Fatal("orphaned fork was not retained as a failed, dependency-pinning row")
	}
	if !revocationPersisted || !revokeDelivered {
		t.Fatal("failed fork was not revoked before compensation")
	}
}

func TestQueueSavedSnapshotCleanupPersistsNonNegativeArtifactUsage(t *testing.T) {
	saved := db.Snapshot{
		ID:        uuid.New(),
		SandboxID: uuid.New(),
		TeamID:    uuid.New(),
		Kind:      db.SnapshotKindSaved,
		Status:    db.SnapshotStatusDeleting,
		Trigger:   "api",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	var gotArgs []any
	mock := &mockDBTX{queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
		if !strings.Contains(sql, "SET status = 'deleting'") {
			t.Fatalf("unexpected query: %s", sql)
		}
		gotArgs = append([]any(nil), args...)
		return savedSnapshotRow(saved)
	}}
	h := &Handlers{DB: db.New(mock)}
	err := h.queueSavedSnapshotCleanup(context.Background(), saved, vmdclient.SavedSnapshotArtifacts{
		SnapshotPath:       "/saved/vmstate.snap",
		MemPath:            "/saved/mem.snap",
		ManifestPath:       "/saved/manifest.json",
		LogicalSizeBytes:   -1,
		ExclusiveSizeBytes: -2,
	}, []byte(`{"schema_version":1}`), "artifact_validation_failed")
	if err != nil {
		t.Fatalf("queue cleanup: %v", err)
	}
	if len(gotArgs) != 10 {
		t.Fatalf("queue args = %d, want 10", len(gotArgs))
	}
	if gotArgs[4] != int64(0) || gotArgs[8] != int64(0) {
		t.Fatalf("queued sizes = logical %v exclusive %v, want non-negative zeros", gotArgs[4], gotArgs[8])
	}
}
