package api

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/preview"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

func TestSavedSnapshotFeatureDisabledStopsCaptureAndForkBeforeResourceLookup(t *testing.T) {
	teamID := uuid.New()
	sourceID := uuid.New()
	snapshotID := uuid.New()

	tests := []struct {
		name   string
		method string
		path   string
		body   string
		router func(*Handlers) http.Handler
	}{
		{
			name:   "capture",
			method: http.MethodPost,
			path:   "/sandboxes/" + sourceID.String() + "/snapshots",
			body:   `{}`,
			router: func(h *Handlers) http.Handler {
				gin.SetMode(gin.TestMode)
				r := gin.New()
				r.Use(func(c *gin.Context) {
					c.Set("team_id", teamID.String())
					c.Next()
				})
				r.POST("/sandboxes/:sandbox_id/snapshots", h.CreateSnapshot)
				return r
			},
		},
		{
			name:   "fork",
			method: http.MethodPost,
			path:   "/sandboxes",
			body:   `{"name":"fork","from_snapshot":"` + snapshotID.String() + `"}`,
			router: func(h *Handlers) http.Handler {
				return setupTestRouter(h, teamID.String())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			featureLookups := 0
			dbtx := &mockDBTX{
				queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
					if !strings.Contains(sql, "-- name: IsFeatureEnabledForTeam :one") {
						t.Errorf("unexpected DB query after disabled feature gate: %s", firstSQLLine(sql))
						return errorRow(fmt.Errorf("unexpected query"))
					}
					featureLookups++
					assertSnapshotFeatureArgs(t, args, teamID)
					return boolRow(false)
				},
				execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
					t.Errorf("unexpected DB write after disabled feature gate: %s", firstSQLLine(sql))
					return pgconn.CommandTag{}, fmt.Errorf("unexpected exec")
				},
			}
			vmdCalls := 0
			h := &Handlers{
				DB:  db.New(dbtx),
				VMD: snapshotVMDRecordingUnexpectedCalls(t, &vmdCalls),
			}

			w := httptest.NewRecorder()
			tc.router(h).ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body)))

			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body: %s", w.Code, w.Body.String())
			}
			if got := errorCode(parseJSON(t, w)); got != "feature_disabled" {
				t.Fatalf("error code = %q, want feature_disabled", got)
			}
			if featureLookups != 1 {
				t.Fatalf("feature lookups = %d, want 1", featureLookups)
			}
			if vmdCalls != 0 {
				t.Fatalf("VMD calls = %d, want 0", vmdCalls)
			}
		})
	}
}

func TestSavedSnapshotCrossTeamOperationsAreIndistinguishableFromMissing(t *testing.T) {
	callerTeamID := uuid.New()
	foreignSnapshotID := uuid.New()

	tests := []struct {
		name       string
		method     string
		path       string
		body       string
		lookupName string
		router     func(*Handlers) http.Handler
	}{
		{
			name:       "get",
			method:     http.MethodGet,
			path:       "/snapshots/" + foreignSnapshotID.String(),
			lookupName: "-- name: GetSavedSnapshot :one",
			router: func(h *Handlers) http.Handler {
				gin.SetMode(gin.TestMode)
				r := gin.New()
				r.Use(func(c *gin.Context) {
					c.Set("team_id", callerTeamID.String())
					c.Next()
				})
				r.GET("/snapshots/:snapshot_id", h.GetSnapshot)
				return r
			},
		},
		{
			name:       "delete",
			method:     http.MethodDelete,
			path:       "/snapshots/" + foreignSnapshotID.String(),
			lookupName: "-- name: GetSavedSnapshotForDelete :one",
			router: func(h *Handlers) http.Handler {
				return savedSnapshotDeleteTestRouter(h, callerTeamID)
			},
		},
		{
			name:       "fork",
			method:     http.MethodPost,
			path:       "/sandboxes",
			body:       `{"name":"fork","from_snapshot":"` + foreignSnapshotID.String() + `"}`,
			lookupName: "-- name: GetSavedSnapshot :one",
			router: func(h *Handlers) http.Handler {
				return setupTestRouter(h, callerTeamID.String())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lookups := 0
			dbtx := &mockDBTX{
				queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
					if strings.Contains(sql, "-- name: IsFeatureEnabledForTeam :one") {
						if tc.name != "fork" {
							t.Errorf("unexpected feature lookup for %s", tc.name)
						}
						assertSnapshotFeatureArgs(t, args, callerTeamID)
						return boolRow(true)
					}
					if !strings.Contains(sql, tc.lookupName) {
						t.Errorf("unexpected DB query: %s", firstSQLLine(sql))
						return errorRow(fmt.Errorf("unexpected query"))
					}
					lookups++
					assertTeamScopedSnapshotArgs(t, args, foreignSnapshotID, callerTeamID)
					// The database predicate filters the row owned by another team.
					return notFoundRow()
				},
				execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
					t.Errorf("unexpected DB write for cross-team %s: %s", tc.name, firstSQLLine(sql))
					return pgconn.CommandTag{}, fmt.Errorf("unexpected exec")
				},
			}
			vmdCalls := 0
			h := &Handlers{
				DB:  db.New(dbtx),
				VMD: snapshotVMDRecordingUnexpectedCalls(t, &vmdCalls),
			}

			w := httptest.NewRecorder()
			var body *strings.Reader
			if tc.body == "" {
				body = strings.NewReader("")
			} else {
				body = strings.NewReader(tc.body)
			}
			tc.router(h).ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, body))

			if w.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404; body: %s", w.Code, w.Body.String())
			}
			if got := errorCode(parseJSON(t, w)); got != "snapshot_not_found" {
				t.Fatalf("error code = %q, want snapshot_not_found", got)
			}
			if lookups != 1 {
				t.Fatalf("team-scoped snapshot lookups = %d, want 1", lookups)
			}
			if vmdCalls != 0 {
				t.Fatalf("VMD calls = %d, want 0", vmdCalls)
			}
		})
	}
}

func TestSavedSnapshotForkInheritanceMintsUniqueChildCredentials(t *testing.T) {
	teamID := uuid.New()
	sourceID := uuid.New()
	snapshotID := uuid.New()
	secretID := uuid.New()
	provider := "openai"
	const envKey = "OPENAI_API_KEY"
	const sourceProxyToken = "sk-proj-source-sandbox-token"

	hostID := "host-a"
	manifestPath := "/var/lib/superserve/snapshots/saved/" + sourceID.String() + "/" + snapshotID.String() + "/manifest.json"
	manifestDigest := strings.Repeat("a", 64)
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
		SecretBindings: []byte(`[{"env_key":"` + envKey + `","secret_id":"` + secretID.String() + `","secret_name":"openai"}]`),
		SecretEnvKeys:  []byte(`["` + envKey + `"]`),
		CreatedAt:      time.Now().Add(-time.Minute),
		UpdatedAt:      time.Now(),
	}
	secret := db.Secret{
		ID:               secretID,
		TeamID:           teamID,
		Name:             "openai",
		AuthType:         "bearer",
		AuthConfig:       []byte(`{}`),
		ProviderShortcut: &provider,
		Hosts:            []string{"api.openai.com"},
	}

	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	signer, err := NewSecretsSigner(base64.StdEncoding.EncodeToString(seed), "snapshot-fork-test")
	if err != nil {
		t.Fatalf("create secrets signer: %v", err)
	}

	var mu sync.Mutex
	inserted := make([]uuid.UUID, 0, 2)
	insertedSandboxes := make(map[uuid.UUID]db.Sandbox)
	persistedTokens := make(map[uuid.UUID]string)
	injectedTokens := make(map[uuid.UUID]string)
	injectedJWTs := make(map[uuid.UUID]string)
	restoredIPs := make(map[uuid.UUID]string)
	activityDone := make(chan struct{}, 2)

	dbtx := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "-- name: IsFeatureEnabledForTeam :one"):
				assertSnapshotFeatureArgs(t, args, teamID)
				return boolRow(true)
			case strings.Contains(sql, "-- name: GetSavedSnapshot :one"):
				assertTeamScopedSnapshotArgs(t, args, snapshotID, teamID)
				return savedSnapshotRow(saved)
			case strings.Contains(sql, "-- name: HostHasCapabilities :one"):
				return boolRow(true)
			case strings.Contains(sql, "-- name: GetSecretByID :one"):
				if len(args) != 2 || args[0] != secretID || args[1] != teamID {
					t.Errorf("GetSecretByID args = %#v, want [%s %s]", args, secretID, teamID)
				}
				return secretRow(secret)
			case strings.Contains(sql, "-- name: CreateSandboxFromSnapshot :one"):
				childID, ok := args[2].(uuid.UUID)
				if !ok {
					t.Errorf("fork child ID arg = %T, want uuid.UUID", args[2])
					return errorRow(fmt.Errorf("invalid child id"))
				}
				sandbox := db.Sandbox{
					ID:               childID,
					TeamID:           teamID,
					Name:             args[3].(string),
					Status:           db.SandboxStatusStarting,
					VcpuCount:        vcpu,
					MemoryMib:        memoryMiB,
					DiskMib:          diskMiB,
					HostID:           hostID,
					Metadata:         []byte(`{}`),
					SourceSnapshotID: pgtype.UUID{Bytes: snapshotID, Valid: true},
					CreatedAt:        time.Now(),
					UpdatedAt:        time.Now(),
				}
				mu.Lock()
				inserted = append(inserted, childID)
				insertedSandboxes[childID] = sandbox
				mu.Unlock()
				return sandboxRow(sandbox)
			case strings.Contains(sql, "-- name: GetSandbox :one"):
				childID := args[0].(uuid.UUID)
				if args[1] != teamID {
					t.Errorf("GetSandbox team arg = %v, want %s", args[1], teamID)
				}
				mu.Lock()
				sandbox := insertedSandboxes[childID]
				ip := restoredIPs[childID]
				mu.Unlock()
				sandbox.Status = db.SandboxStatusActive
				addr := netip.MustParseAddr(ip)
				sandbox.IpAddress = &addr
				return sandboxRow(sandbox)
			case strings.Contains(sql, "-- name: CreateActivity :one"):
				activityDone <- struct{}{}
				return activityRow()
			default:
				t.Errorf("unexpected DB query during inherited-secret fork: %s", firstSQLLine(sql))
				return errorRow(fmt.Errorf("unexpected query"))
			}
		},
		execFn: func(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
			switch {
			case strings.Contains(sql, "-- name: AddSandboxSecrets :exec"):
				childID := args[0].(uuid.UUID)
				secretIDs := args[1].([]uuid.UUID)
				envKeys := args[2].([]string)
				proxyTokens := args[3].([]string)
				if len(secretIDs) != 1 || secretIDs[0] != secretID || len(envKeys) != 1 || envKeys[0] != envKey || len(proxyTokens) != 1 {
					t.Errorf("persisted inherited binding = ids:%v env:%v tokens:%d", secretIDs, envKeys, len(proxyTokens))
				} else {
					mu.Lock()
					persistedTokens[childID] = proxyTokens[0]
					mu.Unlock()
				}
				return pgconn.NewCommandTag("UPDATE 1"), nil
			case strings.Contains(sql, "-- name: ActivateSandbox :exec"):
				if args[4] != teamID {
					t.Errorf("ActivateSandbox team arg = %v, want %s", args[4], teamID)
				}
				return pgconn.NewCommandTag("UPDATE 1"), nil
			default:
				t.Errorf("unexpected DB write during inherited-secret fork: %s", firstSQLLine(sql))
				return pgconn.CommandTag{}, fmt.Errorf("unexpected exec")
			}
		},
	}

	vmd := &stubSavedSnapshotVMD{
		stubVMD: &stubVMD{
			injectEnvFn: func(_ context.Context, id string, env map[string]string, secretsJWT string) error {
				childID, err := uuid.Parse(id)
				if err != nil {
					return err
				}
				mu.Lock()
				injectedTokens[childID] = env[envKey]
				injectedJWTs[childID] = secretsJWT
				mu.Unlock()
				return nil
			},
		},
		checkSavedFn: func(context.Context) error { return nil },
		restoreSavedFn: func(_ context.Context, id, _, _, gotTeamID, _ string, _ vmdclient.SavedSnapshotNetwork, clearEnvKeys []string, previewAccess string, previewPorts map[int32]vmdclient.PortPolicy, previewPolicyRevision int64) (string, uint32, uint32, error) {
			if gotTeamID != teamID.String() {
				t.Errorf("restore team ID = %q, want %q", gotTeamID, teamID)
			}
			if previewAccess != preview.AccessPublic || previewPorts != nil || previewPolicyRevision != 0 {
				t.Errorf("restore preview policy = (%q, %#v, %d), want public/nil/0", previewAccess, previewPorts, previewPolicyRevision)
			}
			// The captured guest is assumed to contain sourceProxyToken under
			// envKey. The restore boundary must scrub that captured value before
			// the freshly minted child credential is injected below.
			if !slices.Contains(clearEnvKeys, envKey) {
				t.Errorf("restore clear env keys = %v, want captured key %q", clearEnvKeys, envKey)
			}
			childID, err := uuid.Parse(id)
			if err != nil {
				return "", 0, 0, err
			}
			mu.Lock()
			ip := fmt.Sprintf("10.0.0.%d", len(restoredIPs)+8)
			restoredIPs[childID] = ip
			mu.Unlock()
			return ip, uint32(vcpu), uint32(memoryMiB), nil
		},
	}
	h := &Handlers{DB: db.New(dbtx), VMD: vmd, Signer: signer}
	router := setupTestRouter(h, teamID.String())

	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		body := `{"name":"fork-` + fmt.Sprint(i+1) + `","from_snapshot":"` + snapshotID.String() + `"}`
		router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/sandboxes", strings.NewReader(body)))
		if w.Code != http.StatusCreated {
			t.Fatalf("fork %d status = %d, want 201; body: %s", i+1, w.Code, w.Body.String())
		}
		select {
		case <-activityDone:
		case <-time.After(time.Second):
			t.Fatalf("fork %d activity bookkeeping did not finish", i+1)
		}
	}

	mu.Lock()
	children := append([]uuid.UUID(nil), inserted...)
	persisted := cloneStringMapByUUID(persistedTokens)
	injected := cloneStringMapByUUID(injectedTokens)
	jwtByChild := cloneStringMapByUUID(injectedJWTs)
	mu.Unlock()

	if len(children) != 2 {
		t.Fatalf("inserted children = %d, want 2", len(children))
	}
	if children[0] == children[1] {
		t.Fatalf("sibling forks reused child ID %s", children[0])
	}
	for _, childID := range children {
		token := injected[childID]
		if token == "" {
			t.Fatalf("child %s received an empty inherited proxy token", childID)
		}
		if token == sourceProxyToken {
			t.Fatalf("child %s reused the source sandbox proxy token", childID)
		}
		if persisted[childID] != token {
			t.Fatalf("child %s persisted token %q, injected %q", childID, persisted[childID], token)
		}

		claims := &SecretsClaims{}
		parsed, err := jwt.ParseWithClaims(jwtByChild[childID], claims, func(token *jwt.Token) (any, error) {
			if token.Method.Alg() != jwt.SigningMethodEdDSA.Alg() {
				return nil, fmt.Errorf("unexpected signing method %s", token.Method.Alg())
			}
			return signer.PublicKey(), nil
		})
		if err != nil || !parsed.Valid {
			t.Fatalf("verify child %s secrets JWT: valid=%v err=%v", childID, parsed != nil && parsed.Valid, err)
		}
		if claims.Subject != childID.String() {
			t.Errorf("JWT subject = %q, want child %s", claims.Subject, childID)
		}
		if claims.TeamID != teamID.String() {
			t.Errorf("JWT team = %q, want %s", claims.TeamID, teamID)
		}
		if len(claims.Bindings) != 1 || claims.Bindings[0].ProxyToken != token || claims.Bindings[0].SecretID != secretID.String() || claims.Bindings[0].EnvKey != envKey {
			t.Errorf("JWT binding for child %s = %#v", childID, claims.Bindings)
		}
	}
	if injected[children[0]] == injected[children[1]] {
		t.Fatalf("sibling forks reused proxy token %q", injected[children[0]])
	}
}

func assertSnapshotFeatureArgs(t *testing.T, args []any, teamID uuid.UUID) {
	t.Helper()
	if len(args) != 2 {
		t.Errorf("feature lookup args = %d, want 2", len(args))
		return
	}
	if args[0] != "sandbox_snapshots_v1" {
		t.Errorf("feature key = %v, want sandbox_snapshots_v1", args[0])
	}
	gotTeam, ok := args[1].(pgtype.UUID)
	if !ok || !gotTeam.Valid || uuid.UUID(gotTeam.Bytes) != teamID {
		t.Errorf("feature team = %#v, want %s", args[1], teamID)
	}
}

func assertTeamScopedSnapshotArgs(t *testing.T, args []any, snapshotID, teamID uuid.UUID) {
	t.Helper()
	if len(args) != 2 {
		t.Errorf("snapshot lookup args = %d, want 2", len(args))
		return
	}
	if args[0] != snapshotID || args[1] != teamID {
		t.Errorf("snapshot lookup args = %#v, want [%s %s]", args, snapshotID, teamID)
	}
}

func snapshotVMDRecordingUnexpectedCalls(t *testing.T, calls *int) *stubSavedSnapshotVMD {
	t.Helper()
	record := func(op string) {
		(*calls)++
		t.Errorf("unexpected VMD %s call", op)
	}
	return &stubSavedSnapshotVMD{
		stubVMD: &stubVMD{
			injectEnvFn: func(context.Context, string, map[string]string, string) error {
				record("InjectSandboxEnv")
				return fmt.Errorf("unexpected VMD call")
			},
		},
		checkSavedFn: func(context.Context) error {
			record("CheckSavedSnapshotSupport")
			return fmt.Errorf("unexpected VMD call")
		},
		createSavedFn: func(context.Context, string, string) (vmdclient.SavedSnapshotArtifacts, error) {
			record("CreateSavedSnapshot")
			return vmdclient.SavedSnapshotArtifacts{}, fmt.Errorf("unexpected VMD call")
		},
		restoreSavedFn: func(context.Context, string, string, string, string, string, vmdclient.SavedSnapshotNetwork, []string, string, map[int32]vmdclient.PortPolicy, int64) (string, uint32, uint32, error) {
			record("RestoreSavedSnapshot")
			return "", 0, 0, fmt.Errorf("unexpected VMD call")
		},
		deleteSavedFn: func(context.Context, string, string) error {
			record("DeleteSavedSnapshot")
			return fmt.Errorf("unexpected VMD call")
		},
		measureSavedFn: func(context.Context, string) (int64, int64, error) {
			record("MeasureSandboxWritableLayer")
			return 0, 0, fmt.Errorf("unexpected VMD call")
		},
	}
}

func firstSQLLine(sql string) string {
	if i := strings.IndexByte(sql, '\n'); i >= 0 {
		return sql[:i]
	}
	return sql
}

func cloneStringMapByUUID(in map[uuid.UUID]string) map[uuid.UUID]string {
	out := make(map[uuid.UUID]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
