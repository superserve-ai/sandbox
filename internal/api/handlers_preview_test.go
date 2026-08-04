package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/auth"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/preview"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

func setupPreviewRouter(h *Handlers, teamID string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("team_id", teamID)
		c.Next()
	})
	r.GET("/sandboxes/:sandbox_id/preview-ports", h.ListSandboxPreviewPorts)
	r.POST("/sandboxes/:sandbox_id/preview-ports", h.PublishSandboxPreviewPort)
	r.DELETE("/sandboxes/:sandbox_id/preview-ports/:port", h.UnpublishSandboxPreviewPort)
	r.POST("/sandboxes/:sandbox_id/preview-ports/:port/token", h.MintSandboxPreviewToken)
	r.POST("/sandboxes/:sandbox_id/preview-ports/:port/token/rotate", h.RotateSandboxPreviewToken)
	r.PATCH("/sandboxes/:sandbox_id", h.PatchSandbox)
	return r
}

func publishedPortRow(port int32, access string) pgx.Row {
	return &mockRow{scanFn: func(dest ...any) error {
		*dest[0].(*int32) = port
		*dest[1].(*string) = access
		return nil
	}}
}

func scalarBoolRow(value bool) pgx.Row {
	return &mockRow{scanFn: func(dest ...any) error {
		*dest[0].(*bool) = value
		return nil
	}}
}

func scalarUUIDRow(value uuid.UUID) pgx.Row {
	return &mockRow{scanFn: func(dest ...any) error {
		*dest[0].(*uuid.UUID) = value
		return nil
	}}
}

func previewPolicyRow(access string, revision int64) pgx.Row {
	return previewPolicyRowWithWire(access, access, revision)
}

func previewPolicyRowWithWire(access, wireAccess string, revision int64) pgx.Row {
	return &mockRow{scanFn: func(dest ...any) error {
		*dest[0].(*string) = access
		*dest[1].(*string) = wireAccess
		*dest[2].(*int64) = revision
		return nil
	}}
}

func previewPortRows(ports ...int32) pgx.Rows {
	policies := make([]publishedPortResponse, 0, len(ports))
	for _, port := range ports {
		policies = append(policies, publishedPortResponse{Port: port, Access: preview.AccessPublic})
	}
	return previewPortPolicyRows(policies...)
}

func previewPortPolicyRows(ports ...publishedPortResponse) pgx.Rows {
	rows := make([]func(dest ...any) error, 0, len(ports))
	for _, item := range ports {
		port := item
		rows = append(rows, func(dest ...any) error {
			*dest[0].(*int32) = port.Port
			*dest[1].(*string) = port.Access
			if port.TokenVersion == 0 {
				port.TokenVersion = 1
			}
			*dest[2].(*int64) = port.TokenVersion
			return nil
		})
	}
	return &scanRows{rows: rows}
}

func TestPublishedPortPoliciesMapsRawPrivateToBrowserWireMode(t *testing.T) {
	got := publishedPortPolicies([]db.ListPublishedPortsRow{
		{Port: 3000, Access: preview.AccessPublic, TokenVersion: 9},
		{Port: 8080, Access: preview.AccessPrivate, TokenVersion: 12},
	})
	if got[3000].Access != preview.AccessPublic || got[3000].TokenVersion != 9 {
		t.Fatalf("control-plane public policy=%#v, want API generation 9", got[3000])
	}
	if got[8080].Access != preview.AccessPrivateBrowserV1 || got[8080].TokenVersion != 12 {
		t.Fatalf("private wire policy=%#v, want private_browser_v1 generation 12", got[8080])
	}
	policy := previewPolicySnapshot{Access: preview.AccessPublic, WireAccess: preview.AccessPrivate, Ports: got}
	wire := policy.vmdPorts()
	if wire[3000].TokenVersion != 0 || wire[8080].TokenVersion != 12 {
		t.Fatalf("wire generations=%#v, want public=0 private=12", wire)
	}
	if access := policy.vmdAccess(); access != preview.AccessPrivate {
		t.Fatalf("top-level wire access=%q, want Phase2-compatible private fallback", access)
	}
}

func TestPublicationRequiresBrowserAuthUsesResultingPerPortModes(t *testing.T) {
	private := preview.AccessPrivate
	public := preview.AccessPublic
	tests := []struct {
		name    string
		current previewPolicySnapshot
		port    int32
		access  *string
		want    bool
	}{
		{name: "new omitted inherits private", current: previewPolicySnapshot{Access: preview.AccessPrivate}, port: 3000, want: true},
		{name: "new explicit public under private default", current: previewPolicySnapshot{Access: preview.AccessPrivate}, port: 3000, access: &public, want: false},
		{name: "existing browser private omission preserves private", current: previewPolicySnapshot{Access: preview.AccessPublic, Ports: map[int32]vmdclient.PortPolicy{3000: {Access: preview.AccessPrivateBrowserV1}}}, port: 3000, want: true},
		{name: "explicit public replaces sole browser private", current: previewPolicySnapshot{Access: preview.AccessPublic, Ports: map[int32]vmdclient.PortPolicy{3000: {Access: preview.AccessPrivateBrowserV1}}}, port: 3000, access: &public, want: false},
		{name: "explicit public leaves tokenized private sibling", current: previewPolicySnapshot{Access: preview.AccessPublic, Ports: map[int32]vmdclient.PortPolicy{3000: {Access: preview.AccessPrivateBrowserV1}, 8080: {Access: preview.AccessPrivateTokenV1}}}, port: 3000, access: &public, want: true},
		{name: "new explicit private", current: previewPolicySnapshot{Access: preview.AccessPublic}, port: 3000, access: &private, want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := publicationRequiresBrowserAuth(tc.current, tc.port, tc.access); got != tc.want {
				t.Fatalf("publicationRequiresBrowserAuth=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestListSandboxPreviewPortsReturnsAuthoritativeAllowlist(t *testing.T) {
	sandboxID, teamID := uuid.New(), uuid.New()
	sandbox := db.Sandbox{
		ID: sandboxID, TeamID: teamID, HostID: "host-a",
	}
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "-- name: GetSandbox :one"):
				return sandboxRow(sandbox)
			case strings.Contains(sql, "-- name: GetSandboxPreviewPolicy :one"):
				return previewPolicyRowWithWire(preview.AccessPublic, preview.AccessPrivate, 7)
			}
			return errorRow(fmt.Errorf("unexpected QueryRow: %s", sql))
		},
		queryFn: func(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
			if strings.Contains(sql, "-- name: ListPublishedPorts :many") {
				return previewPortPolicyRows(
					publishedPortResponse{Port: 3000, Access: preview.AccessPublic, TokenVersion: 3},
					publishedPortResponse{Port: 8080, Access: preview.AccessPrivate, TokenVersion: 8},
				), nil
			}
			return nil, fmt.Errorf("unexpected Query: %s", sql)
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, fmt.Errorf("unexpected Exec: %s", sql)
		},
	}

	h := &Handlers{DB: db.New(mock)}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sandboxes/"+sandboxID.String()+"/preview-ports", nil)
	setupPreviewRouter(h, teamID.String()).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	var got listPreviewPortsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.PreviewAccess != preview.AccessPublic {
		t.Fatalf("preview_access = %q, want %q", got.PreviewAccess, preview.AccessPublic)
	}
	if len(got.Ports) != 2 || got.Ports[0].Port != 3000 || got.Ports[1].Port != 8080 {
		t.Fatalf("ports = %#v, want [3000, 8080]", got.Ports)
	}
	if got.Ports[0].Access != preview.AccessPublic || got.Ports[1].Access != preview.AccessPrivate {
		t.Fatalf("port access = %#v, want public/private while default remains public", got.Ports)
	}
	if got.Ports[0].TokenVersion != 3 || got.Ports[1].TokenVersion != 8 {
		t.Fatalf("token versions = %#v, want [3 8]", got.Ports)
	}
}

func TestPublishPrivatePreviewPortRejectsLegacySandboxBeforeMutation(t *testing.T) {
	sandboxID, teamID := uuid.New(), uuid.New()
	sandbox := db.Sandbox{ID: sandboxID, TeamID: teamID, HostID: "host-new"}
	mutated := false
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "-- name: GetSandbox :one"):
				return sandboxRow(sandbox)
			case strings.Contains(sql, "-- name: GetSandboxPreviewPolicy :one"):
				return previewPolicyRow(preview.AccessLegacyPublic, 0)
			default:
				mutated = true
				return errorRow(fmt.Errorf("unexpected query after legacy guard: %s", sql))
			}
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			mutated = true
			return pgconn.CommandTag{}, fmt.Errorf("unexpected mutation: %s", sql)
		},
	}

	h := &Handlers{DB: db.New(mock), VMD: &stubVMD{}}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sandboxes/"+sandboxID.String()+"/preview-ports", strings.NewReader(`{"port":3000,"access":"private"}`))
	setupPreviewRouter(h, teamID.String()).ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body: %s", w.Code, w.Body.String())
	}
	if mutated {
		t.Fatal("legacy private publication reached capability or mutation queries")
	}
}

func TestPatchPreviewAccessPersistsPrivateDefaultAndPreservesPortModes(t *testing.T) {
	sandboxID, teamID := uuid.New(), uuid.New()
	sandbox := db.Sandbox{ID: sandboxID, TeamID: teamID, HostID: "host-new", Name: "preview"}
	var updatedDefault string
	var capabilityRequirements [][]string
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "-- name: GetSandbox :one"):
				return sandboxRow(sandbox)
			case strings.Contains(sql, "-- name: GetSandboxPreviewPolicy :one"):
				return previewPolicyRow(preview.AccessPublic, 0)
			case (strings.Contains(sql, "-- name: HostHasCapabilities :one") || strings.Contains(sql, "-- name: HostHasCapabilitiesUnlocked :one")):
				capabilityRequirements = append(capabilityRequirements, append([]string(nil), args[0].([]string)...))
				return scalarBoolRow(true)
			case strings.Contains(sql, "-- name: LockSandboxForPreviewMutation :one"):
				return scalarUUIDRow(sandboxID)
			case strings.Contains(sql, "-- name: AdvanceSandboxPreviewPolicy :one"):
				return previewPolicyRowWithWire(preview.AccessPrivate, preview.AccessPrivate, 12)
			case strings.Contains(sql, "-- name: CreateActivity :one"):
				return activityRow()
			default:
				return errorRow(fmt.Errorf("unexpected QueryRow: %s", sql))
			}
		},
		queryFn: func(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
			if strings.Contains(sql, "-- name: ListPublishedPorts :many") {
				return previewPortPolicyRows(publishedPortResponse{Port: 3000, Access: preview.AccessPublic}), nil
			}
			return nil, fmt.Errorf("unexpected Query: %s", sql)
		},
		execFn: func(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
			switch {
			case strings.Contains(sql, "-- name: EnsureSandboxPreviewPolicy :exec"):
				return pgconn.NewCommandTag("INSERT 0 0"), nil
			case strings.Contains(sql, "-- name: UpdateSandboxPreviewAccess :execrows"):
				updatedDefault = args[1].(string)
				return pgconn.NewCommandTag("UPDATE 1"), nil
			default:
				return pgconn.CommandTag{}, fmt.Errorf("unexpected Exec: %s", sql)
			}
		},
	}

	var pushed bool
	h := &Handlers{
		DB: db.New(mock),
		VMD: &stubVMD{updatePreviewFn: func(_ context.Context, id, access string, ports map[int32]vmdclient.PortPolicy, revision int64) error {
			pushed = true
			if id != sandboxID.String() || access != preview.AccessPrivate || revision != 12 ||
				len(ports) != 1 || ports[3000].Access != preview.AccessPublic {
				t.Errorf("pushed policy = (%q, %q, %#v, %d)", id, access, ports, revision)
			}
			return nil
		}},
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/sandboxes/"+sandboxID.String(), strings.NewReader(`{"preview_access":"private"}`))
	setupPreviewRouter(h, teamID.String()).ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", w.Code, w.Body.String())
	}
	if updatedDefault != preview.AccessPrivate || !pushed {
		t.Fatalf("updated default = %q, pushed=%v", updatedDefault, pushed)
	}
	if len(capabilityRequirements) != 2 {
		t.Fatalf("private PATCH capability checks=%d, want preflight and transaction recheck", len(capabilityRequirements))
	}
	for _, got := range capabilityRequirements {
		if !slices.Equal(got, previewBrowserCapabilities()) {
			t.Fatalf("private PATCH capabilities=%v, want %v", got, previewBrowserCapabilities())
		}
	}
}

func TestPublishPreviewPortRejectsHostWithoutCapabilityBeforeMutation(t *testing.T) {
	sandboxID, teamID := uuid.New(), uuid.New()
	sandbox := db.Sandbox{
		ID: sandboxID, TeamID: teamID, HostID: "host-old",
	}
	mutated := false
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "-- name: GetSandbox :one"):
				return sandboxRow(sandbox)
			case strings.Contains(sql, "-- name: GetSandboxPreviewPolicy :one"):
				return previewPolicyRow(preview.AccessPublic, 0)
			case (strings.Contains(sql, "-- name: HostHasCapabilities :one") || strings.Contains(sql, "-- name: HostHasCapabilitiesUnlocked :one")):
				return scalarBoolRow(false)
			case strings.Contains(sql, "AdvanceSandboxPreviewPolicy"), strings.Contains(sql, "PublishPort"), strings.Contains(sql, "LockSandboxForPreviewMutation"):
				mutated = true
				return errorRow(fmt.Errorf("mutation must not run"))
			default:
				return errorRow(fmt.Errorf("unexpected QueryRow: %s", sql))
			}
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			mutated = true
			return pgconn.CommandTag{}, fmt.Errorf("unexpected Exec: %s", sql)
		},
	}
	vmdCalled := false
	h := &Handlers{
		DB: db.New(mock),
		VMD: &stubVMD{updatePreviewFn: func(context.Context, string, string, map[int32]vmdclient.PortPolicy, int64) error {
			vmdCalled = true
			return nil
		}},
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sandboxes/"+sandboxID.String()+"/preview-ports", strings.NewReader(`{"port":3000}`))
	setupPreviewRouter(h, teamID.String()).ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body: %s", w.Code, w.Body.String())
	}
	if mutated || vmdCalled {
		t.Fatalf("incapable host reached mutation=%v vmd=%v", mutated, vmdCalled)
	}
}

func TestPublishPrivatePreviewPathsRequireBrowserCapabilityBeforeMutation(t *testing.T) {
	tests := []struct {
		name         string
		defaultMode  string
		existingRows []publishedPortResponse
		body         string
	}{
		{name: "explicit private", defaultMode: preview.AccessPublic, body: `{"port":3000,"access":"private"}`},
		{name: "inferred private default", defaultMode: preview.AccessPrivate, body: `{"port":3000}`},
		{name: "private sibling", defaultMode: preview.AccessPublic, existingRows: []publishedPortResponse{{Port: 8080, Access: preview.AccessPrivate, TokenVersion: 4}}, body: `{"port":3000,"access":"public"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sandboxID, teamID := uuid.New(), uuid.New()
			sandbox := db.Sandbox{ID: sandboxID, TeamID: teamID, HostID: "phase3-host"}
			var gotCapabilities []string
			mutated := false
			mock := &mockDBTX{
				queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
					switch {
					case strings.Contains(sql, "-- name: GetSandbox :one"):
						return sandboxRow(sandbox)
					case strings.Contains(sql, "-- name: GetSandboxPreviewPolicy :one"):
						return previewPolicyRow(tt.defaultMode, 0)
					case (strings.Contains(sql, "-- name: HostHasCapabilities :one") || strings.Contains(sql, "-- name: HostHasCapabilitiesUnlocked :one")):
						gotCapabilities = append([]string(nil), args[0].([]string)...)
						return scalarBoolRow(!slices.Contains(gotCapabilities, preview.HostCapabilityPortBrowserAuth))
					default:
						mutated = true
						return errorRow(fmt.Errorf("unexpected mutation QueryRow: %s", sql))
					}
				},
				queryFn: func(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
					if strings.Contains(sql, "-- name: ListPublishedPorts :many") {
						return previewPortPolicyRows(tt.existingRows...), nil
					}
					mutated = true
					return nil, fmt.Errorf("unexpected mutation Query: %s", sql)
				},
				execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
					mutated = true
					return pgconn.CommandTag{}, fmt.Errorf("unexpected mutation Exec: %s", sql)
				},
			}
			h := &Handlers{DB: db.New(mock), VMD: &stubVMD{}}
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/sandboxes/"+sandboxID.String()+"/preview-ports", strings.NewReader(tt.body))
			setupPreviewRouter(h, teamID.String()).ServeHTTP(w, req)

			if w.Code != http.StatusConflict {
				t.Fatalf("status=%d, want 409; body=%s", w.Code, w.Body.String())
			}
			if !slices.Equal(gotCapabilities, previewBrowserCapabilities()) {
				t.Fatalf("private publication capabilities=%v, want %v", gotCapabilities, previewBrowserCapabilities())
			}
			if mutated {
				t.Fatal("browser-incapable host reached private publication mutation")
			}
		})
	}
}

func TestPublishPreviewPortOmissionPreservesPrivateModeAndPushesRestrictiveSnapshot(t *testing.T) {
	sandboxID, teamID := uuid.New(), uuid.New()
	sandbox := db.Sandbox{
		ID: sandboxID, TeamID: teamID, HostID: "host-new", Name: "preview",
	}
	activityFinished := make(chan struct{}, 1)
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "-- name: GetSandbox :one"):
				return sandboxRow(sandbox)
			case strings.Contains(sql, "-- name: GetSandboxPreviewPolicy :one"):
				return previewPolicyRowWithWire(preview.AccessPublic, preview.AccessPrivate, 10)
			case (strings.Contains(sql, "-- name: HostHasCapabilities :one") || strings.Contains(sql, "-- name: HostHasCapabilitiesUnlocked :one")):
				return scalarBoolRow(true)
			case strings.Contains(sql, "-- name: LockSandboxForPreviewMutation :one"):
				return scalarUUIDRow(sandboxID)
			case strings.Contains(sql, "-- name: AdvanceSandboxPreviewPolicy :one"):
				return previewPolicyRowWithWire(preview.AccessPublic, preview.AccessPrivate, 11)
			case strings.Contains(sql, "-- name: PublishPort :one"):
				if len(args) != 3 || args[2] != (*string)(nil) {
					t.Errorf("PublishPort access arg = %#v, want nil omission", args)
				}
				return publishedPortRow(3000, preview.AccessPrivate)
			case strings.Contains(sql, "-- name: CreateActivity :one"):
				row := activityRow()
				return &mockRow{scanFn: func(dest ...any) error {
					err := row.Scan(dest...)
					activityFinished <- struct{}{}
					return err
				}}
			default:
				return errorRow(fmt.Errorf("unexpected QueryRow: %s", sql))
			}
		},
		queryFn: func(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
			if strings.Contains(sql, "-- name: ListPublishedPorts :many") {
				return previewPortPolicyRows(
					publishedPortResponse{Port: 3000, Access: preview.AccessPrivate},
					publishedPortResponse{Port: 8080, Access: preview.AccessPublic},
				), nil
			}
			return nil, fmt.Errorf("unexpected Query: %s", sql)
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			if strings.Contains(sql, "-- name: EnsureSandboxPreviewPolicy :exec") {
				return pgconn.NewCommandTag("INSERT 0 1"), nil
			}
			return pgconn.CommandTag{}, fmt.Errorf("unexpected Exec: %s", sql)
		},
	}

	pushes := 0
	h := &Handlers{
		DB: db.New(mock),
		VMD: &stubVMD{updatePreviewFn: func(_ context.Context, id, access string, ports map[int32]vmdclient.PortPolicy, revision int64) error {
			pushes++
			if id != sandboxID.String() || access != preview.AccessPrivate || revision != 11 {
				t.Errorf("push = (%q, %q, %d), want (%q, %q, 11)", id, access, revision, sandboxID, preview.AccessPrivate)
			}
			if len(ports) != 2 {
				t.Errorf("pushed ports = %#v, want 3000 and 8080", ports)
			}
			if _, ok := ports[3000]; !ok {
				t.Errorf("pushed ports = %#v, missing 3000", ports)
			}
			if _, ok := ports[8080]; !ok {
				t.Errorf("pushed ports = %#v, missing 8080", ports)
			}
			if ports[3000].Access != preview.AccessPrivateBrowserV1 || ports[8080].Access != preview.AccessPublic {
				t.Errorf("pushed modes = %#v, want private_browser_v1/public", ports)
			}
			return nil
		}},
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sandboxes/"+sandboxID.String()+"/preview-ports", strings.NewReader(`{"port":3000}`))
	setupPreviewRouter(h, teamID.String()).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if pushes != 1 {
		t.Fatalf("policy pushes = %d, want 1", pushes)
	}
	var body publishedPortResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Port != 3000 || body.Access != preview.AccessPrivate {
		t.Fatalf("response = (%+v, %v), want private port 3000", body, err)
	}
	select {
	case <-activityFinished:
	case <-time.After(time.Second):
		t.Fatal("publish activity was not written")
	}
}

func TestPublishPreviewPortUsesStrictRequestShape(t *testing.T) {
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			return errorRow(fmt.Errorf("DB must not be called: %s", sql))
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, fmt.Errorf("DB must not be called: %s", sql)
		},
	}
	h := &Handlers{DB: db.New(mock)}
	sandboxID, teamID := uuid.New(), uuid.New()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sandboxes/"+sandboxID.String()+"/preview-ports", strings.NewReader(`{"port":3000,"label":"web"}`))
	setupPreviewRouter(h, teamID.String()).ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
}

func TestPreviewPortMutationsRejectReservedBoxdPortBeforeDB(t *testing.T) {
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			return errorRow(fmt.Errorf("DB must not be called: %s", sql))
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, fmt.Errorf("DB must not be called: %s", sql)
		},
	}
	h := &Handlers{DB: db.New(mock)}
	sandboxID, teamID := uuid.New(), uuid.New()
	tests := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{
			name:   "publish",
			method: http.MethodPost,
			path:   "/sandboxes/" + sandboxID.String() + "/preview-ports",
			body:   fmt.Sprintf(`{"port":%d}`, preview.ReservedBoxdPort),
		},
		{
			name:   "unpublish",
			method: http.MethodDelete,
			path:   fmt.Sprintf("/sandboxes/%s/preview-ports/%d", sandboxID, preview.ReservedBoxdPort),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			setupPreviewRouter(h, teamID.String()).ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "reserved") {
				t.Fatalf("body = %q, want reserved-port explanation", w.Body.String())
			}
		})
	}
}

func TestUnpublishPreviewPortRetryRepushesFullAllowlist(t *testing.T) {
	sandboxID, teamID := uuid.New(), uuid.New()
	sandbox := db.Sandbox{
		ID: sandboxID, TeamID: teamID, HostID: "host-a", Name: "preview",
	}
	revision := int64(40)
	deleteCalls := 0
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "-- name: GetSandbox :one"):
				return sandboxRow(sandbox)
			case strings.Contains(sql, "-- name: LockSandboxForPreviewMutation :one"):
				return scalarUUIDRow(sandboxID)
			case strings.Contains(sql, "-- name: AdvanceSandboxPreviewPolicy :one"):
				revision++
				return previewPolicyRow(preview.AccessPublic, revision)
			default:
				return errorRow(fmt.Errorf("unexpected QueryRow: %s", sql))
			}
		},
		queryFn: func(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
			if strings.Contains(sql, "-- name: ListPublishedPorts :many") {
				return previewPortRows(8080), nil
			}
			return nil, fmt.Errorf("unexpected Query: %s", sql)
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			if strings.Contains(sql, "-- name: EnsureSandboxPreviewPolicy :exec") {
				return pgconn.NewCommandTag("INSERT 0 1"), nil
			}
			if strings.Contains(sql, "-- name: UnpublishPort :execrows") {
				deleteCalls++
				if deleteCalls == 1 {
					return pgconn.NewCommandTag("DELETE 1"), nil
				}
				return pgconn.NewCommandTag("DELETE 0"), nil
			}
			return pgconn.CommandTag{}, fmt.Errorf("unexpected Exec: %s", sql)
		},
	}

	var pushedRevisions []int64
	h := &Handlers{
		DB: db.New(mock),
		VMD: &stubVMD{updatePreviewFn: func(_ context.Context, id, access string, ports map[int32]vmdclient.PortPolicy, gotRevision int64) error {
			if id != sandboxID.String() || access != preview.AccessPublic {
				t.Errorf("push target = (%q, %q), want (%q, %q)", id, access, sandboxID, preview.AccessPublic)
			}
			if len(ports) != 1 {
				t.Errorf("pushed ports = %#v, want only 8080", ports)
			} else if _, ok := ports[8080]; !ok {
				t.Errorf("pushed ports = %#v, want only 8080", ports)
			}
			pushedRevisions = append(pushedRevisions, gotRevision)
			if len(pushedRevisions) == 1 {
				return fmt.Errorf("first policy push failed")
			}
			return nil
		}},
	}
	router := setupPreviewRouter(h, teamID.String())
	wantStatuses := []int{http.StatusInternalServerError, http.StatusNoContent}
	for attempt := 0; attempt < 2; attempt++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodDelete, "/sandboxes/"+sandboxID.String()+"/preview-ports/3000", nil)
		router.ServeHTTP(w, req)
		if w.Code != wantStatuses[attempt] {
			t.Fatalf("attempt %d status = %d, want %d; body: %s", attempt+1, w.Code, wantStatuses[attempt], w.Body.String())
		}
	}

	if deleteCalls != 2 {
		t.Fatalf("DELETE calls = %d, want 2", deleteCalls)
	}
	if len(pushedRevisions) != 2 || pushedRevisions[0] != 41 || pushedRevisions[1] != 42 {
		t.Fatalf("pushed revisions = %#v, want [41 42]", pushedRevisions)
	}
}

var previewHeaderTokenTestSeed = []byte("preview-token-test-seed-32-bytes!!")

type previewCredentialTestEnv struct {
	sandboxID uuid.UUID
	teamID    uuid.UUID
	sandbox   db.Sandbox
	h         *Handlers
	router    *gin.Engine

	published        bool
	access           string
	version          int64
	otherVersion     int64
	revision         int64
	revisionBumps    int
	rotationCalls    int
	lockedStatus     db.SandboxStatus
	capabilities     map[string]bool
	capabilityChecks [][]string
	credentialPush   func(context.Context, string, string, map[int32]vmdclient.PortPolicy, int64) error
}

func newPreviewCredentialTestEnv(t *testing.T) *previewCredentialTestEnv {
	t.Helper()
	e := &previewCredentialTestEnv{
		sandboxID: uuid.New(), teamID: uuid.New(),
		published: true, access: preview.AccessPrivate, version: 7, otherVersion: 3, revision: 10,
		lockedStatus: db.SandboxStatusActive,
		capabilities: map[string]bool{
			preview.HostCapabilityPorts:           true,
			preview.HostCapabilityPortAccess:      true,
			preview.HostCapabilityPortTokens:      true,
			preview.HostCapabilityPortBrowserAuth: true,
		},
	}
	e.sandbox = db.Sandbox{
		ID: e.sandboxID, TeamID: e.teamID, HostID: "token-host", Name: "token-sandbox",
		Status: db.SandboxStatusActive,
	}
	getPortRow := func() pgx.Row {
		if !e.published {
			return errorRow(pgx.ErrNoRows)
		}
		return &mockRow{scanFn: func(dest ...any) error {
			*dest[0].(*int32) = 3000
			*dest[1].(*string) = e.access
			*dest[2].(*int64) = e.version
			return nil
		}}
	}
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "-- name: GetSandbox :one"):
				return sandboxRow(e.sandbox)
			case strings.Contains(sql, "-- name: GetSandboxStatusForPreviewMutation :one"):
				return &mockRow{scanFn: func(dest ...any) error {
					*dest[0].(*db.SandboxStatus) = e.lockedStatus
					return nil
				}}
			case strings.Contains(sql, "-- name: GetPublishedPreviewPort :one"):
				return getPortRow()
			case (strings.Contains(sql, "-- name: HostHasCapabilities :one") || strings.Contains(sql, "-- name: HostHasCapabilitiesUnlocked :one")):
				required, _ := args[0].([]string)
				e.capabilityChecks = append(e.capabilityChecks, append([]string(nil), required...))
				available := true
				for _, capability := range required {
					available = available && e.capabilities[capability]
				}
				return scalarBoolRow(available)
			case strings.Contains(sql, "-- name: LockSandboxForPreviewMutation :one"):
				return scalarUUIDRow(e.sandboxID)
			case strings.Contains(sql, "-- name: RotatePublishedPreviewPortToken :one"):
				if !e.published {
					return errorRow(pgx.ErrNoRows)
				}
				if e.access == preview.AccessPrivate {
					e.version++
				}
				e.rotationCalls++
				return &mockRow{scanFn: func(dest ...any) error {
					*dest[0].(*int32) = 3000
					*dest[1].(*string) = e.access
					*dest[2].(*int64) = e.version
					return nil
				}}
			case strings.Contains(sql, "-- name: AdvanceSandboxPreviewPolicy :one"):
				e.revision++
				e.revisionBumps++
				return previewPolicyRowWithWire(preview.AccessPrivate, preview.AccessPrivate, e.revision)
			case strings.Contains(sql, "-- name: CreateActivity :one"):
				return activityRow()
			default:
				return errorRow(fmt.Errorf("unexpected QueryRow: %s", sql))
			}
		},
		queryFn: func(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
			if !strings.Contains(sql, "-- name: ListPublishedPorts :many") {
				return nil, fmt.Errorf("unexpected Query: %s", sql)
			}
			if !e.published {
				return previewPortPolicyRows(), nil
			}
			rows := []publishedPortResponse{{Port: 3000, Access: e.access, TokenVersion: e.version}}
			if e.otherVersion > 0 {
				rows = append(rows, publishedPortResponse{Port: 8080, Access: preview.AccessPrivate, TokenVersion: e.otherVersion})
			}
			return previewPortPolicyRows(rows...), nil
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			if strings.Contains(sql, "-- name: EnsureSandboxPreviewPolicy :exec") {
				return pgconn.NewCommandTag("INSERT 0 0"), nil
			}
			return pgconn.CommandTag{}, fmt.Errorf("unexpected Exec: %s", sql)
		},
	}
	e.h = &Handlers{
		DB: db.New(mock), Config: &config.Config{SandboxAccessTokenSeed: previewHeaderTokenTestSeed},
		VMD: &stubVMD{updatePreviewFn: func(ctx context.Context, id, access string, ports map[int32]vmdclient.PortPolicy, revision int64) error {
			if e.credentialPush != nil {
				return e.credentialPush(ctx, id, access, ports, revision)
			}
			return nil
		}},
	}
	e.router = setupPreviewRouter(e.h, e.teamID.String())
	return e
}

func (e *previewCredentialTestEnv) request(method, suffix, body string) *httptest.ResponseRecorder {
	var req *http.Request
	path := "/sandboxes/" + e.sandboxID.String() + "/preview-ports/3000" + suffix
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	return w
}

func TestMintPreviewTokenActivatesExactHeaderPolicyBeforeReturningCredential(t *testing.T) {
	e := newPreviewCredentialTestEnv(t)
	var pushed bool
	e.credentialPush = func(_ context.Context, id, access string, ports map[int32]vmdclient.PortPolicy, revision int64) error {
		pushed = true
		if id != e.sandboxID.String() || access != preview.AccessPrivate || revision != 11 {
			t.Fatalf("push = (%q,%q,%d), want sandbox/raw-private/revision 11", id, access, revision)
		}
		if got := ports[3000]; got.Access != preview.AccessPrivateBrowserV1 || got.TokenVersion != 7 {
			t.Fatalf("private port push = %#v, want private_browser_v1 v7", got)
		}
		if got := ports[8080]; got.Access != preview.AccessPrivateBrowserV1 || got.TokenVersion != 3 {
			t.Fatalf("sibling private port push = %#v, want private_browser_v1 v3", got)
		}
		return nil
	}
	w := e.request(http.MethodPost, "/token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if !pushed || e.revisionBumps != 1 {
		t.Fatalf("pushed=%v revision bumps=%d, want activation push after one no-op bump", pushed, e.revisionBumps)
	}
	if len(e.capabilityChecks) != 2 {
		t.Fatalf("mint capability checks=%d, want preflight and transaction recheck", len(e.capabilityChecks))
	}
	for _, got := range e.capabilityChecks {
		if !slices.Equal(got, previewBrowserCapabilities()) {
			t.Fatalf("mint capabilities=%v, want %v", got, previewBrowserCapabilities())
		}
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	body := parseJSON(t, w)
	if body["query_param"] != auth.PreviewTokenQueryParam {
		t.Fatalf("query_param = %#v, want %q", body["query_param"], auth.PreviewTokenQueryParam)
	}
	if _, exists := body["cookie"]; exists {
		t.Fatalf("API response exposed cookie value: %s", w.Body.String())
	}
	if body["header"] != auth.PreviewTokenHeader || body["access"] != preview.AccessPrivate || body["preview_access"] != preview.AccessPrivate {
		t.Fatalf("credential metadata = %#v", body)
	}
	if body["token_version"] != float64(7) {
		t.Fatalf("token_version = %v, want 7", body["token_version"])
	}
	token, _ := body["token"].(string)
	if token == "" || !auth.VerifyPreviewToken(previewHeaderTokenTestSeed, e.sandboxID.String(), 3000, 7, token) {
		t.Fatal("returned token does not verify for the exact sandbox/port/generation")
	}
	if auth.VerifyPreviewToken(previewHeaderTokenTestSeed, e.sandboxID.String(), 8080, 7, token) {
		t.Fatal("returned token verified for a sibling port")
	}
}

func TestMintPreviewTokenRejectsUnpublishedAndPublicPorts(t *testing.T) {
	for _, tc := range []struct {
		name      string
		configure func(*previewCredentialTestEnv)
		want      int
	}{
		{name: "unpublished", configure: func(e *previewCredentialTestEnv) { e.published = false }, want: http.StatusNotFound},
		{name: "public", configure: func(e *previewCredentialTestEnv) { e.access = preview.AccessPublic }, want: http.StatusConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newPreviewCredentialTestEnv(t)
			tc.configure(e)
			w := e.request(http.MethodPost, "/token", "")
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d; body: %s", w.Code, tc.want, w.Body.String())
			}
			if e.revisionBumps != 0 {
				t.Fatalf("invalid mint advanced revision %d times", e.revisionBumps)
			}
		})
	}
}

func TestMintPreviewTokenExpiryBoundariesAndExactClaim(t *testing.T) {
	for _, body := range []string{
		`{"expires_in_seconds":0}`,
		`{"expires_in_seconds":-1}`,
		`{"expires_in_seconds":604801}`,
	} {
		e := newPreviewCredentialTestEnv(t)
		w := e.request(http.MethodPost, "/token", body)
		if w.Code != http.StatusBadRequest || e.revisionBumps != 0 {
			t.Fatalf("body %s: status=%d bumps=%d, want 400/0; response=%s", body, w.Code, e.revisionBumps, w.Body.String())
		}
	}

	for _, seconds := range []int64{1, maxPreviewTokenExpirySeconds} {
		e := newPreviewCredentialTestEnv(t)
		before := time.Now().UTC().Unix()
		w := e.request(http.MethodPost, "/token", fmt.Sprintf(`{"expires_in_seconds":%d}`, seconds))
		if w.Code != http.StatusOK {
			t.Fatalf("expiry %d: status=%d body=%s", seconds, w.Code, w.Body.String())
		}
		body := parseJSON(t, w)
		expiresAt, err := time.Parse(time.RFC3339, body["expires_at"].(string))
		if err != nil {
			t.Fatalf("parse expires_at: %v", err)
		}
		if expiresAt.Nanosecond() != 0 || expiresAt.Unix() < before+seconds || expiresAt.Unix() > time.Now().UTC().Unix()+seconds {
			t.Fatalf("expires_at=%s is not the exact whole-second requested lifetime", expiresAt)
		}
		token := body["token"].(string)
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Fatalf("token shape = %q", token)
		}
		raw, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatalf("decode claims: %v", err)
		}
		var claims auth.PreviewClaims
		if err := json.Unmarshal(raw, &claims); err != nil {
			t.Fatalf("decode claims JSON: %v", err)
		}
		if claims.ExpiresAt != expiresAt.Unix() {
			t.Fatalf("signed expiry=%d response expiry=%d", claims.ExpiresAt, expiresAt.Unix())
		}
	}
}

func TestMintPreviewTokenMissingSeedAndHostDeliveryFailuresReturnNoCredential(t *testing.T) {
	t.Run("missing seed", func(t *testing.T) {
		e := newPreviewCredentialTestEnv(t)
		e.h.Config.SandboxAccessTokenSeed = nil
		w := e.request(http.MethodPost, "/token", "")
		if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "spv1.") || e.revisionBumps != 0 {
			t.Fatalf("status=%d bumps=%d body=%s", w.Code, e.revisionBumps, w.Body.String())
		}
	})
	t.Run("active not found", func(t *testing.T) {
		e := newPreviewCredentialTestEnv(t)
		e.credentialPush = func(context.Context, string, string, map[int32]vmdclient.PortPolicy, int64) error {
			return status.Error(codes.NotFound, "active VM missing")
		}
		w := e.request(http.MethodPost, "/token", "")
		if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "spv1.") {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
	})
	t.Run("serialized active status overrides stale paused read", func(t *testing.T) {
		e := newPreviewCredentialTestEnv(t)
		e.sandbox.Status = db.SandboxStatusPaused
		e.lockedStatus = db.SandboxStatusActive
		e.credentialPush = func(context.Context, string, string, map[int32]vmdclient.PortPolicy, int64) error {
			return status.Error(codes.NotFound, "active VM missing")
		}
		w := e.request(http.MethodPost, "/token", "")
		if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "spv1.") {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
	})
	t.Run("paused not found reconciles on resume", func(t *testing.T) {
		e := newPreviewCredentialTestEnv(t)
		e.sandbox.Status = db.SandboxStatusPaused
		e.lockedStatus = db.SandboxStatusPaused
		e.credentialPush = func(context.Context, string, string, map[int32]vmdclient.PortPolicy, int64) error {
			return status.Error(codes.NotFound, "paused VM absent")
		}
		w := e.request(http.MethodPost, "/token", "")
		if w.Code != http.StatusOK {
			t.Fatalf("status=%d want 200 for paused NotFound; body=%s", w.Code, w.Body.String())
		}
	})
}

func TestRotatePreviewTokenRevokesOnlyTargetBeforeCapabilityAndDeliveryChecks(t *testing.T) {
	e := newPreviewCredentialTestEnv(t)
	e.capabilities[preview.HostCapabilityPortBrowserAuth] = false
	w := e.request(http.MethodPost, "/token/rotate", "")
	if w.Code != http.StatusConflict {
		t.Fatalf("status=%d want 409 after revocation; body=%s", w.Code, w.Body.String())
	}
	if e.version != 8 || e.otherVersion != 3 || e.rotationCalls != 1 || e.revisionBumps != 1 {
		t.Fatalf("state target=%d sibling=%d rotations=%d revisions=%d", e.version, e.otherVersion, e.rotationCalls, e.revisionBumps)
	}
	if strings.Contains(w.Body.String(), "spv1.") {
		t.Fatalf("failed rotation leaked credential: %s", w.Body.String())
	}
}

func TestRotatePreviewTokenPushesNewExactGenerationThenReturnsHeaderToken(t *testing.T) {
	e := newPreviewCredentialTestEnv(t)
	var pushed bool
	e.credentialPush = func(_ context.Context, _ string, access string, ports map[int32]vmdclient.PortPolicy, revision int64) error {
		pushed = true
		if access != preview.AccessPrivate || revision != 11 ||
			ports[3000].Access != preview.AccessPrivateBrowserV1 || ports[3000].TokenVersion != 8 ||
			ports[8080].Access != preview.AccessPrivateBrowserV1 || ports[8080].TokenVersion != 3 {
			t.Fatalf("rotation push access=%q revision=%d ports=%#v", access, revision, ports)
		}
		return nil
	}
	w := e.request(http.MethodPost, "/token/rotate", "")
	if w.Code != http.StatusOK || !pushed {
		t.Fatalf("status=%d pushed=%v body=%s", w.Code, pushed, w.Body.String())
	}
	body := parseJSON(t, w)
	if body["token_version"] != float64(8) || body["header"] != auth.PreviewTokenHeader || body["query_param"] != auth.PreviewTokenQueryParam {
		t.Fatalf("response=%#v", body)
	}
	if _, exists := body["cookie"]; exists {
		t.Fatalf("rotation response exposed cookie value: %#v", body)
	}
	if !auth.VerifyPreviewToken(previewHeaderTokenTestSeed, e.sandboxID.String(), 3000, 8, body["token"].(string)) {
		t.Fatal("replacement token does not verify at the new generation")
	}
}

func TestRotationAuditDetachesCanceledRequestContext(t *testing.T) {
	sandbox := db.Sandbox{ID: uuid.New(), TeamID: uuid.New(), Name: "detached-audit"}
	called := false
	mock := &mockDBTX{queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
		if !strings.Contains(sql, "-- name: CreateActivity :one") {
			return errorRow(fmt.Errorf("unexpected QueryRow: %s", sql))
		}
		called = true
		if err := ctx.Err(); err != nil {
			t.Errorf("rotation audit inherited canceled request context: %v", err)
		}
		auditStatus, _ := args[9].(*string)
		auditError, _ := args[12].(*string)
		if args[8] != "preview_token_rotated" || auditStatus == nil || *auditStatus != "error" || auditError == nil || *auditError != "delivery_failed" {
			t.Errorf("rotation audit args=%#v", args)
		}
		metadata, _ := args[13].([]byte)
		if strings.Contains(string(metadata), "spv1.") || !strings.Contains(string(metadata), `"token_version":8`) || !strings.Contains(string(metadata), `"delivery_outcome":"delivery_failed"`) {
			t.Errorf("rotation audit metadata=%s", metadata)
		}
		return activityRow()
	}}
	h := &Handlers{DB: db.New(mock)}
	requestCtx, cancel := context.WithCancel(context.Background())
	cancel()
	h.logPreviewTokenRotationActivity(requestCtx, sandbox, sandbox.TeamID, nil, 3000, 8, "delivery_failed", errors.New("VMD failed"))
	if !called {
		t.Fatal("rotation audit was not attempted")
	}
}

func TestRotatePreviewTokenRejectsPublicAndUnpublishedWithoutRevisionAdvance(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*previewCredentialTestEnv)
		want int
	}{
		{"public", func(e *previewCredentialTestEnv) { e.access = preview.AccessPublic }, http.StatusConflict},
		{"unpublished", func(e *previewCredentialTestEnv) { e.published = false }, http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newPreviewCredentialTestEnv(t)
			tc.set(e)
			w := e.request(http.MethodPost, "/token/rotate", "")
			if w.Code != tc.want || e.revisionBumps != 0 {
				t.Fatalf("status=%d revisions=%d want %d/0; body=%s", w.Code, e.revisionBumps, tc.want, w.Body.String())
			}
		})
	}
}

func TestPreviewTokenRoutesRejectReservedBoxdPortBeforeDatabaseAccess(t *testing.T) {
	e := newPreviewCredentialTestEnv(t)
	for _, suffix := range []string{"/token", "/token/rotate"} {
		path := "/sandboxes/" + e.sandboxID.String() + "/preview-ports/49983" + suffix
		w := httptest.NewRecorder()
		e.router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, nil))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s status=%d want 400; body=%s", suffix, w.Code, w.Body.String())
		}
	}
	if e.revisionBumps != 0 || e.rotationCalls != 0 {
		t.Fatalf("reserved port reached mutation: revisions=%d rotations=%d", e.revisionBumps, e.rotationCalls)
	}
}
