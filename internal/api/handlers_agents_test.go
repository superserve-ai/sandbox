package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	actorrt "github.com/superserve-ai/sandbox/internal/actor"
	"github.com/superserve-ai/sandbox/internal/actor/vmdwaker"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/state"
)

// fakeBooter satisfies vmdwaker.SandboxBooter without a real vmd.
type fakeBooter struct{}

func (fakeBooter) RestoreSnapshot(context.Context, string, string, string, string, string, string, string, map[string]string) (string, uint32, uint32, error) {
	return "10.0.0.1", 1, 1024, nil
}
func (fakeBooter) BareResumeInstance(context.Context, string) (string, uint32, uint32, error) {
	return "10.0.0.1", 1, 1024, nil
}
func (fakeBooter) DestroyInstance(context.Context, string, bool) error { return nil }

// echoDeliverer stands in for the real boxd harness delivery: it writes the
// turn's reply into the output sink.
type echoDeliverer struct{}

func (echoDeliverer) Deliver(_ context.Context, _ string, ev actorrt.Event) error {
	if ev.Out != nil {
		ev.Out.Append(1, []byte("reply: "))
		ev.Out.Append(2, ev.Payload)
	}
	return nil
}

func agentSendReq(body string) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/agents/send", strings.NewReader(body))
}

func newAgentRouter() *actorrt.Router {
	resolver := func(actorrt.Actor) (vmdwaker.Target, error) {
		return vmdwaker.Target{SnapshotPath: "/snap/s", MemPath: "/snap/m"}, nil
	}
	waker := vmdwaker.New(fakeBooter{}, echoDeliverer{}, resolver)
	reg := actorrt.NewRegistry(actorrt.NewMemStore(), nil)
	return actorrt.NewRouter(reg, waker, "host-test", 8)
}

func TestSendAgentEvent_StreamsReply(t *testing.T) {
	h := &Handlers{Agents: newAgentRouter(), DB: db.New(&mockDBTX{})}
	w := httptest.NewRecorder()
	setupTestRouter(h, uuid.New().String()).ServeHTTP(w, agentSendReq(`{"agent":"support/t1","message":"hi"}`))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if got := w.Body.String(); got != "reply: hi" {
		t.Fatalf("streamed reply = %q, want %q", got, "reply: hi")
	}
}

func TestSendAgentEvent_DisabledWhenNoRuntime(t *testing.T) {
	h := &Handlers{DB: db.New(&mockDBTX{})} // Agents nil
	w := httptest.NewRecorder()
	setupTestRouter(h, uuid.New().String()).ServeHTTP(w, agentSendReq(`{"agent":"x","message":"y"}`))
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("nil runtime should 501, got %d", w.Code)
	}
}

func TestSendAgentEvent_MissingAgent(t *testing.T) {
	h := &Handlers{Agents: newAgentRouter(), DB: db.New(&mockDBTX{})}
	w := httptest.NewRecorder()
	setupTestRouter(h, uuid.New().String()).ServeHTTP(w, agentSendReq(`{"message":"y"}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing agent should 400, got %d", w.Code)
	}
}

func TestAgentTargetResolver(t *testing.T) {
	tplID := uuid.New()
	tpl := defaultReadyTemplate() // has SnapshotPath + MemPath
	mock := &mockDBTX{queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
		if strings.Contains(sql, "FROM template") {
			return templateRow(tpl)
		}
		return notFoundRow()
	}}
	resolve := AgentTargetResolver(db.New(mock), uuid.Nil)
	target, err := resolve(actorrt.Actor{Template: tplID.String(), TeamID: uuid.New().String(), Name: "agent"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if target.SnapshotPath == "" || target.MemPath == "" {
		t.Fatalf("resolved target missing snapshot paths: %+v", target)
	}
}

func TestAgentTargetResolver_NoTemplateBinding(t *testing.T) {
	resolve := AgentTargetResolver(db.New(&mockDBTX{}), uuid.Nil)
	if _, err := resolve(actorrt.Actor{Template: "", TeamID: uuid.New().String(), Name: "x"}); err == nil {
		t.Fatal("actor with no template binding should error")
	}
}

// fakeStateProvider records the identity it provisioned and reports a block (or
// directory) mount so the resolver's /state wiring is testable without a backend.
type fakeStateProvider struct {
	block     bool
	mountedID string
	mountErr  error
}

func (f *fakeStateProvider) Mount(_ context.Context, identity, _ string) (*state.Mount, error) {
	if f.mountErr != nil {
		return nil, f.mountErr
	}
	f.mountedID = identity
	return &state.Mount{Identity: identity, Path: "/srv/state/" + identity + "/state.img", IsBlockDevice: f.block}, nil
}
func (f *fakeStateProvider) Checkpoint(context.Context, string, string) (state.Checkpoint, error) {
	return state.Checkpoint{}, nil
}
func (f *fakeStateProvider) Branch(context.Context, string, string, string) error { return nil }
func (f *fakeStateProvider) Rollback(context.Context, string, string) error       { return nil }
func (f *fakeStateProvider) ListCheckpoints(context.Context, string) ([]state.Checkpoint, error) {
	return nil, nil
}

func resolverWithTemplate(t *testing.T, provider state.Provider) (vmdwaker.Resolver, string) {
	t.Helper()
	tplID := uuid.New()
	tpl := defaultReadyTemplate()
	mock := &mockDBTX{queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
		if strings.Contains(sql, "FROM template") {
			return templateRow(tpl)
		}
		return notFoundRow()
	}}
	return AgentTargetResolverWithState(db.New(mock), uuid.Nil, provider), tplID.String()
}

// TestAgentTargetResolverWithState_BlockDevice: a block-backed provider's image
// path is carried into the Target (keyed by the Actor's durable id) for vmd to
// attach as /state.
func TestAgentTargetResolverWithState_BlockDevice(t *testing.T) {
	fp := &fakeStateProvider{block: true}
	resolve, tpl := resolverWithTemplate(t, fp)
	act := actorrt.Actor{ID: "actor-xyz", Template: tpl, TeamID: uuid.New().String(), Name: "agent"}
	target, err := resolve(act)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if fp.mountedID != "actor-xyz" {
		t.Errorf("provider provisioned %q, want the Actor's durable id actor-xyz", fp.mountedID)
	}
	if target.StateDiskPath != "/srv/state/actor-xyz/state.img" {
		t.Errorf("StateDiskPath = %q, want the provisioned block image", target.StateDiskPath)
	}
}

// Directory/FUSE backends provision the volume but leave StateDiskPath empty (the
// guest mounts it), so vmd attaches no /state drive.
func TestAgentTargetResolverWithState_DirectoryBackendNoDrive(t *testing.T) {
	fp := &fakeStateProvider{block: false}
	resolve, tpl := resolverWithTemplate(t, fp)
	target, err := resolve(actorrt.Actor{ID: "a1", Template: tpl, TeamID: uuid.New().String(), Name: "agent"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if target.StateDiskPath != "" {
		t.Errorf("directory backend must not set StateDiskPath, got %q", target.StateDiskPath)
	}
	if fp.mountedID != "a1" {
		t.Errorf("directory backend should still provision the volume, mountedID=%q", fp.mountedID)
	}
}

// nil provider (no durable /state configured) → no provisioning, empty path.
func TestAgentTargetResolverWithState_NilProvider(t *testing.T) {
	resolve, tpl := resolverWithTemplate(t, nil)
	target, err := resolve(actorrt.Actor{ID: "a1", Template: tpl, TeamID: uuid.New().String(), Name: "agent"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if target.StateDiskPath != "" {
		t.Errorf("nil provider must leave StateDiskPath empty, got %q", target.StateDiskPath)
	}
}
