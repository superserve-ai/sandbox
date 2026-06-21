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
)

// fakeBooter satisfies vmdwaker.SandboxBooter without a real vmd.
type fakeBooter struct{}

func (fakeBooter) RestoreSnapshot(context.Context, string, string, string, string, string, string, string, map[string]string) (string, uint32, uint32, error) {
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
