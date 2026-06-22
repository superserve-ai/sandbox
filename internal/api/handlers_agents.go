package api

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	actorrt "github.com/superserve-ai/sandbox/internal/actor"
	"github.com/superserve-ai/sandbox/internal/actor/vmdwaker"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/state"
)

// AgentTargetResolver is the production vmdwaker.Resolver: it maps an Actor to
// the template snapshot its sandbox boots from. This is the third of the three
// production seams that wire the Actor runtime to vmd (with the vmd client as
// SandboxBooter and a boxd exec/stream Deliverer). Wire it in controlplane main:
//
//	waker  := vmdwaker.New(vmdClient, boxdDeliverer, AgentTargetResolver(q, systemTeam))
//	router := actor.NewRouter(actor.NewRegistry(pgstore.New(q), nil), waker, hostID, 16)
//	handlers.Agents = router
func AgentTargetResolver(q *db.Queries, systemTeam uuid.UUID) vmdwaker.Resolver {
	return agentTargetResolver(q, systemTeam, nil)
}

// AgentTargetResolverWithState is AgentTargetResolver that also auto-provisions
// the Actor's durable /state: on each resolve it ensures the per-Actor state
// volume exists via the state.Provider (keyed by the Actor's durable identity)
// and, for block-device backends, carries its host path in Target.StateDiskPath
// for vmd to attach as the sandbox's /state drive. Directory/FUSE backends
// (Mesa) provision the repo but leave StateDiskPath empty (the guest mounts it).
func AgentTargetResolverWithState(q *db.Queries, systemTeam uuid.UUID, provider state.Provider) vmdwaker.Resolver {
	return agentTargetResolver(q, systemTeam, provider)
}

func agentTargetResolver(q *db.Queries, systemTeam uuid.UUID, provider state.Provider) vmdwaker.Resolver {
	return func(a actorrt.Actor) (vmdwaker.Target, error) {
		tid, err := uuid.Parse(a.Template)
		if err != nil {
			return vmdwaker.Target{}, fmt.Errorf("actor %q has no template binding", a.Name)
		}
		team, err := uuid.Parse(a.TeamID)
		if err != nil {
			return vmdwaker.Target{}, err
		}
		tpl, err := q.GetTemplate(context.Background(), db.GetTemplateParams{ID: tid, TeamID: team, TeamID_2: systemTeam})
		if err != nil {
			return vmdwaker.Target{}, fmt.Errorf("resolve template for actor %q: %w", a.Name, err)
		}
		if tpl.SnapshotPath == nil || tpl.MemPath == nil {
			return vmdwaker.Target{}, fmt.Errorf("template for actor %q is not ready (no snapshot)", a.Name)
		}
		t := vmdwaker.Target{SnapshotPath: *tpl.SnapshotPath, MemPath: *tpl.MemPath, TeamID: a.TeamID}
		if tpl.BasePath != nil {
			t.BasePath = *tpl.BasePath
		}
		if tpl.DeltaPath != nil {
			t.DeltaDir = filepath.Dir(*tpl.DeltaPath)
		}
		// Auto-provision the Actor's durable /state, addressed by its stable
		// identity (a.ID) so state follows the Actor across sandboxes/hosts.
		if provider != nil {
			m, err := provider.Mount(context.Background(), a.ID, "/state")
			if err != nil {
				return vmdwaker.Target{}, fmt.Errorf("provision /state for actor %q: %w", a.Name, err)
			}
			if m.IsBlockDevice {
				t.StateDiskPath = m.Path
			}
		}
		return t, nil
	}
}

type sendAgentRequest struct {
	Agent   string `json:"agent"`   // durable Actor name (unique per team); created on first reference
	Message string `json:"message"` // the turn's input
}

// SendAgentEvent is the durable-Actor client plane: route a turn to an Actor and
// stream its reply. The Actor is resolved-or-created by name (wake-on-reference),
// woken if cold (vmd tiered restore via the Waker), and the event is serialized
// through its single-writer inbox. The reply streams back as the harness
// produces it — and survives the Actor hibernating mid-turn (the Relay). This is
// the HTTP binding over the internal/actor runtime; `agent→agent`, webhooks, and
// alarms route the same way (fire-and-forget, no Out sink).
func (h *Handlers) SendAgentEvent(c *gin.Context) {
	if h.Agents == nil {
		respondErrorMsg(c, "not_implemented", "the durable-Actor runtime is not enabled on this deployment", http.StatusNotImplemented)
		return
	}
	var req sendAgentRequest
	if err := bindJSONStrict(c, &req); err != nil {
		respondErrorMsg(c, "bad_request", "Request body is not valid JSON or contains unknown fields.", http.StatusBadRequest)
		return
	}
	if req.Agent == "" {
		respondErrorMsg(c, "bad_request", "agent is required", http.StatusBadRequest)
		return
	}
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}

	relay := actorrt.NewRelay()
	ev := actorrt.Event{ID: uuid.NewString(), Type: "msg", Payload: []byte(req.Message), Out: relay}

	// Route wakes the Actor (cold→restore) and enqueues the event on its serial
	// inbox; the harness output streams into `relay`, Closed at turn end. The
	// route/turn runs on a detached context so a slow client read can't cancel an
	// in-flight turn — the stream loop below honors the client's context.
	routeCtx := context.WithoutCancel(c.Request.Context())
	if err := h.Agents.Route(routeCtx, teamID.String(), req.Agent, actorrt.Actor{}, ev); err != nil {
		// ErrLeaseHeld → the Actor is live on another host; the caller retries or
		// the edge forwards to that host.
		respondErrorMsg(c, "conflict", "agent is live on another host; retry", http.StatusConflict)
		return
	}

	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Header("X-Accel-Buffering", "no") // don't let a reverse proxy buffer the stream
	flusher, _ := c.Writer.(http.Flusher)
	cur := int64(0)
	for {
		chunk, ok, err := relay.ReadFrom(c.Request.Context(), cur)
		if err != nil {
			return // client disconnected; the turn finishes detached
		}
		if !ok {
			return // turn complete — clean end of stream
		}
		_, _ = c.Writer.Write(chunk.Data)
		if flusher != nil {
			flusher.Flush()
		}
		cur = chunk.Seq
	}
}
