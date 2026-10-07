package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/auth"
)

func loggingMachineCapability() auth.MachineCapability {
	return auth.MachineCapability{
		PrincipalID: uuid.New(), CredentialID: uuid.New(), LineageID: uuid.New(), TeamID: uuid.MustParse(logTestTeam),
		SandboxID: uuid.MustParse(logTestSandbox), Operations: []auth.MachineOperation{auth.MachineOperationFileRead, auth.MachineOperationCommandRun},
		Audience: "sandbox-proxy", ExpiresAt: time.Now().Add(time.Minute), RevocationGeneration: 1,
	}
}

func machineLoggingProxy(t *testing.T, capability auth.MachineCapability, upstream http.Handler) (*Handler, *requestLogBuffer, string) {
	t.Helper()
	h, buf := loggingProxy(t, upstream)
	info := &h.resolver.(*stubResolver).info
	info.MachineOwned, info.OwnershipState = true, auth.OwnershipMachine
	info.MachineOwnerPrincipalID = capability.PrincipalID.String()
	h.machineAuthority = func(context.Context, uuid.UUID, uuid.UUID) (uint64, error) { return 1, nil }
	token, err := auth.SignMachineCapability(capability, logTestSeed, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return h, buf, token
}

func assertMachineLog(t *testing.T, event map[string]any, c auth.MachineCapability) {
	t.Helper()
	for k, v := range map[string]any{"actor_type": "machine", "actor_id": c.PrincipalID.String(), "credential_id": c.CredentialID.String(), "team_id": c.TeamID.String(), "auth_outcome": "authenticated", "attribution_status": "identified"} {
		if event[k] != v {
			t.Errorf("%s=%v want %v", k, event[k], v)
		}
	}
	if event["user_id"] != nil {
		t.Fatal("machine request acquired human identity")
	}
}

func TestMachineRequestLoggingRotationAndDenials(t *testing.T) {
	base := loggingMachineCapability()
	for _, name := range []string{"success", "rotation", "owner denial", "team denial", "scope denial", "target denial", "bad signature", "revoked", "authority failure", "api key", "verified human", "verified human without parent"} {
		t.Run(name, func(t *testing.T) {
			capability := base
			if name == "rotation" {
				capability.CredentialID, capability.LineageID = uuid.New(), uuid.New()
			}
			if name == "scope denial" {
				capability.Operations = []auth.MachineOperation{auth.MachineOperationCommandRun}
			}
			if name == "target denial" {
				capability.SandboxID = uuid.New()
			}
			if name == "api key" || strings.HasPrefix(name, "verified human") {
				capability.PrincipalID, capability.CredentialID, capability.LineageID = uuid.Nil, uuid.Nil, uuid.Nil
				capability.RevocationGeneration = 0
				capability.CallerKind, capability.ParentCredentialID = "api_key", uuid.New()
				if strings.HasPrefix(name, "verified human") {
					capability.CallerKind, capability.ActorID = "human", uuid.New()
				}
				if name == "verified human without parent" {
					capability.ParentCredentialID = uuid.Nil
				}
			}
			var served atomic.Int32
			h, buf, token := machineLoggingProxy(t, capability, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				served.Add(1)
				io.WriteString(w, "SYNTHETIC_FILE_CONTENT")
			}))
			status, outcome := 200, "authenticated"
			info := &h.resolver.(*stubResolver).info
			switch name {
			case "owner denial":
				info.MachineOwnerPrincipalID, status = uuid.NewString(), 403
			case "team denial":
				info.TeamID, status = uuid.NewString(), 403
			case "scope denial":
				status = 403
			case "target denial":
				status = 401
			case "bad signature":
				token += "invalid"
				status, outcome = 401, "invalid"
			case "revoked":
				h.machineAuthority = func(context.Context, uuid.UUID, uuid.UUID) (uint64, error) { return 2, nil }
				status, outcome = 401, "invalid"
			case "authority failure":
				h.machineAuthority = func(context.Context, uuid.UUID, uuid.UUID) (uint64, error) {
					return 0, errors.New("SYNTHETIC_AUTHORITY_SECRET")
				}
				status, outcome = 401, "error"
			}
			w := httptest.NewRecorder()
			r := loggingRequest("GET", "/files?path=/SYNTHETIC_PATH_SECRET", token)
			r.Header.Set("X-Machine-Principal", "SYNTHETIC_SPOOFED_PRINCIPAL")
			r.Header.Set("X-Actor-User-Id", "SYNTHETIC_SPOOFED_HUMAN")
			h.ServeHTTP(w, r)
			events := buf.events(t)
			if w.Code != status || len(events) != 1 || (status != 200 && served.Load() != 0) {
				t.Fatalf("status=%d events=%v served=%d", w.Code, events, served.Load())
			}
			e := events[0]
			if e["auth_outcome"] != outcome {
				t.Fatal(e)
			}
			if outcome == "authenticated" {
				if name == "api key" {
					if e["actor_type"] != "api_key" || e["actor_id"] != capability.ParentCredentialID.String() || e["credential_id"] != capability.ParentCredentialID.String() || e["user_id"] != nil {
						t.Fatalf("key creator became human: %v", e)
					}
				} else if strings.HasPrefix(name, "verified human") {
					if e["actor_type"] != "human" || e["actor_id"] != capability.ActorID.String() || e["user_id"] != capability.ActorID.String() {
						t.Fatal(e)
					}
					if capability.ParentCredentialID == uuid.Nil {
						if e["credential_id"] != nil {
							t.Fatal("fabricated credential", e)
						}
					} else if e["credential_id"] != capability.ParentCredentialID.String() {
						t.Fatal(e)
					}
				} else {
					assertMachineLog(t, e, capability)
				}
				if name != "target denial" && e["resource_team_id"] != info.TeamID {
					t.Fatal("lost resolved resource context")
				}
			} else if e["actor_id"] != nil || e["credential_id"] != nil || e["team_id"] != nil {
				t.Fatalf("unverified claims acquired identity: %v", e)
			}
			if strings.Contains(buf.text(), "SYNTHETIC") || strings.Contains(buf.text(), token) {
				t.Fatal("secret/content leaked to logs")
			}
		})
	}
}

func TestMachineRequestLoggingPeerPreservesOwnerIdentity(t *testing.T) {
	capability := loggingMachineCapability()
	h, buf, token := machineLoggingProxy(t, capability, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	owner := httptest.NewServer(PeerRequestLogging(h))
	defer owner.Close()
	peers, addr := startRoutingTestPeer(t, owner.Listener.Addr().String())
	router := NewRoutingHandler(h.domains, "edge", RouteLookupFunc(func(context.Context, string) (SandboxRoute, error) {
		return SandboxRoute{HostID: "owner", ProxyAddr: addr, Generation: 1}, nil
	}), peers, h, h.log)
	edge := httptest.NewServer(router)
	defer edge.Close()
	r, _ := http.NewRequest("GET", edge.URL+"/files?path=/data", nil)
	r.Host, r.Close = "boxd-"+logTestSandbox+".sandbox.test", true
	r.Header.Set(accessTokenHeader, token)
	spoofed := uuid.NewString()
	r.Header.Set(peerRequestIDHeader, spoofed)
	r.Header.Set("X-Machine-Principal", spoofed)
	resp, err := edge.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	events := awaitRequestEvents(t, buf, 2)
	if resp.StatusCode != 200 || len(events) != 2 || events[0]["request_id"] != events[1]["request_id"] || events[0]["request_id"] == spoofed {
		t.Fatal(events)
	}
	counts := map[string]int{}
	for _, e := range events {
		counts[e["event_type"].(string)]++
		if e["event_type"] == "request" {
			assertMachineLog(t, e, capability)
		} else if e["actor_id"] != nil || e["auth_outcome"] != "not_evaluated" {
			t.Fatal("forwarding edge asserted owner-verified caller identity")
		}
	}
	if counts["request"] != 1 || counts["proxy_forward"] != 1 {
		t.Fatal(events)
	}
}

func TestMachineRequestLoggingSessionRetainsHandshakeIdentity(t *testing.T) {
	capability := loggingMachineCapability()
	h, buf, token := machineLoggingProxy(t, capability, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Host = "boxd-" + logTestSandbox + ".sandbox.test"
		h.ServeHTTP(w, r)
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/exec/connect", &websocket.DialOptions{
		Subprotocols: []string{execProtocol, "token." + token},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	initial := awaitRequestEvents(t, buf, 1)
	if initial[0]["event_type"] != "session_start" {
		t.Fatal(initial)
	}
	assertMachineLog(t, initial[0], capability)
	if err := ws.Write(ctx, websocket.MessageText, []byte(`{"SYNTHETIC_CONTENT":"invalid start"}`)); err != nil {
		t.Fatal(err)
	}
	_, _, _ = ws.Read(ctx)
	events := awaitRequestEvents(t, buf, 2)
	if len(events) != 2 || events[1]["event_type"] != "session_complete" || events[1]["request_id"] != initial[0]["request_id"] {
		t.Fatal(events)
	}
	assertMachineLog(t, events[1], capability)
	if strings.Contains(buf.text(), "SYNTHETIC_CONTENT") || strings.Contains(buf.text(), token) {
		t.Fatal("session content/credential leaked")
	}
}

func TestMachineRequestLoggingPeerAuthorityFailure(t *testing.T) {
	capability := loggingMachineCapability()
	h, buf, token := machineLoggingProxy(t, capability, nil)
	var lookups atomic.Int32
	h.machineAuthority = func(context.Context, uuid.UUID, uuid.UUID) (uint64, error) {
		lookups.Add(1)
		return 0, errors.New("SYNTHETIC_AUTHORITY_SECRET")
	}
	ownerCalls := atomic.Int32{}
	owner := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { ownerCalls.Add(1) }))
	defer owner.Close()
	peers, addr := startRoutingTestPeer(t, owner.Listener.Addr().String())
	router := NewRoutingHandler(h.domains, "edge", RouteLookupFunc(func(context.Context, string) (SandboxRoute, error) {
		return SandboxRoute{HostID: "owner", ProxyAddr: addr, Generation: 1}, nil
	}), peers, h, h.log)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, loggingRequest("GET", "/files?path=/data", token))
	events := buf.events(t)
	if w.Code != http.StatusServiceUnavailable || lookups.Load() != 1 || ownerCalls.Load() != 0 || len(events) != 1 {
		t.Fatalf("status=%d lookups=%d owner=%d events=%v", w.Code, lookups.Load(), ownerCalls.Load(), events)
	}
	e := events[0]
	if e["event_type"] != "request" || e["auth_outcome"] != "error" || e["actor_type"] != "unknown" || e["actor_id"] != nil || e["credential_id"] != nil || e["team_id"] != nil || strings.Contains(buf.text(), "SYNTHETIC") {
		t.Fatal(e)
	}
}
