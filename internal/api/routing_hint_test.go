package api

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/auth"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestLifecycleResponseRoutingHintUsesKnownOwner(t *testing.T) {
	seed := []byte(strings.Repeat("k", 32))
	h := &Handlers{Config: &config.Config{SandboxAccessTokenSeed: seed, EdgeProxyDomain: "sandbox.example.com"}}
	s := db.Sandbox{ID: uuid.New(), HostID: "host-a", RoutingVersion: 1}
	response := h.sandboxToResponseWithToken(s, time.Now())
	hint, ok := auth.VerifyRoutingHint(seed, response.RoutingHint, s.ID.String(), []string{"sandbox.example.com"}, time.Now())
	if !ok || hint.HostID != "host-a" {
		t.Fatal(hint, ok)
	}
	if !auth.VerifyAccessToken(seed, s.ID.String(), response.AccessToken) {
		t.Fatal("access token changed")
	}
	s.HostID = "host-b"
	response = h.sandboxToResponseWithToken(s, time.Now())
	hint, ok = auth.VerifyRoutingHint(seed, response.RoutingHint, s.ID.String(), []string{"sandbox.example.com"}, time.Now())
	if !ok || hint.HostID != "host-b" {
		t.Fatal("did not use refreshed owner", hint)
	}
	if h.sandboxToResponse(s).RoutingHint != "" {
		t.Fatal("list leaked hint")
	}
}

func BenchmarkLifecycleResponseWithRoutingHint(b *testing.B) {
	h := &Handlers{Config: &config.Config{SandboxAccessTokenSeed: []byte(strings.Repeat("k", 32)), EdgeProxyDomain: "sandbox.example.com"}}
	s := db.Sandbox{ID: uuid.New(), HostID: "host-a", RoutingVersion: 1}
	b.ReportAllocs()
	for b.Loop() {
		h.sandboxToResponseWithToken(s, time.Now())
	}
}

func routingHintTestConfig() *config.Config {
	return &config.Config{SandboxAccessTokenSeed: []byte(strings.Repeat("k", 32)), EdgeProxyDomain: "sandbox.example.com"}
}
func assertResponseRoutingHint(t *testing.T, body map[string]interface{}, cfg *config.Config, id, host string) {
	t.Helper()
	token, _ := body["routing_hint"].(string)
	hint, ok := auth.VerifyRoutingHint(cfg.SandboxAccessTokenSeed, token, id, []string{cfg.EdgeProxyDomain}, time.Now())
	if !ok || hint.HostID != host {
		t.Fatalf("invalid lifecycle hint: %+v, valid=%v", hint, ok)
	}
}

func TestDelayedRoutingResponseKeepsDatabaseExpiration(t *testing.T) {
	h := &Handlers{Config: routingHintTestConfig()}
	sb := db.Sandbox{ID: uuid.New(), HostID: "owner", RoutingVersion: 7}
	observed := time.Now().Add(-30 * time.Minute)
	response := h.sandboxToResponseWithToken(sb, observed)
	hint, ok := auth.VerifyRoutingHint(h.Config.SandboxAccessTokenSeed, response.RoutingHint, sb.ID.String(), []string{h.Config.EdgeProxyDomain}, time.Now())
	if !ok || hint.Expires != observed.Add(auth.RoutingHintTTL).Unix() || hint.Version != 7 {
		t.Fatalf("delayed response renewed hint: %+v %v", hint, ok)
	}
	expired := h.sandboxToResponseWithToken(sb, observed.Add(-time.Hour))
	if _, ok := auth.VerifyRoutingHint(h.Config.SandboxAccessTokenSeed, expired.RoutingHint, sb.ID.String(), []string{h.Config.EdgeProxyDomain}, time.Now()); ok {
		t.Fatal("expired observation renewed hint")
	}
}
