package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/gateway"
	"github.com/superserve-ai/sandbox/internal/handoff"
)

func TestBudgetsFromEnv(t *testing.T) {
	log := zerolog.Nop()
	def := handoff.DefaultBudgets()

	t.Setenv("VMD_HANDOFF_DRAIN_BUDGET", "7s")
	if got := budgetsFromEnv(def, log); got.Drain != 7*time.Second {
		t.Fatalf("valid drain = %v, want 7s", got.Drain)
	}

	// Zero, negative, over-max, and unparseable must all fall back to the default.
	for _, bad := range []string{"0", "-5s", "10m", "nonsense"} {
		t.Setenv("VMD_HANDOFF_DRAIN_BUDGET", bad)
		if got := budgetsFromEnv(def, log); got.Drain != def.Drain {
			t.Fatalf("bad value %q accepted: got %v, want default %v", bad, got.Drain, def.Drain)
		}
	}
}

func TestApplyControl(t *testing.T) {
	cs := &controlState{gw: gateway.New()}

	if got := cs.apply([]string{"set-active", "B", "/tmp/b.sock", "/tmp/b-res.sock"}); got != "OK" {
		t.Fatalf("set-active = %q", got)
	}
	if up, _ := cs.gw.Router().Active(); up.Generation != "B" || up.GRPCSocket != "/tmp/b.sock" || up.ResolverSocket != "/tmp/b-res.sock" {
		t.Fatalf("router not updated: %+v", up)
	}

	if got := cs.apply([]string{"quiesce", "on"}); got != "OK" {
		t.Fatalf("quiesce on = %q", got)
	}
	if _, q := cs.gw.Router().Active(); !q {
		t.Fatal("router not quiescing after quiesce on")
	}

	if got := cs.apply([]string{"status"}); !strings.Contains(got, "quiescing=true") || !strings.Contains(got, `generation="B"`) {
		t.Fatalf("status = %q", got)
	}

	// deploy/current require a controller; without one they error, not panic.
	if got := cs.apply([]string{"deploy", "b"}); !strings.HasPrefix(got, "ERR") {
		t.Fatalf("deploy without controller = %q, want ERR", got)
	}

	for _, bad := range [][]string{{}, {"set-active", "B"}, {"quiesce", "maybe"}, {"nope"}} {
		if got := cs.apply(bad); !strings.HasPrefix(got, "ERR") {
			t.Fatalf("apply(%v) = %q, want ERR", bad, got)
		}
	}
}

func TestPersistLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "active-generation")

	// Full record round-trips.
	persistActive(path, gateway.Upstream{Generation: "b", GRPCSocket: "/g.sock", ResolverSocket: "/r.sock"})
	if up, ok := loadActive(path); !ok || up.Generation != "b" || up.ResolverSocket != "/r.sock" {
		t.Fatalf("round-trip = %+v ok=%v", up, ok)
	}

	// A trailing-empty resolver field must still load (regression: TrimRight+SplitN dropped it).
	persistActive(path, gateway.Upstream{Generation: "b", GRPCSocket: "/g.sock", ResolverSocket: ""})
	if up, ok := loadActive(path); !ok || up.Generation != "b" || up.ResolverSocket != "" {
		t.Fatalf("empty-resolver record dropped: %+v ok=%v", up, ok)
	}

	// Missing file → no record.
	if _, ok := loadActive(filepath.Join(t.TempDir(), "nope")); ok {
		t.Fatal("missing file should not load")
	}
}
