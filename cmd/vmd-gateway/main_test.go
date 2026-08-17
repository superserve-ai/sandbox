package main

import (
	"strings"
	"testing"

	"github.com/superserve-ai/sandbox/internal/gateway"
)

func TestApplyControl(t *testing.T) {
	gw := gateway.New()

	if got := applyControl([]string{"set-active", "B", "/tmp/b.sock"}, gw); got != "OK" {
		t.Fatalf("set-active = %q", got)
	}
	if up, _ := gw.Router().Active(); up.Generation != "B" || up.Socket != "/tmp/b.sock" {
		t.Fatalf("router not updated: %+v", up)
	}

	if got := applyControl([]string{"quiesce", "on"}, gw); got != "OK" {
		t.Fatalf("quiesce on = %q", got)
	}
	if _, q := gw.Router().Active(); !q {
		t.Fatal("router not quiescing after quiesce on")
	}

	if got := applyControl([]string{"status"}, gw); !strings.Contains(got, "quiescing=true") || !strings.Contains(got, `generation="B"`) {
		t.Fatalf("status = %q", got)
	}

	for _, bad := range [][]string{{}, {"set-active", "B"}, {"quiesce", "maybe"}, {"nope"}} {
		if got := applyControl(bad, gw); !strings.HasPrefix(got, "ERR") {
			t.Fatalf("applyControl(%v) = %q, want ERR", bad, got)
		}
	}
}
