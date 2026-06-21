package harness

import (
	"path/filepath"
	"testing"
)

// TestReferenceHarnessManifests proves the Harness Contract expresses real
// harnesses: the committed reference adapters under ../../harnesses/ load and
// validate through the same loader the runtime uses. This is the concrete
// "an Actor can be anything" check — claude-code (platform-supplied durability,
// Level 1) and flue (self-managed durability, Level 2) plug into one socket.
func TestReferenceHarnessManifests(t *testing.T) {
	t.Run("claude-code", func(t *testing.T) {
		m, err := Load(filepath.Join("..", "..", "harnesses", "claude-code", "harness.toml"))
		if err != nil {
			t.Fatalf("claude-code manifest must load+validate: %v", err)
		}
		if m.Transport != TransportStdin {
			t.Errorf("transport = %q, want stdin", m.Transport)
		}
		if m.Level != Level1 {
			t.Errorf("level = %d, want 1", m.Level)
		}
		if m.Idle.Kind != IdleSignal {
			t.Errorf("idle kind = %q, want signal", m.Idle.Kind)
		}
		if len(m.State) == 0 || m.State[0] != "/root/.claude" {
			t.Errorf("state = %v, want it to include /root/.claude", m.State)
		}
		if argv := m.StartArgv(); len(argv) != 1 || argv[0] != "cc-actor-shim" {
			t.Errorf("start argv = %v, want [cc-actor-shim]", argv)
		}
	})

	t.Run("flue", func(t *testing.T) {
		m, err := Load(filepath.Join("..", "..", "harnesses", "flue", "harness.toml"))
		if err != nil {
			t.Fatalf("flue manifest must load+validate: %v", err)
		}
		if m.Transport != TransportHTTP {
			t.Errorf("transport = %q, want http", m.Transport)
		}
		if m.Port != 8080 {
			t.Errorf("port = %d, want 8080", m.Port)
		}
		if m.Level != Level2 {
			t.Errorf("level = %d, want 2 (self-managed durability)", m.Level)
		}
		if m.Idle.Kind != IdleHTTP || m.Idle.Path != "/flue/parked" {
			t.Errorf("idle = %q %q, want http /flue/parked", m.Idle.Kind, m.Idle.Path)
		}
		if argv := m.StartArgv(); len(argv) == 0 || argv[0] != "flue" {
			t.Errorf("start argv = %v, want it to start with flue", argv)
		}
	})
}
