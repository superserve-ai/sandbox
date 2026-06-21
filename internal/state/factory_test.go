package state

import (
	"context"
	"errors"
	"testing"
)

// TestFactoryDefaultsToLocal verifies an empty Backend yields the local
// provider, and that it is usable.
func TestFactoryDefaultsToLocal(t *testing.T) {
	p, err := NewProvider(Config{BaseDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	if _, ok := p.(*LocalProvider); !ok {
		t.Fatalf("default backend = %T, want *LocalProvider", p)
	}
	if _, err := p.Mount(context.Background(), "id", "/state"); err != nil {
		t.Fatalf("default provider Mount: %v", err)
	}
}

// TestFactoryExplicitLocal verifies BackendLocal selection.
func TestFactoryExplicitLocal(t *testing.T) {
	p, err := NewProvider(Config{Backend: BackendLocal, BaseDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	if _, ok := p.(*LocalProvider); !ok {
		t.Fatalf("backend local = %T, want *LocalProvider", p)
	}
}

// TestFactoryUnknownBackend verifies an unknown backend is an error, not a panic.
func TestFactoryUnknownBackend(t *testing.T) {
	if _, err := NewProvider(Config{Backend: "nope"}); err == nil {
		t.Fatalf("expected error for unknown backend")
	}
}

// TestStubsReturnNotConfigured verifies the Archil and Mesa adapters are
// selectable and that every method returns ErrNotConfigured (never panics)
// while creds are absent.
func TestStubsReturnNotConfigured(t *testing.T) {
	ctx := context.Background()

	archil, err := NewProvider(Config{Backend: BackendArchil})
	if err != nil {
		t.Fatalf("NewProvider archil: %v", err)
	}
	if _, ok := archil.(*ArchilProvider); !ok {
		t.Fatalf("archil backend = %T", archil)
	}

	mesa, err := NewProvider(Config{Backend: BackendMesa})
	if err != nil {
		t.Fatalf("NewProvider mesa: %v", err)
	}
	if _, ok := mesa.(*MesaProvider); !ok {
		t.Fatalf("mesa backend = %T", mesa)
	}

	for name, p := range map[string]Provider{"archil": archil, "mesa": mesa} {
		if _, err := p.Mount(ctx, "id", "/state"); !errors.Is(err, ErrNotConfigured) {
			t.Fatalf("%s Mount: got %v, want ErrNotConfigured", name, err)
		}
		if _, err := p.Checkpoint(ctx, "id", "c"); !errors.Is(err, ErrNotConfigured) {
			t.Fatalf("%s Checkpoint: got %v, want ErrNotConfigured", name, err)
		}
		if err := p.Branch(ctx, "id", "c", "b"); !errors.Is(err, ErrNotConfigured) {
			t.Fatalf("%s Branch: got %v, want ErrNotConfigured", name, err)
		}
		if err := p.Rollback(ctx, "id", "c"); !errors.Is(err, ErrNotConfigured) {
			t.Fatalf("%s Rollback: got %v, want ErrNotConfigured", name, err)
		}
		if _, err := p.ListCheckpoints(ctx, "id"); !errors.Is(err, ErrNotConfigured) {
			t.Fatalf("%s ListCheckpoints: got %v, want ErrNotConfigured", name, err)
		}
	}
}
