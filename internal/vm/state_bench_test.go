package vm

import (
	"fmt"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// benchPopulate bulk-loads n records through putRecord in one transaction, so
// the indexes are maintained exactly as production writes would.
func benchPopulate(b *testing.B, s *StateStore, n int) {
	b.Helper()
	if err := s.db.Update(func(tx *bolt.Tx) error {
		for i := 0; i < n; i++ {
			rec := VMRecord{ID: fmt.Sprintf("vm-%06d", i), Status: StatusPaused}
			// Shape roughly like prod: ~2% hold slots, ~0.05% cgroup-supervised.
			if i%50 == 0 {
				rec.Namespace = fmt.Sprintf("ns-%06d", i)
			}
			if i%2000 == 0 {
				rec.Supervision = SupervisionCgroup
			}
			if _, err := putRecord(tx, rec, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		b.Fatalf("populate: %v", err)
	}
}

func benchStore(b *testing.B, n int) (*StateStore, string) {
	b.Helper()
	path := filepath.Join(b.TempDir(), "state.db")
	s, err := OpenStateStore(path)
	if err != nil {
		b.Fatalf("open: %v", err)
	}
	benchPopulate(b, s, n)
	return s, path
}

// Trusted open: the fast path a clean deploy restart takes.
func BenchmarkStateStoreOpenTrusted100k(b *testing.B) {
	s, path := benchStore(b, 100_000)
	if err := s.StampIndexTrust(); err != nil {
		b.Fatalf("stamp: %v", err)
	}
	if err := s.Close(); err != nil {
		b.Fatalf("close: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s, err := OpenStateStore(path)
		if err != nil {
			b.Fatalf("open: %v", err)
		}
		if !s.OpenStats().IndexTrusted {
			b.Fatalf("expected trusted open, got %+v", s.OpenStats())
		}
		b.StopTimer()
		if err := s.StampIndexTrust(); err != nil { // re-arm for the next iteration
			b.Fatalf("restamp: %v", err)
		}
		if err := s.Close(); err != nil {
			b.Fatalf("close: %v", err)
		}
		b.StartTimer()
	}
}

// Untrusted open: the projection-rebuild path (first rollout, crash, rollback).
func BenchmarkStateStoreOpenRebuild100k(b *testing.B) {
	s, path := benchStore(b, 100_000)
	if err := s.Close(); err != nil {
		b.Fatalf("close: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s, err := OpenStateStore(path)
		if err != nil {
			b.Fatalf("open: %v", err)
		}
		if s.OpenStats().IndexTrusted {
			b.Fatalf("expected rebuild open")
		}
		b.StopTimer()
		if err := s.Close(); err != nil {
			b.Fatalf("close: %v", err)
		}
		b.StartTimer()
	}
}

// Unchanged rewrite at 100k records: the bulk reattach/reconciler shape — the
// conditional index maintenance must not dirty index pages.
func BenchmarkPutUnchanged100k(b *testing.B) {
	s, _ := benchStore(b, 100_000)
	defer s.Close()
	rec := VMRecord{ID: "vm-000050", Status: StatusPaused, Namespace: "ns-000050"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := s.Put(rec); err != nil {
			b.Fatalf("put: %v", err)
		}
	}
}

// Namespace flip at 100k records: worst case for index maintenance — every
// write updates the slot index.
func BenchmarkPutNamespaceFlip100k(b *testing.B) {
	s, _ := benchStore(b, 100_000)
	defer s.Close()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := VMRecord{ID: "vm-000050", Status: StatusPaused, Namespace: fmt.Sprintf("ns-flip-%d", i&1)}
		if err := s.Put(rec); err != nil {
			b.Fatalf("put: %v", err)
		}
	}
}

// Create+destroy cycle at 100k records: exercises index put and drop.
func BenchmarkPutDeleteCycle100k(b *testing.B) {
	s, _ := benchStore(b, 100_000)
	defer s.Close()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := VMRecord{ID: "vm-cycle", Status: StatusRunning, Supervision: SupervisionCgroup, Namespace: "ns-cycle"}
		if err := s.Put(rec); err != nil {
			b.Fatalf("put: %v", err)
		}
		if err := s.Delete("vm-cycle"); err != nil {
			b.Fatalf("delete: %v", err)
		}
	}
}
