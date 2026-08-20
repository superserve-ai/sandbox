package vm

// Write-path benchmarks, deliberately free of any startup-index symbols so the
// identical file runs against the pre-index base for benchstat comparison.

import (
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// benchPopulate bulk-loads n records through putRecord in one transaction —
// the same tx body production writes use.
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

// Unchanged rewrite at 100k records: the bulk reattach/reconciler shape.
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

// Namespace flip at 100k records: every write changes slot state.
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

// Create+destroy cycle at 100k records.
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

// Concurrent writers at 100k records: distinct records, namespace churn —
// exercises Bolt Batch coalescing, the production write shape.
func BenchmarkPutParallel100k(b *testing.B) {
	s, _ := benchStore(b, 100_000)
	defer s.Close()
	var ctr atomic.Int64
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		id := fmt.Sprintf("vm-par-%d", ctr.Add(1))
		i := 0
		for pb.Next() {
			rec := VMRecord{ID: id, Status: StatusPaused, Namespace: fmt.Sprintf("ns-%s-%d", id, i&1)}
			i++
			if err := s.Put(rec); err != nil {
				b.Fatalf("put: %v", err)
			}
		}
	})
}
