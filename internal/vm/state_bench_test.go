package vm

// Startup-index benchmarks (open paths + trust stamp). Write-path benchmarks
// live in state_write_bench_test.go, which is base-compatible for benchstat.

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

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

// Clean-close trust stamp, quiet disk: the one durable write the shutdown path
// gains, at 100k records.
func BenchmarkStampIndexTrust100k(b *testing.B) {
	s, _ := benchStore(b, 100_000)
	defer s.Close()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := s.StampIndexTrust(); err != nil {
			b.Fatalf("stamp: %v", err)
		}
	}
}

// Trust stamp under concurrent fsync pressure: four writers hammering the same
// filesystem — the disk-contended deploy-gap shape.
func BenchmarkStampIndexTrustUnderDiskPressure100k(b *testing.B) {
	s, _ := benchStore(b, 100_000)
	defer s.Close()
	dir := b.TempDir()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	buf := make([]byte, 1<<20)
	for w := 0; w < 4; w++ {
		f, err := os.Create(filepath.Join(dir, "pressure-"+string(rune('a'+w))))
		if err != nil {
			b.Fatalf("pressure file: %v", err)
		}
		wg.Add(1)
		go func(f *os.File) {
			defer wg.Done()
			defer f.Close()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := f.WriteAt(buf, 0); err != nil {
					return
				}
				_ = f.Sync()
			}
		}(f)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := s.StampIndexTrust(); err != nil {
			b.Fatalf("stamp: %v", err)
		}
	}
	b.StopTimer()
	close(stop)
	wg.Wait()
}
