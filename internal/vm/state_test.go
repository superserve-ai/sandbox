package vm

import (
	"path/filepath"
	"testing"
)

// TestPutIfPresent pins the atomic conditional write the background reattach
// relies on: it must write when the record exists and be a no-op (never
// resurrect) once the record has been deleted.
func TestPutIfPresent(t *testing.T) {
	s, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	rec := VMRecord{ID: "vm-1", Status: StatusRunning}

	// Absent key → no write.
	if wrote, err := s.PutIfPresent(rec); err != nil || wrote {
		t.Fatalf("PutIfPresent on absent key = (%v, %v), want (false, nil)", wrote, err)
	}
	if has, _ := s.Has("vm-1"); has {
		t.Fatal("record must not exist after PutIfPresent on an absent key")
	}

	// Present key → writes (and updates).
	if err := s.Put(rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	rec.Status = StatusPaused
	if wrote, err := s.PutIfPresent(rec); err != nil || !wrote {
		t.Fatalf("PutIfPresent on present key = (%v, %v), want (true, nil)", wrote, err)
	}
	if got, _ := s.Get("vm-1"); got == nil || got.Status != StatusPaused {
		t.Fatalf("record not updated: %+v", got)
	}

	// Deleted key → must NOT resurrect (the whole point of the fix).
	if err := s.Delete("vm-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if wrote, err := s.PutIfPresent(rec); err != nil || wrote {
		t.Fatalf("PutIfPresent after delete = (%v, %v), want (false, nil)", wrote, err)
	}
	if has, _ := s.Has("vm-1"); has {
		t.Fatal("record resurrected after delete — PutIfPresent must be a no-op")
	}
}
