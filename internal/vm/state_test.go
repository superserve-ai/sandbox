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

// The persisted record splits the per-port policy into two parallel maps so
// records written before per-port modes still decode; the round trip must be
// lossless and a version-only record must merge to fallback (empty) access.
func TestVMRecordPreviewPortsRoundTrip(t *testing.T) {
	inst := &VMInstance{
		ID:            "vm-rt",
		PreviewAccess: "public",
		PreviewPorts: map[int32]PreviewPortPolicy{
			3000: {Version: 2, Access: "private"},
			3001: {Version: 1}, // no explicit mode → sandbox fallback
		},
		PreviewPolicyRevision: 7,
	}
	back := toInstance(toRecord(inst))
	if back.PreviewPorts[3000] != (PreviewPortPolicy{Version: 2, Access: "private"}) {
		t.Errorf("3000 round-tripped to %+v", back.PreviewPorts[3000])
	}
	if back.PreviewPorts[3001] != (PreviewPortPolicy{Version: 1}) {
		t.Errorf("3001 round-tripped to %+v", back.PreviewPorts[3001])
	}
	if back.PreviewPolicyRevision != 7 || back.PreviewAccess != "public" {
		t.Errorf("policy fields lost: %+v", back)
	}

	// A record that predates per-port modes: versions only, no access map.
	old := VMRecord{ID: "vm-old", PreviewAccess: "private", PreviewPorts: map[int32]int64{8080: 3}}
	if got := toInstance(old).PreviewPorts[8080]; got != (PreviewPortPolicy{Version: 3}) {
		t.Errorf("legacy record merged to %+v, want version-only", got)
	}
}
