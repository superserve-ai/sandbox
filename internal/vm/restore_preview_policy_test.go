package vm

import (
	"path/filepath"
	"testing"

	"github.com/superserve-ai/sandbox/internal/preview"
)

func TestPreviewPolicyForRestorePreservesPersistedStrictRevisionZero(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open state store: %v", err)
	}
	defer store.Close()

	rec := VMRecord{
		ID:                    "vm-rollback-restore",
		PreviewAccess:         preview.AccessPublic,
		PreviewPorts:          map[int32]bool{3000: true},
		PreviewPolicyRevision: 0,
	}
	if err := store.Put(rec); err != nil {
		t.Fatalf("persist strict policy: %v", err)
	}

	mgr := &Manager{state: store, vms: map[string]*VMInstance{}}
	access, ports, revision, err := mgr.previewPolicyForRestore(rec.ID, "", nil, 0)
	if err != nil {
		t.Fatalf("previewPolicyForRestore: %v", err)
	}
	if access != preview.AccessPublic || revision != 0 {
		t.Fatalf("effective restore policy = (%q, %d), want (public, 0)", access, revision)
	}
	if _, ok := ports[3000]; !ok || len(ports) != 1 {
		t.Fatalf("effective restore ports = %#v, want {3000}", ports)
	}
}

func TestPreviewPolicyForRestoreUsesHighestRevision(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open state store: %v", err)
	}
	defer store.Close()

	const vmID = "vm-restore-ordering"
	if err := store.Put(VMRecord{
		ID: vmID, PreviewAccess: preview.AccessPublic,
		PreviewPorts: map[int32]bool{3000: true}, PreviewPolicyRevision: 4,
	}); err != nil {
		t.Fatalf("persist revision 4: %v", err)
	}
	mgr := &Manager{
		state: store,
		vms: map[string]*VMInstance{vmID: {
			ID: vmID, PreviewAccess: preview.AccessPublic,
			PreviewPorts: map[int32]PreviewPortPolicy{4000: {}}, PreviewPolicyRevision: 6,
		}},
	}

	access, ports, revision, err := mgr.previewPolicyForRestore(
		vmID, preview.AccessPublic, map[int32]PreviewPortPolicy{5000: {}}, 5,
	)
	if err != nil {
		t.Fatalf("memory ordering: %v", err)
	}
	if access != preview.AccessPublic || revision != 6 {
		t.Fatalf("effective policy = (%q, %d), want memory revision 6", access, revision)
	}
	if _, ok := ports[4000]; !ok || len(ports) != 1 {
		t.Fatalf("effective ports = %#v, want {4000}", ports)
	}

	delete(mgr.vms, vmID)
	access, ports, revision, err = mgr.previewPolicyForRestore(
		vmID, preview.AccessPublic, map[int32]PreviewPortPolicy{5000: {}}, 5,
	)
	if err != nil {
		t.Fatalf("wire ordering: %v", err)
	}
	if access != preview.AccessPublic || revision != 5 {
		t.Fatalf("effective policy = (%q, %d), want incoming revision 5", access, revision)
	}
	if _, ok := ports[5000]; !ok || len(ports) != 1 {
		t.Fatalf("effective ports = %#v, want {5000}", ports)
	}
}
