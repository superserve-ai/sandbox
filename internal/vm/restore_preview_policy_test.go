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

func TestPreviewPolicyForRestoreRetainsOnlyValidTokenizedSnapshot(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open state store: %v", err)
	}
	defer store.Close()

	const vmID = "vm-token-restore"
	if err := store.Put(VMRecord{
		ID: vmID, PreviewAccess: preview.AccessPrivate,
		PreviewPorts:             map[int32]bool{3000: true},
		PreviewPortAccess:        map[int32]string{3000: preview.AccessPrivateTokenV1},
		PreviewPortTokenVersions: map[int32]int64{3000: 4},
		PreviewPolicyRevision:    8, PreviewTokenPolicyRevision: 8,
	}); err != nil {
		t.Fatalf("persist tokenized policy: %v", err)
	}

	mgr := &Manager{state: store, vms: map[string]*VMInstance{}}
	access, ports, revision, err := mgr.previewPolicyForRestore(
		vmID, preview.AccessPrivate, map[int32]PreviewPortPolicy{
			3000: {Access: preview.AccessPrivateTokenV1, TokenVersion: 3},
		}, 7,
	)
	if err != nil {
		t.Fatalf("previewPolicyForRestore: %v", err)
	}
	if access != preview.AccessPrivate || revision != 8 ||
		ports[3000].Access != preview.AccessPrivateTokenV1 || ports[3000].TokenVersion != 4 {
		t.Fatalf("restored policy = (%q, %#v, %d), want persisted generation 4 at revision 8", access, ports, revision)
	}

	access, ports, revision, err = mgr.previewPolicyForRestore(
		"vm-malformed-token-restore", preview.AccessPrivate, map[int32]PreviewPortPolicy{
			3000: {Access: preview.AccessPrivateTokenV1},
		}, 9,
	)
	if err != nil {
		t.Fatalf("malformed previewPolicyForRestore: %v", err)
	}
	if access != preview.AccessPrivate || revision != 9 ||
		ports[3000].Access != preview.AccessPrivateTokenV1 || ports[3000].TokenVersion != 0 {
		t.Fatalf("malformed restore policy = (%q, %#v, %d), want closed sentinel", access, ports, revision)
	}
}

func TestPreviewPolicyForRestoreRetainsOnlyValidBrowserTokenSnapshot(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open state store: %v", err)
	}
	defer store.Close()

	const vmID = "vm-browser-restore"
	if err := store.Put(VMRecord{
		ID: vmID, PreviewAccess: preview.AccessPrivate,
		PreviewPorts:             map[int32]bool{3000: true},
		PreviewPortAccess:        map[int32]string{3000: preview.AccessPrivateBrowserV1},
		PreviewPortTokenVersions: map[int32]int64{3000: 4},
		PreviewPolicyRevision:    8, PreviewTokenPolicyRevision: 8,
	}); err != nil {
		t.Fatalf("persist browser policy: %v", err)
	}

	mgr := &Manager{state: store, vms: map[string]*VMInstance{}}
	access, ports, revision, err := mgr.previewPolicyForRestore(
		vmID, preview.AccessPrivate, map[int32]PreviewPortPolicy{
			3000: {Access: preview.AccessPrivateTokenV1, TokenVersion: 3},
		}, 7,
	)
	if err != nil {
		t.Fatalf("previewPolicyForRestore: %v", err)
	}
	if access != preview.AccessPrivate || revision != 8 ||
		ports[3000].Access != preview.AccessPrivateBrowserV1 || ports[3000].TokenVersion != 4 {
		t.Fatalf("restored browser policy = (%q, %#v, %d), want persisted browser generation 4 at revision 8", access, ports, revision)
	}

	access, ports, revision, err = mgr.previewPolicyForRestore(
		"vm-malformed-browser-restore", preview.AccessPrivate, map[int32]PreviewPortPolicy{
			3000: {Access: preview.AccessPrivateBrowserV1},
		}, 9,
	)
	if err != nil {
		t.Fatalf("malformed browser previewPolicyForRestore: %v", err)
	}
	if access != preview.AccessPrivate || revision != 9 ||
		ports[3000].Access != preview.AccessPrivateBrowserV1 || ports[3000].TokenVersion != 0 {
		t.Fatalf("malformed browser restore policy = (%q, %#v, %d), want closed browser sentinel", access, ports, revision)
	}
}
