package vm

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/superserve-ai/sandbox/internal/preview"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestPreviewPolicyRecordRoundTrip(t *testing.T) {
	inst := &VMInstance{
		ID:                    "vm-preview",
		PreviewAccess:         preview.AccessPublic,
		PreviewPorts:          map[int32]struct{}{3000: {}, 8080: {}},
		PreviewPolicyRevision: 7,
	}

	rec := toRecord(inst)
	if rec.PreviewAccess != preview.AccessPublic || rec.PreviewPolicyRevision != 7 {
		t.Fatalf("record policy = (%q, %d), want (%q, 7)", rec.PreviewAccess, rec.PreviewPolicyRevision, preview.AccessPublic)
	}
	if !rec.PreviewPorts[3000] || !rec.PreviewPorts[8080] {
		t.Fatalf("record ports = %#v, want 3000 and 8080", rec.PreviewPorts)
	}

	restored := toInstance(rec)
	if restored.PreviewAccess != preview.AccessPublic || restored.PreviewPolicyRevision != 7 {
		t.Fatalf("restored policy = (%q, %d), want (%q, 7)", restored.PreviewAccess, restored.PreviewPolicyRevision, preview.AccessPublic)
	}
	if _, ok := restored.PreviewPorts[3000]; !ok {
		t.Fatalf("restored ports = %#v, want 3000", restored.PreviewPorts)
	}
	if _, ok := restored.PreviewPorts[8080]; !ok {
		t.Fatalf("restored ports = %#v, want 8080", restored.PreviewPorts)
	}

	// Conversion must not alias either mutable map. A later policy update in
	// memory cannot mutate the durable record that was already constructed.
	delete(restored.PreviewPorts, 3000)
	if !rec.PreviewPorts[3000] {
		t.Fatal("restored preview ports alias the persisted record")
	}
}

func TestLegacyVMRecordRetainsAllPortCompatibility(t *testing.T) {
	// Records written before preview publication have none of the new JSON
	// fields. Their zero values intentionally retain the legacy routing mode.
	inst := toInstance(VMRecord{ID: "vm-legacy"})
	if inst.PreviewAccess != "" {
		t.Fatalf("preview access = %q, want legacy zero value", inst.PreviewAccess)
	}
	if inst.PreviewPorts != nil || inst.PreviewPolicyRevision != 0 {
		t.Fatalf("legacy policy = (%#v, %d), want (nil, 0)", inst.PreviewPorts, inst.PreviewPolicyRevision)
	}
}

func TestUpdateSandboxPreviewPolicyRejectsStaleRevision(t *testing.T) {
	inst := &VMInstance{
		ID:                    "vm-preview",
		PreviewAccess:         preview.AccessPublic,
		PreviewPorts:          map[int32]struct{}{3000: {}},
		PreviewPolicyRevision: 2,
	}
	mgr := &Manager{vms: map[string]*VMInstance{inst.ID: inst}}

	if err := mgr.UpdateSandboxPreviewPolicy(inst.ID, preview.AccessPublic, map[int32]struct{}{4000: {}}, 1); err != nil {
		t.Fatalf("stale update: %v", err)
	}
	if _, ok := inst.PreviewPorts[3000]; !ok {
		t.Fatalf("stale revision replaced policy: %#v", inst.PreviewPorts)
	}
	if _, ok := inst.PreviewPorts[4000]; ok {
		t.Fatalf("stale revision opened port 4000: %#v", inst.PreviewPorts)
	}

	incoming := map[int32]struct{}{5000: {}}
	if err := mgr.UpdateSandboxPreviewPolicy(inst.ID, preview.AccessPublic, incoming, 3); err != nil {
		t.Fatalf("new update: %v", err)
	}
	if inst.PreviewPolicyRevision != 3 {
		t.Fatalf("revision = %d, want 3", inst.PreviewPolicyRevision)
	}
	if _, ok := inst.PreviewPorts[5000]; !ok {
		t.Fatalf("new revision not applied: %#v", inst.PreviewPorts)
	}
	delete(incoming, 5000)
	if _, ok := inst.PreviewPorts[5000]; !ok {
		t.Fatal("manager retained caller-owned preview port map")
	}
}

func TestUpdateSandboxPreviewPolicyEqualRevisionIsIdempotent(t *testing.T) {
	tests := []struct {
		name           string
		storedAccess   string
		incomingAccess string
		storedPorts    map[int32]struct{}
		incomingPorts  map[int32]struct{}
	}{
		{
			name:           "create revision zero attestation",
			storedAccess:   preview.AccessPublic,
			incomingAccess: preview.AccessPublic,
		},
		{
			name:           "legacy zero value is normalized",
			storedAccess:   "",
			incomingAccess: preview.AccessLegacyPublic,
		},
		{
			name:           "full port set matches independent map",
			storedAccess:   preview.AccessPublic,
			incomingAccess: preview.AccessPublic,
			storedPorts:    map[int32]struct{}{3000: {}, 8080: {}},
			incomingPorts:  map[int32]struct{}{8080: {}, 3000: {}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inst := &VMInstance{
				ID:                    "vm-preview",
				PreviewAccess:         tt.storedAccess,
				PreviewPorts:          tt.storedPorts,
				PreviewPolicyRevision: 0,
			}
			mgr := &Manager{vms: map[string]*VMInstance{inst.ID: inst}}

			if err := mgr.UpdateSandboxPreviewPolicy(inst.ID, tt.incomingAccess, tt.incomingPorts, 0); err != nil {
				t.Fatalf("idempotent update: %v", err)
			}
			if inst.PreviewAccess != tt.storedAccess || !previewPolicyEqual(inst.PreviewAccess, inst.PreviewPorts, tt.storedAccess, tt.storedPorts) {
				t.Fatalf("idempotent update changed stored policy to (%q, %#v)", inst.PreviewAccess, inst.PreviewPorts)
			}
		})
	}
}

func TestUpdateSandboxPreviewPolicyEqualRevisionMismatchFailsClosed(t *testing.T) {
	tests := []struct {
		name           string
		storedAccess   string
		incomingAccess string
		storedPorts    map[int32]struct{}
		incomingPorts  map[int32]struct{}
	}{
		{
			name:           "create revision zero cannot attest legacy instance",
			storedAccess:   "",
			incomingAccess: preview.AccessPublic,
		},
		{
			name:           "different full port set",
			storedAccess:   preview.AccessPublic,
			incomingAccess: preview.AccessPublic,
			storedPorts:    map[int32]struct{}{3000: {}},
			incomingPorts:  map[int32]struct{}{8080: {}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inst := &VMInstance{
				ID:                    "vm-preview",
				PreviewAccess:         tt.storedAccess,
				PreviewPorts:          tt.storedPorts,
				PreviewPolicyRevision: 0,
			}
			mgr := &Manager{vms: map[string]*VMInstance{inst.ID: inst}}

			err := mgr.UpdateSandboxPreviewPolicy(inst.ID, tt.incomingAccess, tt.incomingPorts, 0)
			if status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("mismatched equal revision error = %v, want FailedPrecondition", err)
			}
			if inst.PreviewAccess != tt.storedAccess || !previewPolicyEqual(inst.PreviewAccess, inst.PreviewPorts, tt.storedAccess, tt.storedPorts) {
				t.Fatalf("rejected update changed stored policy to (%q, %#v)", inst.PreviewAccess, inst.PreviewPorts)
			}
		})
	}
}

func TestUpdateSandboxPreviewPolicyPersistenceFailureLeavesRevisionRetryable(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "closed.db"))
	if err != nil {
		t.Fatalf("open state store: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close state store: %v", err)
	}

	inst := &VMInstance{
		ID:                    "vm-preview",
		PreviewAccess:         preview.AccessPublic,
		PreviewPorts:          map[int32]struct{}{3000: {}},
		PreviewPolicyRevision: 4,
	}
	mgr := &Manager{
		vms:   map[string]*VMInstance{inst.ID: inst},
		state: store,
	}

	err = mgr.UpdateSandboxPreviewPolicy(inst.ID, preview.AccessPublic, map[int32]struct{}{8080: {}}, 5)
	if err == nil {
		t.Fatal("update succeeded with a closed state store")
	}
	if inst.PreviewPolicyRevision != 4 {
		t.Fatalf("revision = %d, want retryable revision 4", inst.PreviewPolicyRevision)
	}
	if _, ok := inst.PreviewPorts[3000]; !ok {
		t.Fatalf("failed persistence changed current ports: %#v", inst.PreviewPorts)
	}
	if _, ok := inst.PreviewPorts[8080]; ok {
		t.Fatalf("failed persistence applied new port: %#v", inst.PreviewPorts)
	}
}

func TestStateStorePutPreservesNewerPersistedPreviewPolicy(t *testing.T) {
	s, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	current := VMRecord{
		ID:                    "vm-preview-put",
		PID:                   10,
		Status:                StatusRunning,
		PreviewAccess:         preview.AccessPublic,
		PreviewPorts:          map[int32]bool{8080: true},
		PreviewPolicyRevision: 9,
	}
	if err := s.Put(current); err != nil {
		t.Fatalf("seed Put: %v", err)
	}

	staleLifecycleSnapshot := VMRecord{
		ID:                    current.ID,
		PID:                   20,
		Status:                StatusPaused,
		SnapshotPath:          "/snapshots/new.vmstate",
		PreviewAccess:         preview.AccessLegacyPublic,
		PreviewPorts:          map[int32]bool{3000: true},
		PreviewPolicyRevision: 8,
	}
	if err := s.Put(staleLifecycleSnapshot); err != nil {
		t.Fatalf("stale Put: %v", err)
	}

	got, err := s.Get(current.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	assertLifecycleAppliedWithPreviewPolicyPreserved(t, got, staleLifecycleSnapshot, current)
}

func TestStateStorePutIfPresentPreservesNewerPersistedPreviewPolicy(t *testing.T) {
	s, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	current := VMRecord{
		ID:                    "vm-preview-put-if-present",
		PID:                   30,
		Status:                StatusRunning,
		PreviewAccess:         preview.AccessPublic,
		PreviewPorts:          map[int32]bool{8080: true},
		PreviewPolicyRevision: 12,
	}
	if err := s.Put(current); err != nil {
		t.Fatalf("seed Put: %v", err)
	}

	staleLifecycleSnapshot := VMRecord{
		ID:                    current.ID,
		PID:                   40,
		Status:                StatusPaused,
		SnapshotPath:          "/snapshots/conditional.vmstate",
		PreviewAccess:         preview.AccessLegacyPublic,
		PreviewPorts:          map[int32]bool{3000: true},
		PreviewPolicyRevision: 11,
	}
	wrote, err := s.PutIfPresent(staleLifecycleSnapshot)
	if err != nil {
		t.Fatalf("PutIfPresent: %v", err)
	}
	if !wrote {
		t.Fatal("PutIfPresent reported absent record")
	}

	got, err := s.Get(current.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	assertLifecycleAppliedWithPreviewPolicyPreserved(t, got, staleLifecycleSnapshot, current)
}

func TestStateStorePutPreservesEqualRevisionSidecarPolicy(t *testing.T) {
	s, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	// Revision zero is valid for the initial strict policy. An old lifecycle
	// snapshot has the same numeric zero but no preview fields at all.
	current := VMRecord{
		ID:                    "vm-preview-equal-revision",
		PID:                   50,
		Status:                StatusRunning,
		PreviewAccess:         preview.AccessPublic,
		PreviewPorts:          map[int32]bool{8080: true},
		PreviewPolicyRevision: 0,
	}
	if err := s.Put(current); err != nil {
		t.Fatalf("seed Put: %v", err)
	}

	oldLifecycleSnapshot := VMRecord{
		ID:           current.ID,
		PID:          60,
		Status:       StatusPaused,
		SnapshotPath: "/snapshots/equal-revision.vmstate",
	}
	if err := s.Put(oldLifecycleSnapshot); err != nil {
		t.Fatalf("old-shape Put: %v", err)
	}

	got, err := s.Get(current.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	assertLifecycleAppliedWithPreviewPolicyPreserved(t, got, oldLifecycleSnapshot, current)
}

func TestOpenStateStoreMigratesEmbeddedPreviewPolicySidecar(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	strict := VMRecord{
		ID:                    "vm-migrate-strict",
		PreviewAccess:         preview.AccessPublic,
		PreviewPorts:          map[int32]bool{3000: true},
		PreviewPolicyRevision: 4,
	}
	legacy := VMRecord{ID: "vm-migrate-legacy", Status: StatusRunning}
	if err := db.Update(func(tx *bolt.Tx) error {
		records, err := tx.CreateBucketIfNotExists(bucketName)
		if err != nil {
			return err
		}
		for _, rec := range []VMRecord{strict, legacy} {
			data, err := json.Marshal(rec)
			if err != nil {
				return err
			}
			if err := records.Put([]byte(rec.ID), data); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		db.Close()
		t.Fatalf("seed legacy database: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}

	s, err := OpenStateStore(path)
	if err != nil {
		t.Fatalf("open migrated store: %v", err)
	}
	defer s.Close()

	policy, ok := readPreviewPolicySidecar(t, s, strict.ID)
	if !ok {
		t.Fatal("strict embedded policy was not migrated to the sidecar")
	}
	if policy.Access != strict.PreviewAccess || policy.Revision != strict.PreviewPolicyRevision || !policy.Ports[3000] {
		t.Fatalf("migrated policy = %+v, want policy from %+v", policy, strict)
	}
	if _, ok := readPreviewPolicySidecar(t, s, legacy.ID); ok {
		t.Fatal("legacy record unexpectedly gained a preview policy sidecar")
	}
	got, err := s.Get(legacy.ID)
	if err != nil {
		t.Fatalf("Get legacy record: %v", err)
	}
	if got == nil || got.PreviewAccess != "" || got.PreviewPorts != nil || got.PreviewPolicyRevision != 0 {
		t.Fatalf("legacy policy = %+v, want legacy zero values", got)
	}
}

func TestStateStoreRecoversPolicyAfterOldWriterOverwritesPrimaryRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := OpenStateStore(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	policy := VMRecord{
		ID:                    "vm-old-writer",
		PID:                   70,
		Status:                StatusRunning,
		PreviewAccess:         preview.AccessPublic,
		PreviewPorts:          map[int32]bool{3000: true, 8080: true},
		PreviewPolicyRevision: 15,
	}
	if err := s.Put(policy); err != nil {
		s.Close()
		t.Fatalf("seed Put: %v", err)
	}

	oldWriterRecord := VMRecord{
		ID:           policy.ID,
		PID:          71,
		Status:       StatusPaused,
		SnapshotPath: "/snapshots/from-old-vmd.vmstate",
	}
	overwritePrimaryVMRecord(t, s, oldWriterRecord)
	if err := s.Close(); err != nil {
		t.Fatalf("close before reopen: %v", err)
	}

	s, err = OpenStateStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s.Close()

	got, err := s.Get(policy.ID)
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	assertLifecycleAppliedWithPreviewPolicyPreserved(t, got, oldWriterRecord, policy)

	records, err := s.All()
	if err != nil {
		t.Fatalf("All after reopen: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("All returned %d records, want 1", len(records))
	}
	assertLifecycleAppliedWithPreviewPolicyPreserved(t, &records[0], oldWriterRecord, policy)
}

func TestOpenStateStoreRemovesOrphanedPreviewPolicySidecar(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := OpenStateStore(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	strict := VMRecord{
		ID:                    "vm-old-delete",
		PreviewAccess:         preview.AccessPublic,
		PreviewPorts:          map[int32]bool{8080: true},
		PreviewPolicyRevision: 6,
	}
	if err := s.Put(strict); err != nil {
		s.Close()
		t.Fatalf("seed Put: %v", err)
	}
	deletePrimaryVMRecord(t, s, strict.ID)
	if _, ok := readPreviewPolicySidecar(t, s, strict.ID); !ok {
		s.Close()
		t.Fatal("old-delete simulation did not leave an orphan sidecar")
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close before reopen: %v", err)
	}

	s, err = OpenStateStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s.Close()
	if _, ok := readPreviewPolicySidecar(t, s, strict.ID); ok {
		t.Fatal("orphan preview policy survived store initialization")
	}
	if got, err := s.Get(strict.ID); err != nil || got != nil {
		t.Fatalf("Get orphaned VM = (%+v, %v), want (nil, nil)", got, err)
	}

	// Reusing the key after cleanup must not inherit the destroyed VM's policy.
	if err := s.Put(VMRecord{ID: strict.ID, Status: StatusCreating}); err != nil {
		t.Fatalf("Put replacement legacy record: %v", err)
	}
	got, err := s.Get(strict.ID)
	if err != nil {
		t.Fatalf("Get replacement: %v", err)
	}
	if got.PreviewAccess != "" || got.PreviewPorts != nil || got.PreviewPolicyRevision != 0 {
		t.Fatalf("replacement inherited orphan policy: %+v", got)
	}
}

func TestPutIfPresentDoesNotResurrectFromOrphanedPreviewPolicy(t *testing.T) {
	s, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	rec := VMRecord{
		ID:                    "vm-orphan-put-if-present",
		Status:                StatusRunning,
		PreviewAccess:         preview.AccessPublic,
		PreviewPorts:          map[int32]bool{3000: true},
		PreviewPolicyRevision: 3,
	}
	if err := s.Put(rec); err != nil {
		t.Fatalf("seed Put: %v", err)
	}
	deletePrimaryVMRecord(t, s, rec.ID)

	rec.Status = StatusPaused
	if wrote, err := s.PutIfPresent(rec); err != nil || wrote {
		t.Fatalf("PutIfPresent with orphan sidecar = (%v, %v), want (false, nil)", wrote, err)
	}
	if has, err := s.Has(rec.ID); err != nil || has {
		t.Fatalf("Has after PutIfPresent = (%v, %v), want (false, nil)", has, err)
	}
	if _, ok := readPreviewPolicySidecar(t, s, rec.ID); ok {
		t.Fatal("PutIfPresent left orphan sidecar behind")
	}
}

func TestStateStoreDeleteRemovesPreviewPolicySidecar(t *testing.T) {
	s, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	rec := VMRecord{
		ID:                    "vm-delete-sidecar",
		PreviewAccess:         preview.AccessPublic,
		PreviewPolicyRevision: 2,
	}
	if err := s.Put(rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, ok := readPreviewPolicySidecar(t, s, rec.ID); !ok {
		t.Fatal("Put did not create preview policy sidecar")
	}
	if err := s.Delete(rec.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := readPreviewPolicySidecar(t, s, rec.ID); ok {
		t.Fatal("Delete left preview policy sidecar behind")
	}
}

func TestStateStorePutPreservesUnknownPreviewPolicyFields(t *testing.T) {
	s, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	rec := VMRecord{
		ID:                    "vm-future-sidecar-fields",
		PreviewAccess:         preview.AccessPublic,
		PreviewPorts:          map[int32]bool{3000: true},
		PreviewPolicyRevision: 7,
	}
	if err := s.Put(rec); err != nil {
		t.Fatalf("seed Put: %v", err)
	}
	futureSidecar := []byte(`{"access":"private","ports":{"3000":true},"revision":7,"port_access":{"3000":"private"},"token_generations":{"3000":4}}`)
	if err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(previewPolicyBucketName).Put([]byte(rec.ID), futureSidecar)
	}); err != nil {
		t.Fatalf("seed future sidecar fields: %v", err)
	}

	// Advance a known Phase 1 field so Put must rewrite, rather than simply
	// retaining, the sidecar value.
	rec.PID = 99
	rec.PreviewPolicyRevision = 8
	if err := s.Put(rec); err != nil {
		t.Fatalf("Put with future sidecar fields: %v", err)
	}

	raw := readRawPreviewPolicySidecar(t, s, rec.ID)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("unmarshal rewritten sidecar: %v", err)
	}
	if string(fields["port_access"]) != `{"3000":"private"}` {
		t.Fatalf("port_access = %s, want preserved future field", fields["port_access"])
	}
	if string(fields["token_generations"]) != `{"3000":4}` {
		t.Fatalf("token_generations = %s, want preserved future field", fields["token_generations"])
	}
	var revision int64
	if err := json.Unmarshal(fields["revision"], &revision); err != nil || revision != 8 {
		t.Fatalf("revision = %d (%v), want advanced revision 8", revision, err)
	}
}

func overwritePrimaryVMRecord(t *testing.T, s *StateStore, rec VMRecord) {
	t.Helper()
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal primary VM record: %v", err)
	}
	if err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketName).Put([]byte(rec.ID), data)
	}); err != nil {
		t.Fatalf("overwrite primary VM record: %v", err)
	}
}

func deletePrimaryVMRecord(t *testing.T, s *StateStore, vmID string) {
	t.Helper()
	if err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketName).Delete([]byte(vmID))
	}); err != nil {
		t.Fatalf("delete primary VM record: %v", err)
	}
}

func readPreviewPolicySidecar(t *testing.T, s *StateStore, vmID string) (persistedPreviewPolicy, bool) {
	t.Helper()
	var policy persistedPreviewPolicy
	found := false
	if err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(previewPolicyBucketName).Get([]byte(vmID))
		if data == nil {
			return nil
		}
		found = true
		return json.Unmarshal(data, &policy)
	}); err != nil {
		t.Fatalf("read preview policy sidecar: %v", err)
	}
	return policy, found
}

func readRawPreviewPolicySidecar(t *testing.T, s *StateStore, vmID string) []byte {
	t.Helper()
	var result []byte
	if err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(previewPolicyBucketName).Get([]byte(vmID))
		result = append(result, data...)
		return nil
	}); err != nil {
		t.Fatalf("read raw preview policy sidecar: %v", err)
	}
	if result == nil {
		t.Fatal("preview policy sidecar missing")
	}
	return result
}

func assertLifecycleAppliedWithPreviewPolicyPreserved(t *testing.T, got *VMRecord, lifecycle, policy VMRecord) {
	t.Helper()
	if got == nil {
		t.Fatal("record missing")
	}
	if got.PID != lifecycle.PID || got.Status != lifecycle.Status || got.SnapshotPath != lifecycle.SnapshotPath {
		t.Fatalf("lifecycle fields = (pid=%d status=%v snapshot=%q), want (%d %v %q)",
			got.PID, got.Status, got.SnapshotPath, lifecycle.PID, lifecycle.Status, lifecycle.SnapshotPath)
	}
	if got.PreviewAccess != policy.PreviewAccess || got.PreviewPolicyRevision != policy.PreviewPolicyRevision {
		t.Fatalf("preview policy = (%q, %d), want (%q, %d)",
			got.PreviewAccess, got.PreviewPolicyRevision, policy.PreviewAccess, policy.PreviewPolicyRevision)
	}
	if len(got.PreviewPorts) != len(policy.PreviewPorts) {
		t.Fatalf("preview ports = %#v, want %#v", got.PreviewPorts, policy.PreviewPorts)
	}
	for port, published := range policy.PreviewPorts {
		if got.PreviewPorts[port] != published {
			t.Fatalf("preview ports = %#v, want %#v", got.PreviewPorts, policy.PreviewPorts)
		}
	}
}

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
