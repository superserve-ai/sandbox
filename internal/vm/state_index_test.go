package vm

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// indexSnapshot reads both startup indexes directly for assertions.
func indexSnapshot(t *testing.T, s *StateStore) (cgroup map[string]bool, slots map[string]string) {
	t.Helper()
	cgroup, slots = map[string]bool{}, map[string]string{}
	if err := s.db.View(func(tx *bolt.Tx) error {
		if err := tx.Bucket(idxCgroupBucketName).ForEach(func(k, _ []byte) error {
			cgroup[string(k)] = true
			return nil
		}); err != nil {
			return err
		}
		return tx.Bucket(idxSlotNSBucketName).ForEach(func(k, v []byte) error {
			slots[string(k)] = string(v)
			return nil
		})
	}); err != nil {
		t.Fatalf("snapshot indexes: %v", err)
	}
	return cgroup, slots
}

func TestIndexMaintenanceFollowsRecordLifecycle(t *testing.T) {
	s, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	// Create: cgroup-supervised with a namespace → both indexed.
	if err := s.Put(VMRecord{ID: "vm-a", Status: StatusRunning, Supervision: SupervisionCgroup, Namespace: "ns-a"}); err != nil {
		t.Fatalf("put: %v", err)
	}
	cg, ns := indexSnapshot(t, s)
	if !cg["vm-a"] || ns["vm-a"] != "ns-a" {
		t.Fatalf("after create: cgroup=%v slots=%v", cg, ns)
	}

	// Unchanged rewrite (bulk reattach shape): still consistent.
	if err := s.Put(VMRecord{ID: "vm-a", Status: StatusRunning, Supervision: SupervisionCgroup, Namespace: "ns-a"}); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	cg, ns = indexSnapshot(t, s)
	if !cg["vm-a"] || ns["vm-a"] != "ns-a" {
		t.Fatalf("after unchanged rewrite: cgroup=%v slots=%v", cg, ns)
	}

	// Namespace change → slot index follows.
	if err := s.Put(VMRecord{ID: "vm-a", Status: StatusRunning, Supervision: SupervisionCgroup, Namespace: "ns-b"}); err != nil {
		t.Fatalf("ns change: %v", err)
	}
	if _, ns = indexSnapshot(t, s); ns["vm-a"] != "ns-b" {
		t.Fatalf("slot index did not follow namespace change: %v", ns)
	}

	// Slot release (pause path shape): namespace cleared → slot entry gone.
	if _, err := s.PutIfPresent(VMRecord{ID: "vm-a", Status: StatusPaused, Supervision: SupervisionCgroup}); err != nil {
		t.Fatalf("slot release: %v", err)
	}
	cg, ns = indexSnapshot(t, s)
	if _, held := ns["vm-a"]; held || !cg["vm-a"] {
		t.Fatalf("after slot release: cgroup=%v slots=%v", cg, ns)
	}

	// Supervision demotion (reconciler shape) → cgroup entry gone.
	if _, err := s.PutIfPresent(VMRecord{ID: "vm-a", Status: StatusPaused, Supervision: SupervisionUnit}); err != nil {
		t.Fatalf("demote: %v", err)
	}
	if cg, _ = indexSnapshot(t, s); cg["vm-a"] {
		t.Fatalf("cgroup index survived demotion: %v", cg)
	}

	// Delete → no residue.
	if err := s.Put(VMRecord{ID: "vm-b", Status: StatusRunning, Supervision: SupervisionCgroup, Namespace: "ns-x"}); err != nil {
		t.Fatalf("put b: %v", err)
	}
	if err := s.Delete("vm-b"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	cg, ns = indexSnapshot(t, s)
	if cg["vm-b"] || ns["vm-b"] != "" {
		t.Fatalf("delete left residue: cgroup=%v slots=%v", cg, ns)
	}

	// PutIfPresent on an absent record: no write, no residue.
	if wrote, err := s.PutIfPresent(VMRecord{ID: "vm-ghost", Supervision: SupervisionCgroup, Namespace: "ns-g"}); err != nil || wrote {
		t.Fatalf("ghost put wrote=%v err=%v", wrote, err)
	}
	cg, ns = indexSnapshot(t, s)
	if cg["vm-ghost"] || ns["vm-ghost"] != "" {
		t.Fatalf("absent PutIfPresent left residue: cgroup=%v slots=%v", cg, ns)
	}
}

func TestIndexAccessorsMatchScanSemantics(t *testing.T) {
	s, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	recs := []VMRecord{
		{ID: "a", Status: StatusRunning, Supervision: SupervisionCgroup, Namespace: "ns-1"},
		{ID: "b", Status: StatusPaused, Supervision: SupervisionUnit, Namespace: "ns-2"},
		{ID: "c", Status: StatusPaused, Supervision: Supervision("future-mode"), Namespace: ""},
		{ID: "d", Status: StatusPaused},
	}
	for _, r := range recs {
		if err := s.Put(r); err != nil {
			t.Fatalf("put %s: %v", r.ID, err)
		}
	}

	// Equivalence with the scan the index replaced.
	all, err := s.All()
	if err != nil {
		t.Fatalf("all: %v", err)
	}
	wantSlots := collectStartupSlots(all)
	gotSlots, err := s.SlotNamespaces()
	if err != nil {
		t.Fatalf("slot namespaces: %v", err)
	}
	if fmt.Sprint(wantSlots) != fmt.Sprint(gotSlots) {
		t.Fatalf("slot index %v != scan %v", gotSlots, wantSlots)
	}

	wantCgroup := false
	for _, r := range all {
		wantCgroup = wantCgroup || cgroupSupervised(r.Supervision)
	}
	gotCgroup, err := s.HasCgroupRecords()
	if err != nil {
		t.Fatalf("has cgroup: %v", err)
	}
	if gotCgroup != wantCgroup {
		t.Fatalf("cgroup index %v != scan %v", gotCgroup, wantCgroup)
	}

	// Unknown supervision values (a newer binary's mode) are not
	// cgroup-supervised — for the index and the scan alike, by the shared
	// predicate. Isolated store so no genuine cgroup record interferes.
	s2, err := OpenStateStore(filepath.Join(t.TempDir(), "unknown.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s2.Close()
	if err := s2.Put(VMRecord{ID: "x", Status: StatusPaused, Supervision: Supervision("future-mode")}); err != nil {
		t.Fatalf("put: %v", err)
	}
	if has, err := s2.HasCgroupRecords(); err != nil || has {
		t.Fatalf("unknown supervision misclassified as cgroup (has=%v err=%v)", has, err)
	}
}

func TestTrustStampRoundTripAndConsumption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := OpenStateStore(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s.Put(VMRecord{ID: "vm-a", Status: StatusPaused, Supervision: SupervisionCgroup, Namespace: "ns-a"}); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := s.StampIndexTrust(); err != nil {
		t.Fatalf("stamp: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Clean close → trusted; projection pass skipped; indexes intact.
	s, err = OpenStateStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	oss := s.OpenStats()
	if !oss.IndexTrusted || oss.IndexTrustReason != "trusted" {
		t.Fatalf("want trusted, got %+v", oss)
	}
	if oss.Records != 0 || oss.Policies != 0 {
		t.Fatalf("trusted boot must skip the projection pass, got %+v", oss)
	}
	if has, _ := s.HasCgroupRecords(); !has {
		t.Fatal("trusted indexes lost content")
	}

	// The stamp was consumed at open: closing WITHOUT re-stamping (crash
	// analogue, incl. the forced-gRPC-stop aborted-closer path) → rebuild.
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	s, err = OpenStateStore(path)
	if err != nil {
		t.Fatalf("reopen 2: %v", err)
	}
	defer s.Close()
	oss = s.OpenStats()
	if oss.IndexTrusted || oss.IndexTrustReason != "no-stamp" {
		t.Fatalf("unstamped close must rebuild, got %+v", oss)
	}
	if oss.Records != 1 {
		t.Fatalf("rebuild should have projected 1 record, got %+v", oss)
	}
}

func TestWriterAfterStampInvalidatesTrust(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := OpenStateStore(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s.Put(VMRecord{ID: "vm-a", Status: StatusPaused, Namespace: "ns-a"}); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := s.StampIndexTrust(); err != nil {
		t.Fatalf("stamp: %v", err)
	}
	// A write racing (or following) the stamp: the stamp is no longer the last
	// transaction, so the next open must NOT trust.
	if err := s.Put(VMRecord{ID: "vm-late", Status: StatusPaused, Namespace: "ns-late"}); err != nil {
		t.Fatalf("late put: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	s, err = OpenStateStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s.Close()
	if oss := s.OpenStats(); oss.IndexTrusted || oss.IndexTrustReason != "txid-moved" {
		t.Fatalf("post-stamp write must invalidate trust, got %+v", oss)
	}
}

// oldBinaryMutate simulates an index-unaware binary: raw bolt writes to the
// records bucket that bypass every StateStore method.
func oldBinaryMutate(t *testing.T, path string, fn func(tx *bolt.Tx) error) {
	t.Helper()
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	defer db.Close()
	if err := db.Update(fn); err != nil {
		t.Fatalf("raw mutate: %v", err)
	}
}

func TestOldBinaryWritesForceRebuildThatCorrectsIndexes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := OpenStateStore(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for _, r := range []VMRecord{
		{ID: "keep", Status: StatusPaused, Supervision: SupervisionCgroup, Namespace: "ns-keep"},
		{ID: "victim", Status: StatusPaused, Supervision: SupervisionCgroup, Namespace: "ns-victim"},
	} {
		if err := s.Put(r); err != nil {
			t.Fatalf("put %s: %v", r.ID, err)
		}
	}
	if err := s.StampIndexTrust(); err != nil {
		t.Fatalf("stamp: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Old binary: deletes one record (stale-EXTRA index entries left behind),
	// creates one (MISSING from the indexes), and changes a namespace in the
	// primary JSON (index value now WRONG).
	oldBinaryMutate(t, path, func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if err := b.Delete([]byte("victim")); err != nil {
			return err
		}
		fresh, err := json.Marshal(VMRecord{ID: "newcomer", Status: StatusPaused, Namespace: "ns-new"})
		if err != nil {
			return err
		}
		if err := b.Put([]byte("newcomer"), fresh); err != nil {
			return err
		}
		moved, err := json.Marshal(VMRecord{ID: "keep", Status: StatusPaused, Supervision: SupervisionCgroup, Namespace: "ns-moved"})
		if err != nil {
			return err
		}
		return b.Put([]byte("keep"), moved)
	})

	s, err = OpenStateStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s.Close()
	if oss := s.OpenStats(); oss.IndexTrusted || oss.IndexTrustReason != "txid-moved" {
		t.Fatalf("old-binary write must invalidate trust, got %+v", oss)
	}
	cg, ns := indexSnapshot(t, s)
	if cg["victim"] || ns["victim"] != "" {
		t.Fatalf("stale-extra entries survived the rebuild: cgroup=%v slots=%v", cg, ns)
	}
	if ns["newcomer"] != "ns-new" {
		t.Fatalf("missing entry not restored: %v", ns)
	}
	if ns["keep"] != "ns-moved" || !cg["keep"] {
		t.Fatalf("changed entry not corrected: cgroup=%v slots=%v", cg, ns)
	}
}

func TestVersionMismatchForcesRebuild(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := OpenStateStore(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s.Put(VMRecord{ID: "vm-a", Status: StatusPaused, Namespace: "ns-a"}); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// A stamp from a future schema: version checked before txid, and the write
	// is crafted so the stamp IS the last tx — only the version differs.
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		stamp, err := json.Marshal(indexTrustStamp{Version: indexSchemaVersion + 1, TxID: tx.ID()})
		if err != nil {
			return err
		}
		return tx.Bucket(metaBucketName).Put(metaIndexTrustKey, stamp)
	}); err != nil {
		t.Fatalf("craft stamp: %v", err)
	}
	db.Close()

	s, err = OpenStateStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s.Close()
	if oss := s.OpenStats(); oss.IndexTrusted || oss.IndexTrustReason != "version-mismatch" {
		t.Fatalf("future-version stamp must rebuild, got %+v", oss)
	}
}

func TestStampAfterCloseFails(t *testing.T) {
	s, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Stamp failure is survivable by design: no stamp ⇒ next boot rebuilds.
	if err := s.StampIndexTrust(); err == nil {
		t.Fatal("stamp on a closed store must fail")
	}
}
