package mining

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/abuse"
)

type fakeStore struct {
	calls       []uuid.UUID
	fail        bool
	disposition abuse.IncidentDisposition
}

func (s *fakeStore) RecordIncident(_ context.Context, i abuse.MiningIncident) (abuse.IncidentReceipt, error) {
	s.calls = append(s.calls, i.ID)
	if s.fail {
		return abuse.IncidentReceipt{}, errors.New("offline")
	}
	return abuse.IncidentReceipt{IncidentID: i.ID, Disposition: s.disposition}, nil
}
func (s *fakeStore) IncidentStatus(_ context.Context, id uuid.UUID) (abuse.IncidentReceipt, error) {
	if s.fail {
		return abuse.IncidentReceipt{}, errors.New("offline")
	}
	return abuse.IncidentReceipt{IncidentID: id, Disposition: s.disposition}, nil
}
func testIncident() abuse.MiningIncident {
	return abuse.MiningIncident{ID: uuid.New(), SandboxID: uuid.New(), TeamID: uuid.New(), HostID: "host-test", HostIP: "192.0.2.3", Assignment: "incarnation-test", ObservedAt: time.Now().UTC(), Evidence: abuse.MiningEvidence{Kind: "domain", Indicator: "pool.invalid"}}
}
func ready(d *Delivery) {
	d.mu.Lock()
	for _, e := range d.pending {
		e.next = time.Time{}
	}
	d.mu.Unlock()
}
func TestDurableDeliveryRetryRestartAndRelease(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store := &fakeStore{fail: true, disposition: abuse.IncidentApplied}
	var applied, released int
	callback := func(_ context.Context, i abuse.MiningIncident, r abuse.IncidentReceipt) error {
		if r.Disposition == abuse.IncidentApplied {
			applied++
		} else {
			released++
		}
		return nil
	}
	d, err := NewDelivery(dir, 2, store, callback)
	if err != nil {
		t.Fatal(err)
	}
	i := testIncident()
	if err := d.Submit(i); err != nil {
		t.Fatal(err)
	}
	d.deliver(ctx)
	if len(store.calls) != 1 || d.Pending() != 1 {
		t.Fatal("failed delivery lost incident")
	}
	// Restore from disk with no audit sink at all.
	d, err = NewDelivery(dir, 2, store, callback)
	if err != nil {
		t.Fatal(err)
	}
	store.fail = false
	d.deliver(ctx)
	if len(store.calls) != 2 || store.calls[0] != store.calls[1] || applied != 1 {
		t.Fatal("retry changed identity or failed to apply")
	}
	d, err = NewDelivery(dir, 2, store, callback)
	if err != nil {
		t.Fatal(err)
	}
	d.deliver(ctx)
	if len(store.calls) != 2 || applied != 2 {
		t.Fatal("applied receipt was not recovered through status")
	}
	store.disposition = abuse.IncidentReleased
	ready(d)
	d.deliver(ctx)
	if d.Pending() != 0 || released != 1 {
		t.Fatal("release cleanup not acknowledged")
	}
	files, _ := os.ReadDir(dir)
	if len(files) != 0 {
		t.Fatal("released spool record remains")
	}
}
func TestDeliveryBoundsAndChangedDuplicate(t *testing.T) {
	d, err := NewDelivery(t.TempDir(), 1, &fakeStore{}, func(context.Context, abuse.MiningIncident, abuse.IncidentReceipt) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	i := testIncident()
	if err := d.Submit(i); err != nil {
		t.Fatal(err)
	}
	if err := d.Submit(i); err != nil {
		t.Fatalf("identical retry: %v", err)
	}
	changed := i
	changed.TeamID = uuid.New()
	if !errors.Is(d.Submit(changed), abuse.ErrInvalidIncident) {
		t.Fatal("accepted changed victim")
	}
	if !errors.Is(d.Submit(testIncident()), ErrSpoolFull) {
		t.Fatal("unbounded spool")
	}
}
func TestDeliveryRetainsUntilCleanupSucceeds(t *testing.T) {
	fail := true
	store := &fakeStore{disposition: abuse.IncidentReleased}
	d, err := NewDelivery(t.TempDir(), 2, store, func(context.Context, abuse.MiningIncident, abuse.IncidentReceipt) error {
		if fail {
			return errors.New("gate removal failed")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Submit(testIncident()); err != nil {
		t.Fatal(err)
	}
	d.deliver(context.Background())
	if d.Pending() != 1 {
		t.Fatal("lost cleanup obligation")
	}
	fail = false
	ready(d)
	d.deliver(context.Background())
	if d.Pending() != 0 {
		t.Fatal("cleanup not retried")
	}
}
func TestDeliveryCorruptRecoveryIsExplicit(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, uuid.NewString()+".json"), []byte("bad"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDelivery(dir, 2, &fakeStore{}, func(context.Context, abuse.MiningIncident, abuse.IncidentReceipt) error { return nil }); err == nil {
		t.Fatal("silently dropped corrupt pending state")
	}
}

func TestDeliveryDiskFailureDoesNotAcknowledgeOrLoseBound(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spool")
	d, err := NewDelivery(dir, 1, &fakeStore{}, func(context.Context, abuse.MiningIncident, abuse.IncidentReceipt) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := d.Submit(testIncident()); err == nil {
		t.Fatal("acknowledged unwritten incident")
	}
	if d.Pending() != 0 {
		t.Fatal("nonexistent spool record counted")
	}
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := d.Submit(testIncident()); err != nil {
		t.Fatalf("did not recover: %v", err)
	}
	if !errors.Is(d.Submit(testIncident()), ErrSpoolFull) {
		t.Fatal("capacity not enforced after recovery")
	}
}

func TestDeliveryOverlappingRestrictionDefersCleanupWithoutFailure(t *testing.T) {
	overlap := true
	d, err := NewDelivery(t.TempDir(), 2, &fakeStore{disposition: abuse.IncidentReleased}, func(context.Context, abuse.MiningIncident, abuse.IncidentReceipt) error {
		if overlap {
			return ErrCleanupPending
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Submit(testIncident()); err != nil {
		t.Fatal(err)
	}
	d.deliver(context.Background())
	if d.Pending() != 1 || d.degraded || d.retries != 0 {
		t.Fatal("ordinary overlap cleanup treated as loss/failure")
	}
	overlap = false
	ready(d)
	d.deliver(context.Background())
	if d.Pending() != 0 {
		t.Fatal("gate cleanup never completed")
	}
}

func TestDeliveryRetiresOnlyLocalSpoolAfterConfirmedAssignmentRetirement(t *testing.T) {
	store := &fakeStore{disposition: abuse.IncidentApplied}
	retired := false
	d, err := NewDelivery(t.TempDir(), 1, store, func(context.Context, abuse.MiningIncident, abuse.IncidentReceipt) error {
		if retired {
			return ErrLocalCleanupComplete
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Submit(testIncident()); err != nil {
		t.Fatal(err)
	}
	d.deliver(context.Background())
	if d.Pending() != 1 {
		t.Fatal("live assignment lost cleanup tracking")
	}
	retired = true
	ready(d)
	d.deliver(context.Background())
	if d.Pending() != 0 || store.disposition != abuse.IncidentApplied || len(store.calls) != 1 {
		t.Fatal("retirement must remove local tracking without changing durable restriction")
	}
	if err := d.Submit(testIncident()); err != nil {
		t.Fatalf("retired entry still consumes host capacity: %v", err)
	}
}
