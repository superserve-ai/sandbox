//go:build integration

package api

import (
	"errors"
	"testing"
)

// Through a transaction pooler a session lock can stay on an idle pooled
// backend after the attempt; the lock must belong to an open transaction.
func TestProUpgradeInvoiceLockIsTransactionScoped(t *testing.T) {
	h, team := newPlanAssignmentFixture(t)
	holders := func() (count int, inTransaction bool) {
		t.Helper()
		if err := h.Pool.QueryRow(t.Context(), `SELECT count(*), coalesce(bool_and(a.xact_start IS NOT NULL), false)
 FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid,
  (SELECT hashtextextended($1, 0) AS key) k
 WHERE l.locktype = 'advisory' AND l.granted
  AND l.classid = ((k.key >> 32) & 4294967295)::bigint::oid
  AND l.objid = (k.key & 4294967295)::bigint::oid`, "invoice:"+team.String()).Scan(&count, &inTransaction); err != nil {
			t.Fatal(err)
		}
		return count, inTransaction
	}

	_, release, err := h.proUpgradeInvoiceLock(t.Context(), team)
	if err != nil {
		t.Fatal(err)
	}
	released := false
	t.Cleanup(func() {
		if !released {
			release()
		}
	})
	if count, inTransaction := holders(); count != 1 || !inTransaction {
		t.Fatalf("lock holders=%d in transaction=%t", count, inTransaction)
	}
	if _, _, err = h.proUpgradeInvoiceLock(t.Context(), team); !errors.Is(err, errProReconciliationBusy) {
		t.Fatalf("second attempt: %v", err)
	}
	release()
	released = true
	if count, _ := holders(); count != 0 {
		t.Fatalf("lock outlived release: %d holders", count)
	}
	_, release, err = h.proUpgradeInvoiceLock(t.Context(), team)
	if err != nil {
		t.Fatalf("lock not reusable after release: %v", err)
	}
	release()
}
