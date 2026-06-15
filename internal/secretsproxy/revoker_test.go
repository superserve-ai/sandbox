package secretsproxy

import (
	"sync"
	"testing"
)

func TestRevoker_EmptyReportsNotRevoked(t *testing.T) {
	r := NewRevoker()
	if r.IsSandboxRevoked("sb-1") {
		t.Fatal("empty revoker must not report sandbox revoked")
	}
}

func TestRevoker_RevokeThenCheck(t *testing.T) {
	r := NewRevoker()
	r.RevokeSandbox("sb-1")
	if !r.IsSandboxRevoked("sb-1") {
		t.Fatal("revoked sandbox must report revoked")
	}
	if r.IsSandboxRevoked("sb-2") {
		t.Fatal("non-revoked sandbox must report not revoked")
	}
}

func TestRevoker_RevokeIsIdempotent(t *testing.T) {
	r := NewRevoker()
	r.RevokeSandbox("sb-1")
	r.RevokeSandbox("sb-1")
	if !r.IsSandboxRevoked("sb-1") {
		t.Fatal("double-revoke must not flip state")
	}
}

func TestRevoker_BootstrapReplacesSet(t *testing.T) {
	r := NewRevoker()
	r.RevokeSandbox("stale")
	r.Bootstrap([]string{"sb-1", "sb-2"})

	if r.IsSandboxRevoked("stale") {
		t.Fatal("Bootstrap must replace, not merge — stale entry should be gone")
	}
	if !r.IsSandboxRevoked("sb-1") || !r.IsSandboxRevoked("sb-2") {
		t.Fatal("bootstrapped entries must be revoked")
	}
}

func TestRevoker_ConcurrentReadWrite(t *testing.T) {
	// Run under -race to verify the RWMutex is sufficient.
	r := NewRevoker()
	const n = 1000
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(2)
		go func(id int) {
			defer wg.Done()
			r.RevokeSandbox(idString(id))
		}(i)
		go func(id int) {
			defer wg.Done()
			_ = r.IsSandboxRevoked(idString(id))
		}(i)
	}
	wg.Wait()
}

func idString(i int) string {
	const digits = "0123456789"
	if i == 0 {
		return "0"
	}
	var b [20]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = digits[i%10]
		i /= 10
	}
	return string(b[n:])
}

func TestReconcileIsAddOnly(t *testing.T) {
	r := NewRevoker()
	r.RevokeSandbox("pushed-1") // arrived via push

	// A reconcile that doesn't include pushed-1 must NOT drop it (no race
	// un-revoke), and must add the entries it does carry.
	r.Reconcile([]string{"fetched-1", "fetched-2"})

	for _, id := range []string{"pushed-1", "fetched-1", "fetched-2"} {
		if !r.IsSandboxRevoked(id) {
			t.Errorf("%q should be revoked after reconcile", id)
		}
	}
	if r.IsSandboxRevoked("never") {
		t.Error("unrelated id should not be revoked")
	}
}
