package db

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMachineRepairLifecycleReconciliation(t *testing.T) {
	principal, lineage := uuid.New(), uuid.New()
	secret := []byte("secret-digest")
	expires := time.Unix(1_900_000_000, 0)
	a := lifecycleInputDigest("issue", principal, lineage, secret, expires, []string{"sandbox:read"}, "sandbox-api", 3, uuid.Nil, false)
	b := lifecycleInputDigest("issue", principal, lineage, secret, expires, []string{"sandbox:read"}, "sandbox-api", 3, uuid.Nil, false)
	if !bytes.Equal(a, b) {
		t.Fatal("identical lifecycle inputs produced different operation digests")
	}
	c := lifecycleInputDigest("issue", principal, lineage, []byte("other"), expires, []string{"sandbox:read"}, "sandbox-api", 3, uuid.Nil, false)
	if bytes.Equal(a, c) {
		t.Fatal("conflicting lifecycle inputs reused an operation digest")
	}
}
