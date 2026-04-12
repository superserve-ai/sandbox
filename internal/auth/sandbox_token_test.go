package auth

import (
	"testing"
	"time"
)

func TestComputeAccessToken_Deterministic(t *testing.T) {
	seed := []byte("test-seed-key-that-is-at-least-32-bytes-long!!")
	tok1 := ComputeAccessToken(seed, "sandbox-123")
	tok2 := ComputeAccessToken(seed, "sandbox-123")
	if tok1 != tok2 {
		t.Errorf("same inputs produced different tokens: %q vs %q", tok1, tok2)
	}
}

func TestComputeAccessToken_DifferentSandboxesDiffer(t *testing.T) {
	seed := []byte("test-seed-key-that-is-at-least-32-bytes-long!!")
	a := ComputeAccessToken(seed, "sandbox-aaa")
	b := ComputeAccessToken(seed, "sandbox-bbb")
	if a == b {
		t.Error("different sandbox IDs produced the same token")
	}
}

func TestComputeAccessToken_DifferentSeedsDiffer(t *testing.T) {
	seedA := []byte("seed-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	seedB := []byte("seed-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	tok1 := ComputeAccessToken(seedA, "sandbox-123")
	tok2 := ComputeAccessToken(seedB, "sandbox-123")
	if tok1 == tok2 {
		t.Error("different seeds produced the same token")
	}
}

func TestVerifyAccessToken_Valid(t *testing.T) {
	seed := []byte("test-seed-key-that-is-at-least-32-bytes-long!!")
	tok := ComputeAccessToken(seed, "sandbox-123")
	if !VerifyAccessToken(seed, "sandbox-123", tok) {
		t.Error("valid token rejected")
	}
}

func TestVerifyAccessToken_WrongToken(t *testing.T) {
	seed := []byte("test-seed-key-that-is-at-least-32-bytes-long!!")
	if VerifyAccessToken(seed, "sandbox-123", "totally-wrong") {
		t.Error("wrong token accepted")
	}
}

func TestVerifyAccessToken_WrongSandbox(t *testing.T) {
	seed := []byte("test-seed-key-that-is-at-least-32-bytes-long!!")
	tok := ComputeAccessToken(seed, "sandbox-aaa")
	if VerifyAccessToken(seed, "sandbox-bbb", tok) {
		t.Error("token for sandbox-aaa accepted for sandbox-bbb")
	}
}

func TestValidateSeed_Empty(t *testing.T) {
	if err := ValidateSeed(nil); err == nil {
		t.Error("nil seed accepted")
	}
	if err := ValidateSeed([]byte{}); err == nil {
		t.Error("empty seed accepted")
	}
}

func TestValidateSeed_TooShort(t *testing.T) {
	if err := ValidateSeed([]byte("short")); err == nil {
		t.Error("short seed accepted")
	}
}

func TestValidateSeed_Valid(t *testing.T) {
	if err := ValidateSeed([]byte("this-is-a-valid-seed-with-32-byt")); err != nil {
		t.Errorf("valid seed rejected: %v", err)
	}
}

func TestVerifyAccessToken_PreviousWindowAccepted(t *testing.T) {
	seed := []byte("test-seed-key-that-is-at-least-32-bytes-long!!")
	// A token from the previous window should still be accepted.
	prevWindow := currentWindow(now()) - 1
	tok := computeTokenForWindow(seed, "sandbox-123", prevWindow)
	if !VerifyAccessToken(seed, "sandbox-123", tok) {
		t.Error("token from previous window rejected")
	}
}

func TestVerifyAccessToken_OldWindowRejected(t *testing.T) {
	seed := []byte("test-seed-key-that-is-at-least-32-bytes-long!!")
	// A token from 2 windows ago should be rejected.
	oldWindow := currentWindow(now()) - 2
	tok := computeTokenForWindow(seed, "sandbox-123", oldWindow)
	if VerifyAccessToken(seed, "sandbox-123", tok) {
		t.Error("token from 2 windows ago accepted")
	}
}

func TestComputeAccessToken_DifferentWindowsDiffer(t *testing.T) {
	seed := []byte("test-seed-key-that-is-at-least-32-bytes-long!!")
	w := currentWindow(now())
	tok1 := computeTokenForWindow(seed, "sandbox-123", w)
	tok2 := computeTokenForWindow(seed, "sandbox-123", w-1)
	if tok1 == tok2 {
		t.Error("different windows produced the same token")
	}
}

func now() time.Time { return time.Now() }
