package auth

import (
	"strings"
	"testing"
	"time"
)

var previewSeed = []byte("test-seed-key-that-is-at-least-32-bytes-long!!")

const previewSID = "0b2f8a44-9c1d-4e5f-8a3b-1c2d3e4f5a6b"

func mustMint(t *testing.T, claims PreviewClaims) string {
	t.Helper()
	tok, err := ComputePreviewToken(previewSeed, claims)
	if err != nil {
		t.Fatalf("ComputePreviewToken: %v", err)
	}
	return tok
}

func TestPreviewToken_ValidForItsPort(t *testing.T) {
	tok := mustMint(t, PreviewClaims{SandboxID: previewSID, Port: 3000, Version: 1})
	if !VerifyPreviewToken(previewSeed, previewSID, 3000, 1, tok) {
		t.Error("valid port token rejected on its own port")
	}
}

func TestPreviewToken_NotValidForOtherPort(t *testing.T) {
	// The core deny-by-default guarantee: a token for one port never
	// authenticates another, even at the same version.
	tok := mustMint(t, PreviewClaims{SandboxID: previewSID, Port: 3000, Version: 1})
	if VerifyPreviewToken(previewSeed, previewSID, 3001, 1, tok) {
		t.Error("port-3000 token accepted on port 3001")
	}
}

func TestPreviewToken_WrongSandbox(t *testing.T) {
	tok := mustMint(t, PreviewClaims{SandboxID: previewSID, Port: 3000, Version: 1})
	if VerifyPreviewToken(previewSeed, "e4d0c9b8-0000-4000-8000-000000000000", 3000, 1, tok) {
		t.Error("token for one sandbox accepted for another")
	}
}

func TestPreviewToken_WrongVersion(t *testing.T) {
	// Rotating this port's version invalidates its old tokens.
	tok := mustMint(t, PreviewClaims{SandboxID: previewSID, Port: 3000, Version: 1})
	if VerifyPreviewToken(previewSeed, previewSID, 3000, 2, tok) {
		t.Error("stale-version token accepted after rotation")
	}
}

func TestPreviewToken_PerPortVersionIsIndependent(t *testing.T) {
	// Port 3000 rotated to v2; port 3001 still at v1. Each token is judged
	// against only its own port's version.
	tok3000 := mustMint(t, PreviewClaims{SandboxID: previewSID, Port: 3000, Version: 2})
	tok3001 := mustMint(t, PreviewClaims{SandboxID: previewSID, Port: 3001, Version: 1})
	if !VerifyPreviewToken(previewSeed, previewSID, 3000, 2, tok3000) {
		t.Error("rotated port token rejected at its new version")
	}
	if !VerifyPreviewToken(previewSeed, previewSID, 3001, 1, tok3001) {
		t.Error("un-rotated port token rejected at its own version")
	}
}

func TestPreviewToken_ZeroPublishedVersionFailsClosed(t *testing.T) {
	tok := mustMint(t, PreviewClaims{SandboxID: previewSID, Port: 3000, Version: 1})
	if VerifyPreviewToken(previewSeed, previewSID, 3000, 0, tok) {
		t.Error("token accepted against a zero published version")
	}
}

func TestPreviewToken_ZeroPortRejected(t *testing.T) {
	// port=0 (the old "any port" value) can no longer be minted or verified.
	if _, err := ComputePreviewToken(previewSeed, PreviewClaims{SandboxID: previewSID, Port: 0, Version: 1}); err == nil {
		t.Error("port-0 token minted; sandbox-wide tokens must be impossible")
	}
	tok := mustMint(t, PreviewClaims{SandboxID: previewSID, Port: 3000, Version: 1})
	if VerifyPreviewToken(previewSeed, previewSID, 0, 1, tok) {
		t.Error("verify accepted port 0")
	}
}

func TestPreviewToken_Expiry(t *testing.T) {
	live := mustMint(t, PreviewClaims{
		SandboxID: previewSID, Port: 3000, Version: 1,
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	if !VerifyPreviewToken(previewSeed, previewSID, 3000, 1, live) {
		t.Error("unexpired token rejected")
	}
	expired := mustMint(t, PreviewClaims{
		SandboxID: previewSID, Port: 3000, Version: 1,
		ExpiresAt: time.Now().Add(-time.Second).Unix(),
	})
	if VerifyPreviewToken(previewSeed, previewSID, 3000, 1, expired) {
		t.Error("expired token accepted")
	}
}

func TestPreviewToken_WrongSeed(t *testing.T) {
	tok := mustMint(t, PreviewClaims{SandboxID: previewSID, Port: 3000, Version: 1})
	other := []byte("another-seed-key-that-is-32-bytes-or-more!!")
	if VerifyPreviewToken(other, previewSID, 3000, 1, tok) {
		t.Error("token verified under a different seed")
	}
}

func TestPreviewToken_TamperedPayload(t *testing.T) {
	tok := mustMint(t, PreviewClaims{SandboxID: previewSID, Port: 3000, Version: 1})
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected token shape: %q", tok)
	}
	// Re-mint claims for a different port but keep the original signature.
	other := mustMint(t, PreviewClaims{SandboxID: previewSID, Port: 4000, Version: 1})
	otherParts := strings.Split(other, ".")
	spliced := parts[0] + "." + otherParts[1] + "." + parts[2]
	if VerifyPreviewToken(previewSeed, previewSID, 4000, 1, spliced) {
		t.Error("payload-spliced token accepted")
	}
}

func TestPreviewToken_GarbageInputs(t *testing.T) {
	cases := []string{
		"",
		"spv1",
		"spv1..",
		"spv1.a.b.c",
		"not-a-token",
		"spv1.!!!!.!!!!",
		"spv1." + strings.Repeat("A", 4096) + ".sig",
		"spv2.eyJzaWQiOiJ4In0.AAAA",
	}
	for _, c := range cases {
		if VerifyPreviewToken(previewSeed, previewSID, 3000, 1, c) {
			t.Errorf("garbage token accepted: %q", c)
		}
	}
}

func TestPreviewToken_BoxdTokenNotAccepted(t *testing.T) {
	boxd := ComputeAccessToken(previewSeed, previewSID)
	if VerifyPreviewToken(previewSeed, previewSID, 3000, 1, boxd) {
		t.Error("boxd access token accepted as a preview token")
	}
}

func TestPreviewToken_NotAcceptedAsBoxdToken(t *testing.T) {
	tok := mustMint(t, PreviewClaims{SandboxID: previewSID, Port: 3000, Version: 1})
	if VerifyAccessToken(previewSeed, previewSID, tok) {
		t.Error("preview token accepted as a boxd access token")
	}
}

func TestPreviewToken_MintValidation(t *testing.T) {
	bad := []PreviewClaims{
		{SandboxID: "", Port: 3000, Version: 1},
		{SandboxID: previewSID, Port: 0, Version: 1},
		{SandboxID: previewSID, Port: 70000, Version: 1},
		{SandboxID: previewSID, Port: 3000, Version: 0},
		{SandboxID: previewSID, Port: 3000, Version: 1, ExpiresAt: -5},
	}
	for i, c := range bad {
		if _, err := ComputePreviewToken(previewSeed, c); err == nil {
			t.Errorf("case %d: invalid claims accepted at mint: %+v", i, c)
		}
	}
}

func TestPreviewToken_Deterministic(t *testing.T) {
	claims := PreviewClaims{SandboxID: previewSID, Port: 8080, Version: 3}
	a := mustMint(t, claims)
	b := mustMint(t, claims)
	if a != b {
		t.Errorf("same claims produced different tokens: %q vs %q", a, b)
	}
}
