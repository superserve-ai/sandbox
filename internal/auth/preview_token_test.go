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

func TestPreviewToken_ValidAnyPort(t *testing.T) {
	tok := mustMint(t, PreviewClaims{SandboxID: previewSID, Version: 1})
	if !VerifyPreviewToken(previewSeed, previewSID, 1, 3000, tok) {
		t.Error("valid any-port token rejected")
	}
	if !VerifyPreviewToken(previewSeed, previewSID, 1, 8080, tok) {
		t.Error("any-port token rejected on a second port")
	}
}

func TestPreviewToken_PortScoped(t *testing.T) {
	tok := mustMint(t, PreviewClaims{SandboxID: previewSID, Version: 1, Port: 3000})
	if !VerifyPreviewToken(previewSeed, previewSID, 1, 3000, tok) {
		t.Error("port-scoped token rejected on its own port")
	}
	if VerifyPreviewToken(previewSeed, previewSID, 1, 3001, tok) {
		t.Error("port-scoped token accepted on a different port")
	}
}

func TestPreviewToken_WrongSandbox(t *testing.T) {
	tok := mustMint(t, PreviewClaims{SandboxID: previewSID, Version: 1})
	if VerifyPreviewToken(previewSeed, "e4d0c9b8-0000-4000-8000-000000000000", 1, 3000, tok) {
		t.Error("token for one sandbox accepted for another")
	}
}

func TestPreviewToken_WrongVersion(t *testing.T) {
	tok := mustMint(t, PreviewClaims{SandboxID: previewSID, Version: 1})
	if VerifyPreviewToken(previewSeed, previewSID, 2, 3000, tok) {
		t.Error("stale-version token accepted after rotation")
	}
}

func TestPreviewToken_ZeroRecordVersionFailsClosed(t *testing.T) {
	// A record without a plumbed version (0) must reject every token,
	// including one minted with version 0 — misconfiguration denies access.
	tok := mustMint(t, PreviewClaims{SandboxID: previewSID, Version: 1})
	if VerifyPreviewToken(previewSeed, previewSID, 0, 3000, tok) {
		t.Error("token accepted against a zero record version")
	}
	forged, err := ComputePreviewToken(previewSeed, PreviewClaims{SandboxID: previewSID, Version: 0})
	if err == nil && VerifyPreviewToken(previewSeed, previewSID, 0, 3000, forged) {
		t.Error("version-0 token accepted against a zero record version")
	}
}

func TestPreviewToken_Expiry(t *testing.T) {
	live := mustMint(t, PreviewClaims{
		SandboxID: previewSID, Version: 1,
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	if !VerifyPreviewToken(previewSeed, previewSID, 1, 3000, live) {
		t.Error("unexpired token rejected")
	}
	expired := mustMint(t, PreviewClaims{
		SandboxID: previewSID, Version: 1,
		ExpiresAt: time.Now().Add(-time.Second).Unix(),
	})
	if VerifyPreviewToken(previewSeed, previewSID, 1, 3000, expired) {
		t.Error("expired token accepted")
	}
}

func TestPreviewToken_WrongSeed(t *testing.T) {
	tok := mustMint(t, PreviewClaims{SandboxID: previewSID, Version: 1})
	other := []byte("another-seed-key-that-is-32-bytes-or-more!!")
	if VerifyPreviewToken(other, previewSID, 1, 3000, tok) {
		t.Error("token verified under a different seed")
	}
}

func TestPreviewToken_TamperedPayload(t *testing.T) {
	tok := mustMint(t, PreviewClaims{SandboxID: previewSID, Version: 1, Port: 3000})
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected token shape: %q", tok)
	}
	// Re-mint claims for a different port but keep the original signature.
	other := mustMint(t, PreviewClaims{SandboxID: previewSID, Version: 1, Port: 4000})
	otherParts := strings.Split(other, ".")
	spliced := parts[0] + "." + otherParts[1] + "." + parts[2]
	if VerifyPreviewToken(previewSeed, previewSID, 1, 4000, spliced) {
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
		// Wrong prefix with otherwise plausible structure.
		"spv2.eyJzaWQiOiJ4In0.AAAA",
	}
	for _, c := range cases {
		if VerifyPreviewToken(previewSeed, previewSID, 1, 3000, c) {
			t.Errorf("garbage token accepted: %q", c)
		}
	}
}

func TestPreviewToken_BoxdTokenNotAccepted(t *testing.T) {
	// The boxd control-plane access token must never authorize a preview.
	boxd := ComputeAccessToken(previewSeed, previewSID)
	if VerifyPreviewToken(previewSeed, previewSID, 1, 3000, boxd) {
		t.Error("boxd access token accepted as a preview token")
	}
}

func TestPreviewToken_NotAcceptedAsBoxdToken(t *testing.T) {
	// And the converse: a preview token must not pass boxd verification.
	tok := mustMint(t, PreviewClaims{SandboxID: previewSID, Version: 1})
	if VerifyAccessToken(previewSeed, previewSID, tok) {
		t.Error("preview token accepted as a boxd access token")
	}
}

func TestPreviewToken_MintValidation(t *testing.T) {
	if _, err := ComputePreviewToken(previewSeed, PreviewClaims{SandboxID: "", Version: 1}); err == nil {
		t.Error("empty sandbox ID accepted at mint")
	}
	if _, err := ComputePreviewToken(previewSeed, PreviewClaims{SandboxID: previewSID, Version: 0}); err == nil {
		t.Error("zero version accepted at mint")
	}
	if _, err := ComputePreviewToken(previewSeed, PreviewClaims{SandboxID: previewSID, Version: 1, Port: -1}); err == nil {
		t.Error("negative port accepted at mint")
	}
	if _, err := ComputePreviewToken(previewSeed, PreviewClaims{SandboxID: previewSID, Version: 1, Port: 70000}); err == nil {
		t.Error("out-of-range port accepted at mint")
	}
	if _, err := ComputePreviewToken(previewSeed, PreviewClaims{SandboxID: previewSID, Version: 1, ExpiresAt: -5}); err == nil {
		t.Error("negative expiry accepted at mint")
	}
}

func TestPreviewToken_Deterministic(t *testing.T) {
	claims := PreviewClaims{SandboxID: previewSID, Version: 3, Port: 8080}
	a := mustMint(t, claims)
	b := mustMint(t, claims)
	if a != b {
		t.Errorf("same claims produced different tokens: %q vs %q", a, b)
	}
}
