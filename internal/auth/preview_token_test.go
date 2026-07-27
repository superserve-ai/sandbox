package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

var previewTokenTestSeed = []byte("test-seed-key-that-is-at-least-32-bytes-long!!")

const (
	previewTokenTestSID      = "0b2f8a44-9c1d-4e5f-8a3b-1c2d3e4f5a6b"
	previewTokenTestOtherSID = "e4d0c9b8-0000-4000-8000-000000000000"
)

func mustComputePreviewToken(t *testing.T, claims PreviewClaims) string {
	t.Helper()
	token, err := ComputePreviewToken(previewTokenTestSeed, claims)
	if err != nil {
		t.Fatalf("ComputePreviewToken: %v", err)
	}
	return token
}

func signedPreviewPayload(raw []byte) string {
	payload := previewB64.EncodeToString(raw)
	signingInput := previewTokenPrefix + "." + payload
	return signingInput + "." + previewB64.EncodeToString(previewTokenMAC(previewTokenTestSeed, signingInput))
}

func signedPreviewPayloadText(payload string) string {
	signingInput := previewTokenPrefix + "." + payload
	return signingInput + "." + previewB64.EncodeToString(previewTokenMAC(previewTokenTestSeed, signingInput))
}

func TestPreviewTokenRoundTripAndWireFormat(t *testing.T) {
	claims := PreviewClaims{
		SandboxID: previewTokenTestSID,
		Port:      3000,
		Version:   7,
		ExpiresAt: 1_800_000_000,
	}
	token := mustComputePreviewToken(t, claims)
	if err := verifyPreviewTokenAt(
		previewTokenTestSeed, previewTokenTestSID, 3000, 7, token, time.Unix(1_700_000_000, 0),
	); err != nil {
		t.Fatalf("valid preview token rejected: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts, want 3: %q", len(parts), token)
	}
	if parts[0] != "spv1" {
		t.Fatalf("prefix = %q, want spv1", parts[0])
	}
	if strings.Contains(token, "=") {
		t.Fatalf("token uses padded base64url: %q", token)
	}

	raw, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	wantJSON := `{"sid":"0b2f8a44-9c1d-4e5f-8a3b-1c2d3e4f5a6b","p":3000,"v":7,"exp":1800000000}`
	if string(raw) != wantJSON {
		t.Fatalf("payload = %s, want %s", raw, wantJSON)
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if len(signature) != sha256.Size {
		t.Fatalf("signature length = %d, want %d", len(signature), sha256.Size)
	}
}

func TestPreviewTokenWithoutExpiryOmitsClaim(t *testing.T) {
	token := mustComputePreviewToken(t, PreviewClaims{
		SandboxID: previewTokenTestSID,
		Port:      8080,
		Version:   1,
	})
	parts := strings.Split(token, ".")
	raw, err := previewB64.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if strings.Contains(string(raw), `"exp"`) {
		t.Fatalf("zero expiry was not omitted: %s", raw)
	}
	if err := verifyPreviewTokenAt(
		previewTokenTestSeed, previewTokenTestSID, 8080, 1, token, time.Unix(1<<61, 0),
	); err != nil {
		t.Fatalf("non-expiring token rejected: %v", err)
	}
}

func TestPreviewTokenMintIsDeterministic(t *testing.T) {
	claims := PreviewClaims{
		SandboxID: previewTokenTestSID,
		Port:      3000,
		Version:   9,
		ExpiresAt: time.Unix(1_800_000_000, 987_654_321).Unix(),
	}
	a := mustComputePreviewToken(t, claims)
	b := mustComputePreviewToken(t, claims)
	if a != b {
		t.Fatalf("identical claims produced different tokens:\n%s\n%s", a, b)
	}

	// Expiry is represented as integral Unix seconds, so sub-second source
	// times in the same second normalize to the same signed claim.
	claims.ExpiresAt = time.Unix(1_800_000_000, 1).Unix()
	c := mustComputePreviewToken(t, claims)
	claims.ExpiresAt = time.Unix(1_800_000_000, 999_999_999).Unix()
	d := mustComputePreviewToken(t, claims)
	if c != d {
		t.Fatalf("sub-second expiry precision changed token:\n%s\n%s", c, d)
	}
}

func TestPreviewTokenScopeIsExact(t *testing.T) {
	token := mustComputePreviewToken(t, PreviewClaims{
		SandboxID: previewTokenTestSID,
		Port:      3000,
		Version:   4,
	})
	tests := []struct {
		name      string
		sandboxID string
		port      int
		version   int64
	}{
		{name: "other sandbox", sandboxID: previewTokenTestOtherSID, port: 3000, version: 4},
		{name: "other port", sandboxID: previewTokenTestSID, port: 3001, version: 4},
		{name: "older generation", sandboxID: previewTokenTestSID, port: 3000, version: 3},
		{name: "newer generation", sandboxID: previewTokenTestSID, port: 3000, version: 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if VerifyPreviewToken(previewTokenTestSeed, tt.sandboxID, tt.port, tt.version, token) {
				t.Fatal("token verified outside its exact scope")
			}
		})
	}
}

func TestPreviewTokenExpiryUsesWholeSecondBoundary(t *testing.T) {
	const expiry = int64(1_800_000_000)
	token := mustComputePreviewToken(t, PreviewClaims{
		SandboxID: previewTokenTestSID,
		Port:      3000,
		Version:   1,
		ExpiresAt: expiry,
	})
	tests := []struct {
		name    string
		now     time.Time
		wantErr bool
	}{
		{name: "one nanosecond before expiry second", now: time.Unix(expiry-1, 999_999_999)},
		{name: "at expiry", now: time.Unix(expiry, 0), wantErr: true},
		{name: "after expiry", now: time.Unix(expiry+1, 0), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyPreviewTokenAt(previewTokenTestSeed, previewTokenTestSID, 3000, 1, token, tt.now)
			if (err != nil) != tt.wantErr {
				t.Fatalf("verify error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestComputePreviewTokenRejectsInvalidInputs(t *testing.T) {
	valid := PreviewClaims{SandboxID: previewTokenTestSID, Port: 3000, Version: 1}
	tests := []struct {
		name   string
		seed   []byte
		claims PreviewClaims
	}{
		{name: "nil seed", seed: nil, claims: valid},
		{name: "empty seed", seed: []byte{}, claims: valid},
		{name: "short seed", seed: []byte("short"), claims: valid},
		{name: "empty sandbox ID", seed: previewTokenTestSeed, claims: PreviewClaims{Port: 3000, Version: 1}},
		{name: "malformed sandbox ID", seed: previewTokenTestSeed, claims: PreviewClaims{SandboxID: "not-a-uuid", Port: 3000, Version: 1}},
		{name: "uppercase sandbox ID", seed: previewTokenTestSeed, claims: PreviewClaims{SandboxID: strings.ToUpper(previewTokenTestSID), Port: 3000, Version: 1}},
		{name: "braced sandbox ID", seed: previewTokenTestSeed, claims: PreviewClaims{SandboxID: "{" + previewTokenTestSID + "}", Port: 3000, Version: 1}},
		{name: "URN sandbox ID", seed: previewTokenTestSeed, claims: PreviewClaims{SandboxID: "urn:uuid:" + previewTokenTestSID, Port: 3000, Version: 1}},
		{name: "nil UUID", seed: previewTokenTestSeed, claims: PreviewClaims{SandboxID: "00000000-0000-0000-0000-000000000000", Port: 3000, Version: 1}},
		{name: "zero port", seed: previewTokenTestSeed, claims: PreviewClaims{SandboxID: previewTokenTestSID, Port: 0, Version: 1}},
		{name: "negative port", seed: previewTokenTestSeed, claims: PreviewClaims{SandboxID: previewTokenTestSID, Port: -1, Version: 1}},
		{name: "port above range", seed: previewTokenTestSeed, claims: PreviewClaims{SandboxID: previewTokenTestSID, Port: 65536, Version: 1}},
		{name: "zero version", seed: previewTokenTestSeed, claims: PreviewClaims{SandboxID: previewTokenTestSID, Port: 3000, Version: 0}},
		{name: "negative version", seed: previewTokenTestSeed, claims: PreviewClaims{SandboxID: previewTokenTestSID, Port: 3000, Version: -1}},
		{name: "negative expiry", seed: previewTokenTestSeed, claims: PreviewClaims{SandboxID: previewTokenTestSID, Port: 3000, Version: 1, ExpiresAt: -1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ComputePreviewToken(tt.seed, tt.claims); err == nil {
				t.Fatalf("ComputePreviewToken accepted invalid input: %+v", tt.claims)
			}
		})
	}
}

func TestPreviewTokenAcceptsClaimBoundaries(t *testing.T) {
	for _, port := range []int{1, 65535} {
		t.Run(fmt.Sprintf("port_%d", port), func(t *testing.T) {
			token := mustComputePreviewToken(t, PreviewClaims{
				SandboxID: previewTokenTestSID,
				Port:      port,
				Version:   1,
			})
			if !VerifyPreviewToken(previewTokenTestSeed, previewTokenTestSID, port, 1, token) {
				t.Fatal("boundary claims were rejected")
			}
		})
	}
}

func TestVerifyPreviewTokenRejectsInvalidExpectedInputs(t *testing.T) {
	token := mustComputePreviewToken(t, PreviewClaims{
		SandboxID: previewTokenTestSID,
		Port:      3000,
		Version:   1,
	})
	tests := []struct {
		name      string
		seed      []byte
		sandboxID string
		port      int
		version   int64
	}{
		{name: "nil seed", sandboxID: previewTokenTestSID, port: 3000, version: 1},
		{name: "short seed", seed: []byte("short"), sandboxID: previewTokenTestSID, port: 3000, version: 1},
		{name: "invalid sandbox ID", seed: previewTokenTestSeed, sandboxID: "not-a-uuid", port: 3000, version: 1},
		{name: "noncanonical sandbox ID", seed: previewTokenTestSeed, sandboxID: strings.ToUpper(previewTokenTestSID), port: 3000, version: 1},
		{name: "zero port", seed: previewTokenTestSeed, sandboxID: previewTokenTestSID, port: 0, version: 1},
		{name: "port above range", seed: previewTokenTestSeed, sandboxID: previewTokenTestSID, port: 65536, version: 1},
		{name: "zero version", seed: previewTokenTestSeed, sandboxID: previewTokenTestSID, port: 3000, version: 0},
		{name: "negative version", seed: previewTokenTestSeed, sandboxID: previewTokenTestSID, port: 3000, version: -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if VerifyPreviewToken(tt.seed, tt.sandboxID, tt.port, tt.version, token) {
				t.Fatal("VerifyPreviewToken accepted invalid expected inputs")
			}
		})
	}
}

func TestVerifyPreviewTokenRejectsMalformedWireTokens(t *testing.T) {
	valid := mustComputePreviewToken(t, PreviewClaims{
		SandboxID: previewTokenTestSID,
		Port:      3000,
		Version:   1,
	})
	parts := strings.Split(valid, ".")
	tests := []struct {
		name  string
		token string
	}{
		{name: "empty"},
		{name: "prefix only", token: "spv1"},
		{name: "missing signature", token: "spv1.payload"},
		{name: "empty payload", token: "spv1.." + parts[2]},
		{name: "empty signature", token: "spv1." + parts[1] + "."},
		{name: "extra segment", token: valid + ".extra"},
		{name: "wrong prefix", token: "spv2." + parts[1] + "." + parts[2]},
		{name: "padded signature", token: "spv1." + parts[1] + "." + parts[2] + "="},
		{name: "invalid signature alphabet", token: "spv1." + parts[1] + "." + strings.Repeat("!", len(parts[2]))},
		{name: "short signature", token: "spv1." + parts[1] + "." + previewB64.EncodeToString(make([]byte, sha256.Size-1))},
		{name: "long signature", token: "spv1." + parts[1] + "." + previewB64.EncodeToString(make([]byte, sha256.Size+1))},
		{name: "oversized token", token: valid + strings.Repeat("x", maxPreviewTokenLen)},
		{name: "oversized encoded payload", token: "spv1." + strings.Repeat("A", maxPreviewTokenPayloadB64Len+1) + "." + parts[2]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if VerifyPreviewToken(previewTokenTestSeed, previewTokenTestSID, 3000, 1, tt.token) {
				t.Fatalf("malformed token accepted: %q", tt.token)
			}
		})
	}
}

func TestPreviewTokenAuthenticatesBeforePayloadDecode(t *testing.T) {
	badSignature := previewB64.EncodeToString(make([]byte, sha256.Size))
	malformedPayload := "!not-base64url!"
	token := previewTokenPrefix + "." + malformedPayload + "." + badSignature
	err := verifyPreviewTokenAt(
		previewTokenTestSeed, previewTokenTestSID, 3000, 1, token, time.Unix(0, 0),
	)
	if !errors.Is(err, errPreviewTokenAuthentication) {
		t.Fatalf("unauthenticated malformed payload error = %v, want authentication error", err)
	}

	// Once that same opaque payload has a valid MAC, verification reaches the
	// payload decoder and reports a format failure instead.
	token = signedPreviewPayloadText(malformedPayload)
	err = verifyPreviewTokenAt(
		previewTokenTestSeed, previewTokenTestSID, 3000, 1, token, time.Unix(0, 0),
	)
	if !errors.Is(err, errPreviewTokenFormat) {
		t.Fatalf("authenticated malformed payload error = %v, want format error", err)
	}
}

func TestPreviewTokenRejectsAuthenticatedBase64Newlines(t *testing.T) {
	token := mustComputePreviewToken(t, PreviewClaims{
		SandboxID: previewTokenTestSID,
		Port:      3000,
		Version:   1,
	})
	parts := strings.Split(token, ".")
	for _, newline := range []string{"\n", "\r", "\r\n"} {
		name := strings.NewReplacer("\r", "CR", "\n", "LF").Replace(newline)
		t.Run(name, func(t *testing.T) {
			middle := len(parts[1]) / 2
			payload := parts[1][:middle] + newline + parts[1][middle:]
			malleable := signedPreviewPayloadText(payload)
			err := verifyPreviewTokenAt(
				previewTokenTestSeed, previewTokenTestSID, 3000, 1, malleable, time.Unix(0, 0),
			)
			if !errors.Is(err, errPreviewTokenFormat) {
				t.Fatalf("authenticated payload containing %s error = %v, want format error", name, err)
			}
		})
	}
}

func TestPreviewTokenRejectsTamperingAndWrongSeed(t *testing.T) {
	token := mustComputePreviewToken(t, PreviewClaims{
		SandboxID: previewTokenTestSID,
		Port:      3000,
		Version:   1,
	})
	parts := strings.Split(token, ".")
	tamperedPayload := parts[1]
	if tamperedPayload[0] == 'A' {
		tamperedPayload = "B" + tamperedPayload[1:]
	} else {
		tamperedPayload = "A" + tamperedPayload[1:]
	}
	tamperedSignature := parts[2]
	if tamperedSignature[0] == 'A' {
		tamperedSignature = "B" + tamperedSignature[1:]
	} else {
		tamperedSignature = "A" + tamperedSignature[1:]
	}
	tests := []struct {
		name  string
		seed  []byte
		token string
	}{
		{name: "payload", seed: previewTokenTestSeed, token: parts[0] + "." + tamperedPayload + "." + parts[2]},
		{name: "signature", seed: previewTokenTestSeed, token: parts[0] + "." + parts[1] + "." + tamperedSignature},
		{name: "wrong seed", seed: []byte("another-seed-key-that-is-at-least-32-bytes!!"), token: token},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if VerifyPreviewToken(tt.seed, previewTokenTestSID, 3000, 1, tt.token) {
				t.Fatal("tampered token verified")
			}
		})
	}
}

func TestPreviewTokenRejectsAuthenticatedNonCanonicalClaims(t *testing.T) {
	canonical := `{"sid":"` + previewTokenTestSID + `","p":3000,"v":1}`
	tests := []struct {
		name string
		raw  string
	}{
		{name: "malformed JSON", raw: `{"sid":`},
		{name: "unknown field", raw: strings.TrimSuffix(canonical, "}") + `,"future":true}`},
		{name: "duplicate field", raw: strings.TrimSuffix(canonical, "}") + `,"p":3000}`},
		{name: "reordered fields", raw: `{"p":3000,"sid":"` + previewTokenTestSID + `","v":1}`},
		{name: "leading whitespace", raw: " " + canonical},
		{name: "trailing whitespace", raw: canonical + "\n"},
		{name: "trailing JSON", raw: canonical + `{}`},
		{name: "explicit zero expiry", raw: strings.TrimSuffix(canonical, "}") + `,"exp":0}`},
		{name: "null expiry", raw: strings.TrimSuffix(canonical, "}") + `,"exp":null}`},
		{name: "fractional expiry", raw: strings.TrimSuffix(canonical, "}") + `,"exp":1800000000.5}`},
		{name: "string port", raw: `{"sid":"` + previewTokenTestSID + `","p":"3000","v":1}`},
		{name: "escaped sandbox ID", raw: `{"sid":"0b2f8a44\u002d9c1d-4e5f-8a3b-1c2d3e4f5a6b","p":3000,"v":1}`},
		{name: "missing sandbox ID", raw: `{"p":3000,"v":1}`},
		{name: "missing port", raw: `{"sid":"` + previewTokenTestSID + `","v":1}`},
		{name: "missing version", raw: `{"sid":"` + previewTokenTestSID + `","p":3000}`},
		{name: "negative expiry", raw: strings.TrimSuffix(canonical, "}") + `,"exp":-1}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := signedPreviewPayload([]byte(tt.raw))
			err := verifyPreviewTokenAt(
				previewTokenTestSeed, previewTokenTestSID, 3000, 1, token, time.Unix(1_700_000_000, 0),
			)
			if !errors.Is(err, errPreviewTokenClaims) {
				t.Fatalf("error = %v, want claims error", err)
			}
		})
	}
}

func TestPreviewTokenRejectsOversizedAuthenticatedPayload(t *testing.T) {
	raw := []byte(strings.Repeat("x", maxPreviewTokenPayloadLen+1))
	token := signedPreviewPayload(raw)
	if len(token) > maxPreviewTokenLen {
		t.Fatalf("test token length = %d; payload cap is not being tested independently", len(token))
	}
	if VerifyPreviewToken(previewTokenTestSeed, previewTokenTestSID, 3000, 1, token) {
		t.Fatal("oversized authenticated payload verified")
	}
}

func TestPreviewTokenMACIsDomainSeparatedFromBoxd(t *testing.T) {
	token := mustComputePreviewToken(t, PreviewClaims{
		SandboxID: previewTokenTestSID,
		Port:      3000,
		Version:   1,
	})
	parts := strings.Split(token, ".")
	signingInput := parts[0] + "." + parts[1]

	// A bare HMAC using the boxd seed is not a valid preview signature.
	bare := hmac.New(sha256.New, previewTokenTestSeed)
	_, _ = bare.Write([]byte(signingInput))
	undomained := signingInput + "." + previewB64.EncodeToString(bare.Sum(nil))
	if VerifyPreviewToken(previewTokenTestSeed, previewTokenTestSID, 3000, 1, undomained) {
		t.Fatal("undomained HMAC accepted as preview signature")
	}

	boxdToken := ComputeAccessToken(previewTokenTestSeed, previewTokenTestSID)
	if VerifyPreviewToken(previewTokenTestSeed, previewTokenTestSID, 3000, 1, boxdToken) {
		t.Fatal("boxd access token accepted as preview token")
	}
	if VerifyAccessToken(previewTokenTestSeed, previewTokenTestSID, token) {
		t.Fatal("preview token accepted as boxd access token")
	}
}

func TestPreviewTokenDifferentClaimsProduceDifferentTokens(t *testing.T) {
	base := PreviewClaims{SandboxID: previewTokenTestSID, Port: 3000, Version: 1}
	baseToken := mustComputePreviewToken(t, base)
	variants := []PreviewClaims{
		{SandboxID: previewTokenTestOtherSID, Port: 3000, Version: 1},
		{SandboxID: previewTokenTestSID, Port: 3001, Version: 1},
		{SandboxID: previewTokenTestSID, Port: 3000, Version: 2},
		{SandboxID: previewTokenTestSID, Port: 3000, Version: 1, ExpiresAt: 1_800_000_000},
	}
	for _, variant := range variants {
		if token := mustComputePreviewToken(t, variant); token == baseToken {
			t.Fatalf("different claims produced identical token: %+v", variant)
		}
	}
}

func TestPreviewClaimsJSONRoundTripUsesIntegerExpiry(t *testing.T) {
	token := mustComputePreviewToken(t, PreviewClaims{
		SandboxID: previewTokenTestSID,
		Port:      3000,
		Version:   1,
		ExpiresAt: 1_800_000_000,
	})
	parts := strings.Split(token, ".")
	raw, err := previewB64.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if string(payload["exp"]) != "1800000000" {
		t.Fatalf("exp = %s, want integer seconds", payload["exp"])
	}
}

func FuzzVerifyPreviewTokenNeverPanics(f *testing.F) {
	valid, err := ComputePreviewToken(previewTokenTestSeed, PreviewClaims{
		SandboxID: previewTokenTestSID,
		Port:      3000,
		Version:   1,
	})
	if err != nil {
		f.Fatalf("seed token: %v", err)
	}
	for _, token := range []string{"", "spv1", "spv1..", "spv1.!!!!.!!!!", valid} {
		f.Add(token)
	}
	f.Fuzz(func(t *testing.T, token string) {
		_ = VerifyPreviewToken(previewTokenTestSeed, previewTokenTestSID, 3000, 1, token)
	})
}
