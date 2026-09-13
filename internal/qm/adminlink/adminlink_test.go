package adminlink

import (
	"strings"
	"testing"
	"time"
)

const (
	testSecret = "0123456789abcdef0123456789abcdef-fixed-test-secret"
	testOrigin = "https://pilot-team.qm.example.com"
	testJTI    = "AAAAAAAAAAAAAAAAAAAAAAAA"
)

var testNow = time.Unix(1789000000, 0)

// Expected values were produced by running the upstream CLI's adminLoginUrl
// (with the same secret, origin, timestamp and jti) under Node.
func TestMintMatchesUpstreamCLI(t *testing.T) {
	cases := []struct {
		email, want string
	}{
		{
			email: "Admin@Example.com ",
			want:  testOrigin + "/auth/admin-login#token=eyJrIjoiYWRtaW4tbG9naW4iLCJzdWIiOiJhZG1pbkBleGFtcGxlLmNvbSIsImF1ZCI6Imh0dHBzOi8vcGlsb3QtdGVhbS5xbS5leGFtcGxlLmNvbSIsImlhdCI6MTc4OTAwMDAwMCwiZXhwIjoxNzg5MDAwMzAwLCJqdGkiOiJBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUEifQ.vX2YGPabtW3HWSPva0lVkv22qZPMp-DXSl6FrjJD7SY",
		},
		{
			// `&` is legal in an address and must not be HTML-escaped the
			// way encoding/json does by default.
			email: "a&b@example.com",
			want:  testOrigin + "/auth/admin-login#token=eyJrIjoiYWRtaW4tbG9naW4iLCJzdWIiOiJhJmJAZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwczovL3BpbG90LXRlYW0ucW0uZXhhbXBsZS5jb20iLCJpYXQiOjE3ODkwMDAwMDAsImV4cCI6MTc4OTAwMDMwMCwianRpIjoiQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBIn0.rV20E0RnRz3RbZ6QRiOrymyKUa2v-kGutm-CXfEqzqc",
		},
	}
	for _, tc := range cases {
		link, err := Mint(testOrigin+"/", testSecret, tc.email, testNow, testJTI)
		if err != nil {
			t.Fatalf("mint %q: %v", tc.email, err)
		}
		if link.URL != tc.want {
			t.Errorf("mint %q:\n got %s\nwant %s", tc.email, link.URL, tc.want)
		}
		if !link.ExpiresAt.Equal(testNow.Add(TTL)) {
			t.Errorf("expiresAt = %v, want %v", link.ExpiresAt, testNow.Add(TTL))
		}
	}
}

func TestVerifyAcceptsMintedLink(t *testing.T) {
	link, err := Mint(testOrigin, testSecret, "admin@example.com", testNow, testJTI)
	if err != nil {
		t.Fatal(err)
	}
	token, err := TokenFromURL(link.URL)
	if err != nil {
		t.Fatal(err)
	}
	claims := Verify(token, testSecret, testOrigin, testNow.Add(time.Minute))
	if claims == nil {
		t.Fatal("portal verifier rejected a freshly minted link")
	}
	if claims.Sub != "admin@example.com" || claims.Jti != testJTI {
		t.Fatalf("claims = %+v", claims)
	}

	rejects := map[string]func() *Claims{
		"expired":        func() *Claims { return Verify(token, testSecret, testOrigin, testNow.Add(TTL)) },
		"future":         func() *Claims { return Verify(token, testSecret, testOrigin, testNow.Add(-time.Minute)) },
		"wrong secret":   func() *Claims { return Verify(token, strings.Repeat("x", 40), testOrigin, testNow) },
		"wrong audience": func() *Claims { return Verify(token, testSecret, "https://other.qm.example.com", testNow) },
		"tampered body": func() *Claims {
			return Verify("f"+token[1:], testSecret, testOrigin, testNow)
		},
		"tampered signature": func() *Claims {
			return Verify(token[:len(token)-1]+"A", testSecret, testOrigin, testNow)
		},
	}
	for name, fn := range rejects {
		if fn() != nil {
			t.Errorf("%s: verifier accepted the link", name)
		}
	}
}

func TestNewJTIShape(t *testing.T) {
	for range 16 {
		jti, err := NewJTI()
		if err != nil {
			t.Fatal(err)
		}
		if !jtiRe.MatchString(jti) {
			t.Fatalf("jti %q does not match the portal's shape", jti)
		}
	}
}

func TestMintInputRules(t *testing.T) {
	cases := []struct {
		name, publicURL, secret, email string
		wantErr                        error
	}{
		{"http public", "http://pilot-team.qm.example.com", testSecret, "admin@example.com", ErrPublicURL},
		{"path", testOrigin + "/portal", testSecret, "admin@example.com", ErrPublicURL},
		{"query", testOrigin + "/?x=1", testSecret, "admin@example.com", ErrPublicURL},
		{"userinfo", "https://u:p@pilot-team.qm.example.com", testSecret, "admin@example.com", ErrPublicURL},
		{"trailing dot", "https://pilot-team.qm.example.com.", testSecret, "admin@example.com", ErrPublicURL},
		{"short secret", testOrigin, "short", "admin@example.com", ErrSecret},
		{"bad email", testOrigin, testSecret, "not-an-email", ErrEmail},
		{"long email", testOrigin, testSecret, strings.Repeat("a", 250) + "@example.com", ErrEmail},
	}
	for _, tc := range cases {
		if _, err := Mint(tc.publicURL, tc.secret, tc.email, testNow, testJTI); err != tc.wantErr {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.wantErr)
		}
	}
	// localhost over http is the one plaintext exception, and default ports
	// fold into the origin the way a browser's URL.origin does.
	for in, want := range map[string]string{
		"http://localhost:3000/":        "http://localhost:3000",
		"http://127.0.0.1:80":           "http://127.0.0.1",
		"https://Pilot.Example.com:443": "https://pilot.example.com",
	} {
		got, err := Origin(in)
		if err != nil || got != want {
			t.Errorf("Origin(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}
