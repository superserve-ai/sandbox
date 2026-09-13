package steps

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// The per-tenant secrets the provisioner generates, in the shape the tenant
// image reads them. QM refuses to boot in production without the five core
// signing secrets, and its embedded sign-in broker refuses without the three
// AUTH_ values, so a tenant missing any of them is a tenant that either
// never becomes healthy or cannot be signed into. DATABASE_PASSWORD is the
// odd one out: the tenant never reads it, the database step does, to create
// the tenant's role and compose its DATABASE_URL.
//
// Not here, deliberately:
//
//   - the model provider key, which qm-api writes at create time
//   - DATABASE_URL, the bucket's HMAC credentials and the tenant's sandbox
//     key, which the steps that create those resources derive and write
//   - RESEND_API_KEY, which is platform-level: hosted QM has one Resend
//     account and one verified sending domain, so every tenant mounts the
//     same secret rather than getting a key of its own
const (
	secretDatabasePassword = "DATABASE_PASSWORD"
	secretDatabaseURL      = "DATABASE_URL"
	secretAccessKeyID      = "AWS_ACCESS_KEY_ID"
	secretSecretAccessKey  = "AWS_SECRET_ACCESS_KEY"
	secretSandboxAPIKey    = "SUPERSERVE_API_KEY"
	secretResendAPIKey     = "RESEND_API_KEY"
)

// sharedSecretRef is the name a tenant's row records the *platform* secret
// it was granted access to under. It is not a tenant secret: nothing is
// stored at qm-<slug>-RESEND_API_KEY, and the reference exists only so a
// teardown can revoke the grant it actually made, even after the
// configured name has been rotated to a different resource.
const sharedSecretRef = secretResendAPIKey

// derivedSecrets are the per-tenant secrets a later step computes from the
// resource it just created. The secrets step's rollback sweeps them too, so
// a teardown that reaches it leaves nothing behind even if the step that
// owns one never got to run its own.
var derivedSecrets = []string{secretDatabaseURL, secretAccessKeyID, secretSecretAccessKey, secretSandboxAPIKey}

// generatedSecret is one secret the secrets step creates. value produces a
// fresh one; nothing regenerates a secret that already exists.
type generatedSecret struct {
	name  string
	value func() (string, error)
}

// randomSecret is a hex secret of n bytes of entropy. QM requires its
// signing secrets to be at least 32 characters, so nothing here drops
// below 16 bytes.
func randomSecret(n int) func() (string, error) {
	return func() (string, error) { return randomHex(n) }
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// newSigningJWK is the broker's token-signing key: a P-256 private JSON Web
// Key, which is the only shape QM's auth config accepts (kty EC, crv P-256,
// with d). Generated per tenant so one tenant's tokens are worthless at
// another.
func newSigningJWK() (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate signing key: %w", err)
	}
	// Fixed-width coordinates: JWK requires the curve's octet length, and
	// big.Int.Bytes() drops leading zero bytes.
	const coordLen = 32
	pad := func(b []byte) string {
		out := make([]byte, coordLen)
		copy(out[coordLen-len(b):], b)
		return base64.RawURLEncoding.EncodeToString(out)
	}
	jwk := map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   pad(key.X.Bytes()),
		"y":   pad(key.Y.Bytes()),
		"d":   pad(key.D.Bytes()),
	}
	out, err := json.Marshal(jwk)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
