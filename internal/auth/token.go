// Package auth implements signed short-lived tokens used to grant browsers
// direct, time-bounded access to streaming endpoints (PTY terminal, future
// log tailers, etc.) on the edge proxy.
//
// Why this exists
//
// The control plane is the only service that knows whether a caller is
// allowed to access a given sandbox (API key → team → sandbox membership).
// The edge proxy serves user-facing data plane traffic and must stay
// stateless and scalable independent of the control plane. We bridge the two
// with a short-lived signed token: the control plane mints, the edge proxy
// verifies. No DB call on the data path, no shared mutable state.
//
// Token format
//
// We deliberately do NOT use JWT — alg-confusion CVEs, oversized libraries,
// and far more flexibility than we need. The format is a compact custom
// envelope:
//
//	v1.<base64url(payload_json)>.<base64url(signature)>
//
// payload_json is the serialized Payload struct below. signature is an
// Ed25519 signature over the raw payload_json bytes.
//
// Ed25519 was chosen over HMAC because the keypair is asymmetric: only the
// control plane holds the private key. The edge proxy only ever needs the
// public key, so a compromised edge proxy cannot mint new tokens — only
// verify existing ones. This blast-radius reduction is the whole point of
// using asymmetric crypto for inter-service auth.
//
// Tokens are intentionally short-lived (default 60s) and single-use: each
// token carries a random Nonce that the verifier must dedupe to prevent
// replay even within the TTL window. The dedupe cache lives at the verifier
// (the edge proxy) — see internal/proxy for the LRU implementation.
package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Scope identifies what a token grants access to. Scopes are namespaces, not
// permissions — a `terminal` token cannot be used to download files even if
// the sandbox would otherwise allow it. Adding a new endpoint that needs a
// signed token means adding a new scope here.
type Scope string

const (
	// ScopeTerminal grants WebSocket upgrade access to a sandbox's PTY.
	ScopeTerminal Scope = "terminal"

	// ScopeFiles grants HTTP upload (POST) and download (GET) access to a
	// sandbox's /files endpoint on the edge proxy. A single scope covers
	// both directions because the capability to read and the capability
	// to write are already both implied by having raw filesystem access
	// to the sandbox — splitting them would create a false sense of
	// least-privilege without actually reducing blast radius. If a future
	// use case genuinely needs read-only handoff to an untrusted viewer,
	// add ScopeFilesRead as a separate capability then.
	ScopeFiles Scope = "files"
)

// Payload is the body of a signed token. Every field is required and
// validated on the verify side; missing or zero fields are a hard error.
type Payload struct {
	// SandboxID binds the token to a single sandbox. The verifier MUST
	// also check this against the request URL/host to prevent a token
	// minted for sandbox A from being replayed against sandbox B.
	SandboxID string `json:"sid"`

	// TeamID is carried so the edge proxy can log it for audit and
	// correlate connections back to the control plane mint event without
	// having to call the control plane.
	TeamID string `json:"tid"`

	// Scope restricts what the token can be used for. See ScopeTerminal etc.
	Scope Scope `json:"scp"`

	// ExpiresAt is the unix timestamp (seconds) after which the token is
	// invalid. Kept very short (default 60s) so a leaked token is nearly
	// worthless even before single-use enforcement kicks in.
	ExpiresAt int64 `json:"exp"`

	// IssuedAt is the unix timestamp (seconds) the token was minted. Used
	// for skew checks and observability.
	IssuedAt int64 `json:"iat"`

	// Nonce is a random per-token identifier. The verifier dedupes nonces
	// in an LRU cache so a captured token cannot be replayed even within
	// the TTL window. Hex-encoded so it round-trips JSON cleanly.
	Nonce string `json:"jti"`
}

// DefaultTTL is the lifetime of a freshly minted token. 60 seconds is plenty
// for the browser to receive the token from the control plane and complete
// the WebSocket handshake against the edge proxy. Anything longer just
// widens the leak window.
const DefaultTTL = 60 * time.Second

// nonceBytes is the size of the random nonce in bytes. 16 bytes (128 bits)
// is overkill for short-lived single-use tokens but eliminates any practical
// collision risk and matches the size of a UUID for log readability.
const nonceBytes = 16

// MaxClockSkew is how much wall-clock skew between control plane and edge
// proxy we tolerate when checking ExpiresAt and IssuedAt. NTP usually keeps
// servers within milliseconds of each other; 5 seconds is generous.
const MaxClockSkew = 5 * time.Second

// version prefix on every token. Bumping this allows future format changes
// without breaking older verifiers in the wild.
const tokenVersion = "v1"

// Sentinel errors. Callers should distinguish them so they can return the
// right HTTP status (e.g. expired → 401 with retry hint vs malformed → 400).
var (
	ErrMalformed       = errors.New("auth: malformed token")
	ErrUnknownVersion  = errors.New("auth: unknown token version")
	ErrBadSignature    = errors.New("auth: signature verification failed")
	ErrExpired         = errors.New("auth: token expired")
	ErrNotYetValid     = errors.New("auth: token issued in the future (clock skew)")
	ErrScopeMismatch   = errors.New("auth: token scope mismatch")
	ErrSandboxMismatch = errors.New("auth: token sandbox mismatch")
)

// Signer mints tokens. Only the control plane should hold a Signer because
// it owns the private key. Construct one with NewSigner.
type Signer struct {
	priv ed25519.PrivateKey
}

// NewSigner constructs a Signer from an Ed25519 private key. The key must
// be exactly ed25519.PrivateKeySize bytes; pass anything else and you get
// a panic immediately rather than a silent failure later.
func NewSigner(priv ed25519.PrivateKey) *Signer {
	if len(priv) != ed25519.PrivateKeySize {
		panic(fmt.Sprintf("auth: invalid Ed25519 private key length: got %d, want %d", len(priv), ed25519.PrivateKeySize))
	}
	return &Signer{priv: priv}
}

// Mint creates a signed token for the given sandbox/team/scope. The TTL is
// taken from DefaultTTL — we deliberately don't expose it as a parameter to
// keep all tokens short-lived; if a future use case needs a longer TTL it
// should be added explicitly with justification.
//
// `now` is taken as a parameter so tests can supply a fixed clock. Pass
// time.Now() in production code.
func (s *Signer) Mint(now time.Time, sandboxID, teamID string, scope Scope) (string, error) {
	if sandboxID == "" || teamID == "" || scope == "" {
		return "", fmt.Errorf("auth: mint requires non-empty sandbox_id, team_id, scope")
	}

	nonce, err := randomNonce()
	if err != nil {
		return "", fmt.Errorf("auth: nonce generation: %w", err)
	}

	payload := Payload{
		SandboxID: sandboxID,
		TeamID:    teamID,
		Scope:     scope,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(DefaultTTL).Unix(),
		Nonce:     nonce,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		// json.Marshal on a fixed struct with no funky types should
		// never fail — wrap defensively.
		return "", fmt.Errorf("auth: marshal payload: %w", err)
	}

	sig := ed25519.Sign(s.priv, body)

	enc := base64.RawURLEncoding
	return tokenVersion + "." + enc.EncodeToString(body) + "." + enc.EncodeToString(sig), nil
}

// Verifier validates tokens. The edge proxy holds one of these with only
// the public half of the keypair, so even if it's compromised the attacker
// cannot mint new tokens.
type Verifier struct {
	pub ed25519.PublicKey
}

// NewVerifier constructs a Verifier from an Ed25519 public key.
func NewVerifier(pub ed25519.PublicKey) *Verifier {
	if len(pub) != ed25519.PublicKeySize {
		panic(fmt.Sprintf("auth: invalid Ed25519 public key length: got %d, want %d", len(pub), ed25519.PublicKeySize))
	}
	return &Verifier{pub: pub}
}

// Verify decodes and verifies a token.
//
// On success it returns the parsed Payload. The caller is still responsible
// for two checks that depend on request context:
//
//  1. Bind the Nonce against a single-use cache (Verify does NOT do this —
//     replay protection is the caller's job because the cache is shared
//     state).
//  2. Compare Payload.SandboxID with the sandbox_id parsed from the
//     request URL/host using SameSandbox (defense against token misuse
//     across sandboxes).
//
// `now` is taken as a parameter for testability.
func (v *Verifier) Verify(token string, now time.Time, expectedScope Scope) (*Payload, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, ErrMalformed
	}
	if parts[0] != tokenVersion {
		return nil, ErrUnknownVersion
	}

	enc := base64.RawURLEncoding
	body, err := enc.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload not base64", ErrMalformed)
	}
	sig, err := enc.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: signature not base64", ErrMalformed)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: signature wrong length", ErrMalformed)
	}

	if !ed25519.Verify(v.pub, body, sig) {
		return nil, ErrBadSignature
	}

	var p Payload
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("%w: payload not json", ErrMalformed)
	}
	if p.SandboxID == "" || p.TeamID == "" || p.Scope == "" || p.Nonce == "" || p.ExpiresAt == 0 || p.IssuedAt == 0 {
		return nil, fmt.Errorf("%w: missing required field", ErrMalformed)
	}

	// Time checks. Allow MaxClockSkew on both ends to absorb NTP drift
	// between the issuer and the verifier.
	exp := time.Unix(p.ExpiresAt, 0)
	iat := time.Unix(p.IssuedAt, 0)
	if now.After(exp.Add(MaxClockSkew)) {
		return nil, ErrExpired
	}
	if now.Add(MaxClockSkew).Before(iat) {
		return nil, ErrNotYetValid
	}

	if p.Scope != expectedScope {
		return nil, ErrScopeMismatch
	}

	return &p, nil
}

// SameSandbox checks that a verified token's SandboxID matches the
// sandbox_id parsed from the request URL/host. This is the second half of
// replay protection: even if an attacker captures a token, they cannot use
// it against a different sandbox.
//
// Kept as a free function (not a method) so the caller passes both values
// explicitly and can't accidentally skip the check.
func SameSandbox(p *Payload, requestSandboxID string) error {
	if p.SandboxID != requestSandboxID {
		return ErrSandboxMismatch
	}
	return nil
}

// randomNonce returns a hex-encoded random string. Hex (not base64) so it
// looks like a normal request ID in logs.
func randomNonce() (string, error) {
	b := make([]byte, nonceBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
