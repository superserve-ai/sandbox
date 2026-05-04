package secrets

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

// fakeEncryptor is a test-only Encryptor that uses a fixed master key
// for "wrapping" the per-row DEK. It exercises the same envelope shape
// (DEK + nonce-prefixed AES-GCM) as KMSEncryptor, just with the KMS
// round-trip swapped for an in-process AES-GCM under the master key.
type fakeEncryptor struct {
	master []byte
	kekID  string
	// failWrap, when set, causes Encrypt to fail at the wrap step.
	failWrap bool
}

func newFakeEncryptor(t *testing.T) *fakeEncryptor {
	t.Helper()
	m := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, m); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return &fakeEncryptor{master: m, kekID: "fake://kek/v1"}
}

func (f *fakeEncryptor) Encrypt(_ context.Context, plaintext []byte) (Encrypted, error) {
	if f.failWrap {
		return Encrypted{}, errors.New("fake wrap failure")
	}
	dek := make([]byte, dekSize)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return Encrypted{}, err
	}
	ct, err := aesGCMSeal(dek, plaintext)
	if err != nil {
		return Encrypted{}, err
	}
	wrapped, err := aesGCMSeal(f.master, dek)
	if err != nil {
		return Encrypted{}, err
	}
	return Encrypted{Ciphertext: ct, EncryptedDEK: wrapped, KEKID: f.kekID}, nil
}

func (f *fakeEncryptor) Decrypt(_ context.Context, enc Encrypted) ([]byte, error) {
	if enc.KEKID != f.kekID {
		return nil, errors.New("kek mismatch")
	}
	dek, err := aesGCMOpen(f.master, enc.EncryptedDEK)
	if err != nil {
		return nil, err
	}
	return aesGCMOpen(dek, enc.Ciphertext)
}

func TestEncryptor_RoundTrip(t *testing.T) {
	e := newFakeEncryptor(t)
	ctx := context.Background()

	cases := []struct {
		name string
		in   []byte
	}{
		{"short", []byte("sk-ant-test")},
		{"realistic", []byte("sk-ant-api03-" + string(make([]byte, 64)))},
		{"empty", []byte{}},
		{"binary", []byte{0x00, 0xFF, 0x10, 0x80, 0x01}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enc, err := e.Encrypt(ctx, tc.in)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			if string(enc.Ciphertext) == string(tc.in) {
				t.Fatal("ciphertext equals plaintext — encryption did nothing")
			}
			pt, err := e.Decrypt(ctx, enc)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if string(pt) != string(tc.in) {
				t.Fatalf("round-trip mismatch: got %q, want %q", pt, tc.in)
			}
		})
	}
}

func TestEncryptor_DistinctCiphertextsForSamePlaintext(t *testing.T) {
	// Same plaintext encrypted twice must produce different ciphertexts:
	// fresh DEK + fresh nonce per call. Catches accidental nonce reuse
	// or hardcoded keys.
	e := newFakeEncryptor(t)
	ctx := context.Background()
	plain := []byte("sk-ant-deterministic-test")

	a, err := e.Encrypt(ctx, plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	b, err := e.Encrypt(ctx, plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if string(a.Ciphertext) == string(b.Ciphertext) {
		t.Fatal("identical ciphertexts for two encryptions of same plaintext")
	}
	if string(a.EncryptedDEK) == string(b.EncryptedDEK) {
		t.Fatal("identical wrapped DEKs — DEK is not fresh per call")
	}
}

func TestEncryptor_DecryptTamperedCiphertext(t *testing.T) {
	e := newFakeEncryptor(t)
	ctx := context.Background()

	enc, err := e.Encrypt(ctx, []byte("sensitive"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	// Flip the last byte of the GCM tag.
	enc.Ciphertext[len(enc.Ciphertext)-1] ^= 0x01
	if _, err := e.Decrypt(ctx, enc); err == nil {
		t.Fatal("Decrypt accepted tampered ciphertext")
	}
}

func TestEncryptor_WrapFailure(t *testing.T) {
	e := newFakeEncryptor(t)
	e.failWrap = true
	if _, err := e.Encrypt(context.Background(), []byte("x")); err == nil {
		t.Fatal("Encrypt did not surface wrap failure")
	}
}

func TestAESGCMOpen_TooShort(t *testing.T) {
	key := make([]byte, 32)
	if _, err := aesGCMOpen(key, []byte{0x00, 0x01}); err == nil {
		t.Fatal("expected error on short ciphertext")
	}
}
