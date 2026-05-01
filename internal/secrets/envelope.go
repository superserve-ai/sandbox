// Package secrets implements envelope encryption for the secrets proxy
// (see docs/SECRETS_PROXY_PLAN.md). Each secret value is encrypted with a
// fresh AES-256-GCM data encryption key (DEK); the DEK is wrapped by a
// Cloud KMS key encryption key (KEK). At rest we store ciphertext +
// wrapped DEK + KEK resource name. Plaintext only ever lives in process
// memory at decrypt time.
package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
)

// Encrypted is the at-rest form of a secret. The three fields map 1:1 to
// the secret table's ciphertext / encrypted_dek / kek_id columns.
type Encrypted struct {
	// Ciphertext is nonce(12) || aes-256-gcm(plaintext, dek) || tag(16),
	// matching crypto/cipher.AEAD.Seal output with the nonce prefixed.
	Ciphertext []byte
	// EncryptedDEK is the per-row data key wrapped by the KEK. KMS
	// embeds the key version that wrapped it, so decrypt round-trips
	// across KEK rotation.
	EncryptedDEK []byte
	// KEKID is the KMS resource name (projects/.../cryptoKeys/...) used
	// to wrap the DEK. Stored per row so a future KEK migration can
	// decrypt rows wrapped by either KEK.
	KEKID string
}

// Encryptor is the interface used by the rest of the codebase. The only
// production implementation is KMSEncryptor; tests substitute a fake.
type Encryptor interface {
	Encrypt(ctx context.Context, plaintext []byte) (Encrypted, error)
	Decrypt(ctx context.Context, enc Encrypted) ([]byte, error)
}

// dekSize is the AES-256 key size. Must match aes.BlockSize math: a
// 256-bit key uses a 16-byte block, GCM uses a 12-byte nonce. Changing
// this constant requires a migration since old rows would have shorter
// DEKs, so we hardcode and assert on decrypt.
const dekSize = 32

// KMSEncryptor wraps DEKs with Cloud KMS. One instance per process is
// enough — the underlying KMS client maintains its own connection pool.
type KMSEncryptor struct {
	client *kms.KeyManagementClient
	kekID  string
}

// NewKMSEncryptor returns an Encryptor that wraps DEKs with the given
// KEK. kekID is the full resource name:
// projects/<project>/locations/<region>/keyRings/<ring>/cryptoKeys/<key>.
func NewKMSEncryptor(client *kms.KeyManagementClient, kekID string) *KMSEncryptor {
	return &KMSEncryptor{client: client, kekID: kekID}
}

// Encrypt generates a fresh DEK, AES-GCM-encrypts plaintext under it, and
// wraps the DEK with the configured KEK. The DEK never leaves this
// function — it's discarded as soon as Encrypt returns.
func (e *KMSEncryptor) Encrypt(ctx context.Context, plaintext []byte) (Encrypted, error) {
	dek := make([]byte, dekSize)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return Encrypted{}, fmt.Errorf("generate DEK: %w", err)
	}

	ct, err := aesGCMSeal(dek, plaintext)
	if err != nil {
		return Encrypted{}, err
	}

	resp, err := e.client.Encrypt(ctx, &kmspb.EncryptRequest{
		Name:      e.kekID,
		Plaintext: dek,
	})
	if err != nil {
		return Encrypted{}, fmt.Errorf("kms wrap dek: %w", err)
	}

	return Encrypted{
		Ciphertext:   ct,
		EncryptedDEK: resp.GetCiphertext(),
		KEKID:        e.kekID,
	}, nil
}

// Decrypt unwraps the DEK with the KEK named on the row (which may
// differ from this process's configured KEK in cross-environment
// migration scenarios), then AES-GCM-decrypts the ciphertext.
func (e *KMSEncryptor) Decrypt(ctx context.Context, enc Encrypted) ([]byte, error) {
	if enc.KEKID == "" {
		return nil, errors.New("encrypted: missing kek_id")
	}
	resp, err := e.client.Decrypt(ctx, &kmspb.DecryptRequest{
		Name:       enc.KEKID,
		Ciphertext: enc.EncryptedDEK,
	})
	if err != nil {
		return nil, fmt.Errorf("kms unwrap dek: %w", err)
	}
	dek := resp.GetPlaintext()
	if len(dek) != dekSize {
		return nil, fmt.Errorf("unwrapped dek size %d, want %d", len(dek), dekSize)
	}
	return aesGCMOpen(dek, enc.Ciphertext)
}

// aesGCMSeal encrypts plaintext with a 256-bit key using AES-GCM and
// returns nonce || ciphertext || tag. The nonce is a fresh 12 random
// bytes, safe because the DEK is one-time per row.
func aesGCMSeal(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	out := make([]byte, 0, len(nonce)+len(plaintext)+aead.Overhead())
	out = append(out, nonce...)
	return aead.Seal(out, nonce, plaintext, nil), nil
}

// aesGCMOpen reverses aesGCMSeal.
func aesGCMOpen(key, packed []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	if len(packed) < aead.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce := packed[:aead.NonceSize()]
	ct := packed[aead.NonceSize():]
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("gcm open: %w", err)
	}
	return pt, nil
}
