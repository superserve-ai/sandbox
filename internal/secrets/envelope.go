// Package secrets implements envelope encryption and JWT minting for
// stored credentials. Each value is encrypted with a fresh AES-256-GCM
// data encryption key (DEK); the DEK is wrapped by a Cloud KMS key
// encryption key (KEK). Plaintext only lives in process memory at
// decrypt time.
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

// Encrypted is the at-rest form of a secret.
type Encrypted struct {
	// Ciphertext: nonce(12) || aes-256-gcm(plaintext, dek) || tag(16).
	Ciphertext []byte
	// EncryptedDEK is the per-row data key wrapped by the KEK named in KEKID.
	EncryptedDEK []byte
	// KEKID is the KMS resource name used to wrap the DEK.
	KEKID string
}

type Encryptor interface {
	Encrypt(ctx context.Context, plaintext []byte) (Encrypted, error)
	Decrypt(ctx context.Context, enc Encrypted) ([]byte, error)
}

const dekSize = 32

type KMSEncryptor struct {
	client *kms.KeyManagementClient
	kekID  string
}

// NewKMSEncryptor returns an Encryptor that wraps DEKs with kekID:
// projects/<project>/locations/<region>/keyRings/<ring>/cryptoKeys/<key>.
func NewKMSEncryptor(client *kms.KeyManagementClient, kekID string) *KMSEncryptor {
	return &KMSEncryptor{client: client, kekID: kekID}
}

// Encrypt generates a fresh DEK, AES-GCM-seals plaintext under it, and
// wraps the DEK with the configured KEK.
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

// Decrypt uses enc.KEKID (which may differ from the configured kekID
// after a KEK migration) to unwrap the DEK, then opens the ciphertext.
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

// aesGCMSeal returns nonce || ciphertext || tag.
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
