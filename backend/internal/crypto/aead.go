// Package crypto wraps AES-256-GCM for at-rest encryption of sensitive
// column values — principally WireGuard private keys in wg_peers and
// wg_interfaces, but the API is deliberately generic so the same primitive
// can encrypt future secrets (API keys, TOTP seeds) without adding new
// packages.
//
// The ciphertext layout is nonce || sealed, stored as a single BYTEA.
// Callers never see or pick a nonce; each Seal() draws a fresh 12-byte
// random nonce.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// KeyLen is the required master-key length (AES-256).
const KeyLen = 32

// ErrKeyLength is returned when the configured master key is the wrong size.
var ErrKeyLength = fmt.Errorf("master key must decode to %d bytes", KeyLen)

// ErrCiphertextTooShort is returned when Open() is handed fewer bytes than
// the nonce size — almost always a sign of a corrupted row or a wrong key.
var ErrCiphertextTooShort = errors.New("ciphertext shorter than nonce")

// AEAD holds an initialised AES-256-GCM cipher. It is safe for concurrent
// use by multiple goroutines; all state beyond the constructor lives inside
// the gcm.AEAD, which is itself concurrent-safe.
type AEAD struct {
	gcm cipher.AEAD
}

// New builds an AEAD from a raw 32-byte key.
func New(key []byte) (*AEAD, error) {
	if len(key) != KeyLen {
		return nil, ErrKeyLength
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	return &AEAD{gcm: gcm}, nil
}

// NewFromBase64 decodes a standard-base64 master key (the shape the
// PEER_KEY_ENCRYPTION_KEY env var takes) before building an AEAD.
func NewFromBase64(s string) (*AEAD, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode master key: %w", err)
	}
	return New(raw)
}

// Seal encrypts plaintext and returns nonce || ciphertext. aad may be nil;
// when supplied it is bound to the ciphertext and must match on Open().
func (a *AEAD) Seal(plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, a.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("read nonce: %w", err)
	}
	// Seal appends to nonce, so the returned slice is exactly nonce || sealed.
	return a.gcm.Seal(nonce, nonce, plaintext, aad), nil
}

// Open reverses Seal. The aad must match what was supplied at seal time.
func (a *AEAD) Open(ciphertext, aad []byte) ([]byte, error) {
	ns := a.gcm.NonceSize()
	if len(ciphertext) < ns {
		return nil, ErrCiphertextTooShort
	}
	nonce, sealed := ciphertext[:ns], ciphertext[ns:]
	plaintext, err := a.gcm.Open(nil, nonce, sealed, aad)
	if err != nil {
		return nil, fmt.Errorf("gcm open: %w", err)
	}
	return plaintext, nil
}
