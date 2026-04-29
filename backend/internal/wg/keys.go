// Package wg collects WireGuard-adjacent primitives: curve25519 key
// material, IP-pool allocation, and the thin wrapper over wgctrl that the
// rest of the backend uses instead of touching the kernel directly.
package wg

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// PrivateKeyLen is the curve25519 scalar size. Public keys derive from the
// same-length secret and base64-encode to 44 characters including the
// trailing '=' — that's what the database CHECK constraint expects.
const PrivateKeyLen = curve25519.ScalarSize

// PresharedKeyLen matches WireGuard's pre-shared key size (32 bytes of
// symmetric entropy, base64 to 44 characters).
const PresharedKeyLen = 32

// PublicKeyB64Len is the canonical base64 length of a curve25519 public
// key, i.e. ceil(32/3)*4 = 44.
const PublicKeyB64Len = 44

// ErrInvalidPublicKey indicates a key that does not decode to 32 bytes of
// base64. The DB CHECK constraint catches these too, but we fail earlier.
var ErrInvalidPublicKey = errors.New("public key must be 32 bytes base64")

// KeyPair is a newly-generated peer/interface key pair. Private is raw
// 32-byte scalar (caller MUST encrypt before writing to storage); Public is
// already base64 for direct INSERT.
type KeyPair struct {
	Private []byte
	Public  string
}

// GenerateKeyPair creates a fresh curve25519 key pair with RFC 7748 §5
// clamping applied to the private scalar.
func GenerateKeyPair() (KeyPair, error) {
	var priv [PrivateKeyLen]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return KeyPair{}, fmt.Errorf("read random: %w", err)
	}
	// Clamp — required so the scalar lands in the valid subgroup.
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return KeyPair{}, fmt.Errorf("derive public: %w", err)
	}
	return KeyPair{
		Private: priv[:],
		Public:  base64.StdEncoding.EncodeToString(pub),
	}, nil
}

// DerivePublic returns the base64 public key for a given 32-byte private
// scalar. Used on read paths when we only have the decrypted private blob.
func DerivePublic(priv []byte) (string, error) {
	if len(priv) != PrivateKeyLen {
		return "", fmt.Errorf("private key: want %d bytes, got %d", PrivateKeyLen, len(priv))
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", fmt.Errorf("derive public: %w", err)
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}

// GeneratePresharedKey returns 32 bytes of random entropy suitable for the
// WireGuard PSK slot.
func GeneratePresharedKey() ([]byte, error) {
	psk := make([]byte, PresharedKeyLen)
	if _, err := rand.Read(psk); err != nil {
		return nil, fmt.Errorf("read random: %w", err)
	}
	return psk, nil
}

// EncodePublicKey is a small helper so callers don't have to import
// encoding/base64 alongside this package.
func EncodePublicKey(raw []byte) string {
	return base64.StdEncoding.EncodeToString(raw)
}

// DecodePublicKey validates shape (44 chars, decodes to 32 bytes) and
// returns the raw scalar. Returns ErrInvalidPublicKey on any failure.
func DecodePublicKey(s string) ([]byte, error) {
	if len(s) != PublicKeyB64Len {
		return nil, ErrInvalidPublicKey
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != PrivateKeyLen {
		return nil, ErrInvalidPublicKey
	}
	return raw, nil
}
