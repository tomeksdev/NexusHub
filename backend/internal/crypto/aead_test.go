package crypto_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/tomeksdev/NexusHub/backend/internal/crypto"
)

func mustKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, crypto.KeyLen)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestAEADRoundTrip(t *testing.T) {
	a, err := crypto.New(mustKey(t))
	if err != nil {
		t.Fatal(err)
	}

	plain := []byte("curve25519 private key, 32 bytes")
	aad := []byte("peer:abc-123")

	ct, err := a.Seal(plain, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, plain) {
		t.Error("ciphertext leaks plaintext bytes")
	}

	got, err := a.Open(ct, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("plaintext mismatch: %q vs %q", got, plain)
	}
}

func TestAEADNonceUniqueness(t *testing.T) {
	a, _ := crypto.New(mustKey(t))
	ct1, _ := a.Seal([]byte("x"), nil)
	ct2, _ := a.Seal([]byte("x"), nil)
	if bytes.Equal(ct1, ct2) {
		t.Error("repeated seals produced identical ciphertext — nonce reuse")
	}
}

func TestAEADRejectsWrongAAD(t *testing.T) {
	a, _ := crypto.New(mustKey(t))
	ct, _ := a.Seal([]byte("secret"), []byte("peer:A"))
	if _, err := a.Open(ct, []byte("peer:B")); err == nil {
		t.Error("open with wrong aad must fail")
	}
}

func TestAEADRejectsTampering(t *testing.T) {
	a, _ := crypto.New(mustKey(t))
	ct, _ := a.Seal([]byte("secret"), nil)
	ct[len(ct)-1] ^= 0xff
	if _, err := a.Open(ct, nil); err == nil {
		t.Error("open of tampered ciphertext must fail")
	}
}

func TestAEADKeyLength(t *testing.T) {
	if _, err := crypto.New(make([]byte, 16)); err == nil {
		t.Error("16-byte key must be rejected")
	}
	if _, err := crypto.New(make([]byte, 33)); err == nil {
		t.Error("33-byte key must be rejected")
	}
}

func TestAEADShortCiphertext(t *testing.T) {
	a, _ := crypto.New(mustKey(t))
	if _, err := a.Open([]byte{1, 2, 3}, nil); err == nil {
		t.Error("short ciphertext must be rejected")
	}
}

func TestNewFromBase64(t *testing.T) {
	key := mustKey(t)
	enc := base64.StdEncoding.EncodeToString(key)

	a, err := crypto.NewFromBase64(enc)
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := a.Seal([]byte("hello"), nil)

	// Re-decoded key opens the same ciphertext.
	b, _ := crypto.NewFromBase64(enc)
	got, err := b.Open(ct, nil)
	if err != nil || string(got) != "hello" {
		t.Errorf("round trip across NewFromBase64 failed: %v %q", err, got)
	}

	if _, err := crypto.NewFromBase64("not valid base64!!"); err == nil {
		t.Error("malformed base64 must be rejected")
	}
}
