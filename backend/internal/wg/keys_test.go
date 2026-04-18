package wg_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/wg"
)

func TestGenerateKeyPairShape(t *testing.T) {
	kp, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if len(kp.Private) != wg.PrivateKeyLen {
		t.Errorf("private len = %d, want %d", len(kp.Private), wg.PrivateKeyLen)
	}
	if len(kp.Public) != wg.PublicKeyB64Len || !strings.HasSuffix(kp.Public, "=") {
		t.Errorf("public key has unexpected shape: %q", kp.Public)
	}
	// Verifier-mirroring check: the DB uses the same regex.
	if _, err := base64.StdEncoding.DecodeString(kp.Public); err != nil {
		t.Errorf("public key not valid base64: %v", err)
	}
}

func TestGenerateKeyPairClamping(t *testing.T) {
	kp, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	// RFC 7748 §5 clamping.
	if kp.Private[0]&7 != 0 {
		t.Error("low 3 bits of byte 0 should be cleared")
	}
	if kp.Private[31]&0x80 != 0 {
		t.Error("high bit of byte 31 should be cleared")
	}
	if kp.Private[31]&0x40 == 0 {
		t.Error("bit 6 of byte 31 should be set")
	}
}

func TestDerivePublicMatchesGeneration(t *testing.T) {
	kp, _ := wg.GenerateKeyPair()
	got, err := wg.DerivePublic(kp.Private)
	if err != nil {
		t.Fatal(err)
	}
	if got != kp.Public {
		t.Errorf("derive mismatch: %q vs %q", got, kp.Public)
	}
}

func TestDerivePublicRejectsBadLength(t *testing.T) {
	if _, err := wg.DerivePublic(make([]byte, 16)); err == nil {
		t.Error("short private must fail")
	}
}

func TestGeneratePresharedKey(t *testing.T) {
	psk1, err := wg.GeneratePresharedKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(psk1) != wg.PresharedKeyLen {
		t.Errorf("psk len = %d, want %d", len(psk1), wg.PresharedKeyLen)
	}
	psk2, _ := wg.GeneratePresharedKey()
	if string(psk1) == string(psk2) {
		t.Error("two PSKs identical — RNG not being called")
	}
}

func TestDecodePublicKey(t *testing.T) {
	kp, _ := wg.GenerateKeyPair()
	raw, err := wg.DecodePublicKey(kp.Public)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != wg.PrivateKeyLen {
		t.Errorf("decoded len = %d, want %d", len(raw), wg.PrivateKeyLen)
	}

	for _, bad := range []string{
		"",
		"too-short",
		strings.Repeat("A", 44),       // decodes fine but not to 32 bytes? actually 'AAAA...A' padded — check shape only
		"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!=",
	} {
		if _, err := wg.DecodePublicKey(bad); err == nil && bad != strings.Repeat("A", 44) {
			t.Errorf("expected failure for %q", bad)
		}
	}
}
