package auth_test

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tomeksdev/NexusHub/backend/internal/auth"
)

const testSecret = "unit-test-secret-at-least-32-bytes!"

func TestIssueAndParseAccess(t *testing.T) {
	j, err := auth.NewJWTIssuer(testSecret, 5*time.Minute)
	if err != nil {
		t.Fatalf("NewJWTIssuer: %v", err)
	}
	uid := uuid.New()
	sid := uuid.New()

	tok, exp, err := j.IssueAccess(uid, sid, "admin")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if exp.Before(time.Now()) {
		t.Error("expiry should be in the future")
	}
	if strings.Count(tok, ".") != 2 {
		t.Errorf("expected three JWT segments, got %q", tok)
	}

	claims, err := j.ParseAccess(tok)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if claims.UserID != uid {
		t.Errorf("uid: got %s want %s", claims.UserID, uid)
	}
	if claims.SessionID != sid {
		t.Errorf("sid: got %s want %s", claims.SessionID, sid)
	}
	if claims.Role != "admin" {
		t.Errorf("role: got %q want admin", claims.Role)
	}
}

func TestParseAccessRejectsWrongSecret(t *testing.T) {
	a, _ := auth.NewJWTIssuer(testSecret, time.Minute)
	b, _ := auth.NewJWTIssuer("different-secret-at-least-32-bytes-long", time.Minute)

	tok, _, err := a.IssueAccess(uuid.New(), uuid.New(), "user")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := b.ParseAccess(tok); err == nil {
		t.Error("expected parse to fail with wrong secret")
	}
}

func TestParseAccessRejectsExpired(t *testing.T) {
	// Issue with a positive TTL so NewJWTIssuer accepts it, then manually
	// pass a token that's already expired by using a short TTL and sleeping.
	j, err := auth.NewJWTIssuer(testSecret, 1*time.Nanosecond)
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	tok, _, err := j.IssueAccess(uuid.New(), uuid.New(), "user")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	if _, err := j.ParseAccess(tok); err == nil {
		t.Error("expected expired token to fail parsing")
	}
}

func TestNewJWTIssuerRejectsShortSecret(t *testing.T) {
	if _, err := auth.NewJWTIssuer("too-short", time.Minute); err == nil {
		t.Error("expected error for short secret")
	}
}

func TestRefreshTokenRoundTrip(t *testing.T) {
	plain, hash, err := auth.NewRefreshToken()
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if len(hash) != 32 {
		t.Errorf("hash len: got %d want 32", len(hash))
	}
	// Decoded length must be 32 bytes → RawURLEncoding of 32 bytes = 43 chars.
	if len(plain) != 43 {
		t.Errorf("plain len: got %d want 43", len(plain))
	}

	again, err := auth.HashRefreshToken(plain)
	if err != nil {
		t.Fatalf("hash again: %v", err)
	}
	if string(again) != string(hash) {
		t.Error("re-hash mismatch")
	}
}

func TestHashRefreshTokenRejectsShort(t *testing.T) {
	short := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	if _, err := auth.HashRefreshToken(short); err == nil {
		t.Error("expected rejection of short refresh token")
	}
}

func TestHashPasswordAndVerify(t *testing.T) {
	hash, err := auth.HashPassword("hunter2hunter2hunter2")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	ok, err := auth.VerifyPassword("hunter2hunter2hunter2", hash)
	if err != nil || !ok {
		t.Errorf("verify: ok=%v err=%v", ok, err)
	}
	ok, err = auth.VerifyPassword("wrong", hash)
	if err != nil {
		t.Errorf("verify wrong err: %v", err)
	}
	if ok {
		t.Error("wrong password verified")
	}
}
