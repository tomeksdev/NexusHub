// Package auth holds primitives for credential hashing and verification.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonTime    uint32 = 3
	argonMemory  uint32 = 64 * 1024 // 64 MiB
	argonThreads uint8  = 4
	argonKeyLen  uint32 = 32
	saltLen             = 16
)

// HashPassword returns an argon2id-encoded password hash in the standard
// `$argon2id$v=19$m=...,t=...,p=...$salt$hash` format.
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("password must not be empty")
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("read salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// VerifyPassword returns true iff password matches encoded.
func VerifyPassword(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("invalid argon2id encoding")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, fmt.Errorf("parse version: %w", err)
	}
	if version != argon2.Version {
		return false, fmt.Errorf("unsupported argon2 version %d", version)
	}

	var memory, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false, fmt.Errorf("parse params: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("decode salt: %w", err)
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("decode hash: %w", err)
	}

	got := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
