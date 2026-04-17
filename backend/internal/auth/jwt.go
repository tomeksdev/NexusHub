package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// AccessClaims is what we sign into a JWT access token. Kept intentionally
// small — anything role- or permission-related must be re-checked against
// the DB on privileged actions, never trusted from the token alone.
type AccessClaims struct {
	UserID    uuid.UUID `json:"uid"`
	SessionID uuid.UUID `json:"sid"`
	Role      string    `json:"role"`
	jwt.RegisteredClaims
}

// JWTIssuer signs and verifies HS256 access tokens. Refresh tokens are
// opaque and do not flow through this type.
type JWTIssuer struct {
	secret       []byte
	accessExpiry time.Duration
	issuer       string
	now          func() time.Time // injectable for tests
}

const jwtIssuer = "nexushub"

// NewJWTIssuer returns an HS256 issuer. secret must be at least 32 bytes;
// anything shorter is a configuration error.
func NewJWTIssuer(secret string, accessExpiry time.Duration) (*JWTIssuer, error) {
	if len(secret) < 32 {
		return nil, fmt.Errorf("jwt secret must be >= 32 bytes, got %d", len(secret))
	}
	if accessExpiry <= 0 {
		return nil, errors.New("access expiry must be positive")
	}
	return &JWTIssuer{
		secret:       []byte(secret),
		accessExpiry: accessExpiry,
		issuer:       jwtIssuer,
		now:          time.Now,
	}, nil
}

// IssueAccess returns a signed JWT for the given session.
func (j *JWTIssuer) IssueAccess(userID, sessionID uuid.UUID, role string) (string, time.Time, error) {
	now := j.now()
	expiresAt := now.Add(j.accessExpiry)

	claims := AccessClaims{
		UserID:    userID,
		SessionID: sessionID,
		Role:      role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    j.issuer,
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			ID:        uuid.NewString(),
		},
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(j.secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign access token: %w", err)
	}
	return signed, expiresAt, nil
}

// ParseAccess validates the signature, issuer, and expiry and returns the
// claims. Returns an error for any tampering or expiry.
func (j *JWTIssuer) ParseAccess(token string) (*AccessClaims, error) {
	claims := &AccessClaims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return j.secret, nil
	}, jwt.WithIssuer(jwtIssuer), jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		return nil, err
	}
	if !parsed.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}

// RefreshTokenBytes is the length of the opaque refresh token payload before
// base64 encoding. 32 bytes → 256 bits of entropy.
const RefreshTokenBytes = 32

// NewRefreshToken returns a url-safe base64 opaque token plus its SHA-256
// hash. Only the hash is stored in the DB; the plaintext is returned to the
// client exactly once.
func NewRefreshToken() (plaintext string, hash []byte, err error) {
	buf := make([]byte, RefreshTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", nil, fmt.Errorf("read random: %w", err)
	}
	sum := sha256.Sum256(buf)
	return base64.RawURLEncoding.EncodeToString(buf), sum[:], nil
}

// HashRefreshToken recomputes the SHA-256 of a refresh-token string produced
// by NewRefreshToken. Used when a client presents a token for rotation.
func HashRefreshToken(plaintext string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(plaintext)
	if err != nil {
		return nil, fmt.Errorf("decode refresh token: %w", err)
	}
	if len(raw) != RefreshTokenBytes {
		return nil, fmt.Errorf("refresh token length: got %d, want %d", len(raw), RefreshTokenBytes)
	}
	sum := sha256.Sum256(raw)
	return sum[:], nil
}
