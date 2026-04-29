package auth

import (
	"fmt"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TOTPIssuer is the label Google Authenticator etc. display above the
// account. Kept as a constant rather than threaded through config so
// changing it requires a code change — otherwise a typo in env would
// silently break key scanning for every user on next enrollment.
const TOTPIssuer = "NexusHub"

// TOTPEnrollment bundles everything a client needs to finish setup:
// the generated base32 secret (for users who type it manually) and
// the full otpauth:// URI (which every authenticator app can consume
// as a QR code). Both derive from the same Key — the client gets
// whichever is more convenient.
type TOTPEnrollment struct {
	Secret      string // base32, ASCII-safe
	OtpauthURI  string // otpauth://totp/NexusHub:<account>?secret=...&issuer=NexusHub
	AccountName string // typically the user's email
}

// GenerateTOTP creates a fresh secret for accountName. The default
// generator uses 30 s step / 6 digits / SHA-1, which matches what
// every mainstream authenticator app defaults to. Secret length is
// 20 bytes base32 (160 bits of entropy), which is the Google
// Authenticator recommended size.
func GenerateTOTP(accountName string) (TOTPEnrollment, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      TOTPIssuer,
		AccountName: accountName,
	})
	if err != nil {
		return TOTPEnrollment{}, fmt.Errorf("totp generate: %w", err)
	}
	return TOTPEnrollment{
		Secret:      key.Secret(),
		OtpauthURI:  key.URL(),
		AccountName: accountName,
	}, nil
}

// ValidateTOTP returns true when the 6-digit code matches the
// current time window for secret. pquerna/otp's Validate tolerates
// ±1 step (30 s) by default — enough to absorb realistic clock
// skew without opening a meaningful replay window.
//
// secret is the base32 string as stored on the server (decrypted
// by the caller before invocation).
func ValidateTOTP(secret, code string) bool {
	return totp.Validate(code, secret)
}

// ValidateTOTPStrict is the same check but returns an error that
// carries more context for logging paths that want to record why a
// code was rejected (empty, bad length, wrong). The happy path
// still returns nil.
func ValidateTOTPStrict(secret, code string) error {
	if secret == "" {
		return fmt.Errorf("totp: empty secret")
	}
	if len(code) == 0 {
		return fmt.Errorf("totp: empty code")
	}
	valid, err := totp.ValidateCustom(code, secret, nowUTC(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return fmt.Errorf("totp validate: %w", err)
	}
	if !valid {
		return fmt.Errorf("totp: code mismatch")
	}
	return nil
}
