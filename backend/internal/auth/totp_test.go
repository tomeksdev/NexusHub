package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestGenerateTOTPFieldsPopulated(t *testing.T) {
	e, err := GenerateTOTP("alice@example.com")
	if err != nil {
		t.Fatalf("GenerateTOTP: %v", err)
	}
	if e.Secret == "" {
		t.Error("Secret empty")
	}
	if e.AccountName != "alice@example.com" {
		t.Errorf("AccountName = %q, want alice@example.com", e.AccountName)
	}
	// otpauth URI must include the issuer + account so authenticators
	// can label the entry unambiguously, and it must carry the
	// generated secret verbatim.
	for _, want := range []string{
		"otpauth://totp/",
		"issuer=" + TOTPIssuer,
		"secret=" + e.Secret,
	} {
		if !strings.Contains(e.OtpauthURI, want) {
			t.Errorf("OtpauthURI %q missing %q", e.OtpauthURI, want)
		}
	}
}

func TestValidateTOTPAcceptsCurrentCode(t *testing.T) {
	e, err := GenerateTOTP("bob@example.com")
	if err != nil {
		t.Fatalf("GenerateTOTP: %v", err)
	}
	code, err := totp.GenerateCode(e.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if !ValidateTOTP(e.Secret, code) {
		t.Errorf("current code %q did not validate against secret", code)
	}
}

func TestValidateTOTPRejectsWrongCode(t *testing.T) {
	e, err := GenerateTOTP("bob@example.com")
	if err != nil {
		t.Fatalf("GenerateTOTP: %v", err)
	}
	if ValidateTOTP(e.Secret, "000000") {
		t.Error("000000 should not validate — the chance of a false positive per test run is 1-in-a-million")
	}
}

func TestValidateTOTPStrictErrorPaths(t *testing.T) {
	e, err := GenerateTOTP("carol@example.com")
	if err != nil {
		t.Fatalf("GenerateTOTP: %v", err)
	}

	if err := ValidateTOTPStrict("", "123456"); err == nil {
		t.Error("empty secret should error")
	}
	if err := ValidateTOTPStrict(e.Secret, ""); err == nil {
		t.Error("empty code should error")
	}
	if err := ValidateTOTPStrict(e.Secret, "badcod"); err == nil {
		t.Error("non-numeric code should error")
	}
	code, _ := totp.GenerateCode(e.Secret, time.Now().UTC())
	if err := ValidateTOTPStrict(e.Secret, code); err != nil {
		t.Errorf("valid code rejected: %v", err)
	}
}

func TestValidateTOTPStrictAcceptsOneStepSkew(t *testing.T) {
	// Skew=1 means the window either side of now is also accepted.
	// We generate a code for 30 s ago and confirm it still passes —
	// this is what absorbs realistic clock drift on user devices.
	e, err := GenerateTOTP("dave@example.com")
	if err != nil {
		t.Fatalf("GenerateTOTP: %v", err)
	}
	past := time.Now().UTC().Add(-30 * time.Second)
	code, err := totp.GenerateCode(e.Secret, past)
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if err := ValidateTOTPStrict(e.Secret, code); err != nil {
		t.Errorf("code from one step ago should validate: %v", err)
	}
}
