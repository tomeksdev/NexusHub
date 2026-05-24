// Pure-helper tests for handler package. Kept un-tagged (no
// `//go:build integration`) so they run under the default
// `go test ./...` and contribute to the coverage floor — the
// existing wg_test.go / auth_test.go / ebpf_rule_test.go /
// users_audit_test.go suites are integration-tagged because they
// need testcontainers, which is correct but means the package
// reads as 0% in default test runs.

package handler

import (
	"net/netip"
	"testing"

	"github.com/tomeksdev/NexusHub/backend/internal/repository"
)

func TestInSet(t *testing.T) {
	cases := []struct {
		s    string
		set  []string
		want bool
	}{
		{"allow", validActions, true},
		{"deny", validActions, true},
		{"sideways", validActions, false},
		{"", validActions, false},
		{"any", validProtocols, true},
		{"icmpv6", validProtocols, false},
	}
	for _, c := range cases {
		if got := inSet(c.s, c.set); got != c.want {
			t.Errorf("inSet(%q): got %v want %v", c.s, got, c.want)
		}
	}
}

func TestValidatePortPair(t *testing.T) {
	one, two, max, neg := 1, 2, 65535, -1
	cases := []struct {
		name     string
		from, to *int
		wantErr  bool
	}{
		{"both nil → wildcard", nil, nil, false},
		{"one side only is invalid", &one, nil, true},
		{"reversed range", &two, &one, true},
		{"valid range", &one, &two, false},
		{"max boundary", &one, &max, false},
		{"negative side", &neg, &one, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validatePortPair(c.from, c.to, "src")
			if (err != nil) != c.wantErr {
				t.Errorf("err=%v want_err=%v", err, c.wantErr)
			}
		})
	}
}

func TestRejectFullTunnelServerSide(t *testing.T) {
	v4Full := netip.MustParsePrefix("0.0.0.0/0")
	v6Full := netip.MustParsePrefix("::/0")
	host := netip.MustParsePrefix("10.0.0.5/32")
	net24 := netip.MustParsePrefix("10.0.0.0/24")

	cases := []struct {
		name    string
		in      []netip.Prefix
		wantErr bool
	}{
		{"empty list", nil, false},
		{"host only", []netip.Prefix{host}, false},
		{"net only", []netip.Prefix{net24}, false},
		{"v4 full tunnel rejected", []netip.Prefix{v4Full}, true},
		{"v6 full tunnel rejected", []netip.Prefix{v6Full}, true},
		{"mixed with full tunnel still rejected", []netip.Prefix{host, v4Full}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := rejectFullTunnelServerSide(c.in)
			if (err != nil) != c.wantErr {
				t.Errorf("err=%v want_err=%v", err, c.wantErr)
			}
		})
	}
}

func TestUpdateTouchesNonActiveFields(t *testing.T) {
	name := "rule-1"
	active := true
	prio := 50
	cases := []struct {
		name string
		p    repository.UpdateRuleParams
		want bool
	}{
		{"empty patch", repository.UpdateRuleParams{}, false},
		{"only is_active", repository.UpdateRuleParams{IsActive: &active}, false},
		{"name change", repository.UpdateRuleParams{Name: &name}, true},
		{"priority change", repository.UpdateRuleParams{Priority: &prio}, true},
		{"is_active + name", repository.UpdateRuleParams{IsActive: &active, Name: &name}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := updateTouchesNonActiveFields(c.p); got != c.want {
				t.Errorf("got %v want %v", got, c.want)
			}
		})
	}
}

func TestParseOptionalCIDR(t *testing.T) {
	empty := ""
	host := "10.0.0.5/32"
	bad := "not a cidr"
	cases := []struct {
		name    string
		in      *string
		wantNil bool
		wantErr bool
	}{
		{"nil → nil", nil, true, false},
		{"empty → nil", &empty, true, false},
		{"valid /32", &host, false, false},
		{"invalid → error", &bad, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := parseOptionalCIDR(c.in, "src_cidr")
			if (err != nil) != c.wantErr {
				t.Errorf("err=%v want_err=%v", err, c.wantErr)
			}
			if (p == nil) != c.wantNil {
				t.Errorf("nil-ness: got nil=%v want nil=%v", p == nil, c.wantNil)
			}
		})
	}
}
