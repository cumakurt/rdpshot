package target

import (
	"testing"
)

func TestDomainToBaseDN(t *testing.T) {
	cases := []struct {
		domain string
		want   string
	}{
		{"corp.example.com", "DC=corp,DC=example,DC=com"},
		{"lab.local", "DC=lab,DC=local"},
		{"sub.domain.co.uk", "DC=sub,DC=domain,DC=co,DC=uk"},
		{"", ""},
		{".single.", "DC=single"},
	}

	for _, tc := range cases {
		got := DomainToBaseDN(tc.domain)
		if got != tc.want {
			t.Errorf("DomainToBaseDN(%q) = %q; want %q", tc.domain, got, tc.want)
		}
	}
}

func TestDiscoverLDAPValidation(t *testing.T) {
	// Empty server and domain should fail immediately
	_, err := DiscoverLDAP(LDAPOptions{})
	if err == nil {
		t.Errorf("expected error for empty server and domain, got nil")
	}

	// Dial to an unreachable non-existent domain should return a dial error (not crash)
	_, err = DiscoverLDAP(LDAPOptions{
		Server: "127.0.0.1:54321", // unlikely to have LDAP
		Domain: "test.local",
	})
	if err == nil {
		t.Errorf("expected error dialing unreachable port, got nil")
	}
}
