// Package kerberos provides a thin availability probe for CredSSP mech
// advertisement. Full AP-REQ construction is out of scope for this wave.
package kerberos

import (
	"os"
	"path/filepath"
)

// Available reports whether a Kerberos credential cache appears usable so
// CredSSP can advertise the Kerberos mechanism alongside NTLM.
func Available() bool {
	if p := os.Getenv("KRB5CCNAME"); p != "" {
		p = stripFilePrefix(p)
		if st, err := os.Stat(p); err == nil && st.Size() > 0 {
			return true
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		cc := filepath.Join(home, ".krb5", "cache")
		if st, err := os.Stat(cc); err == nil && st.Size() > 0 {
			return true
		}
		// Common FILE:/tmp/krb5cc_UID layout.
		matches, _ := filepath.Glob("/tmp/krb5cc_*")
		for _, m := range matches {
			if st, err := os.Stat(m); err == nil && st.Size() > 0 {
				return true
			}
		}
	}
	if p := os.Getenv("KRB5_KTNAME"); p != "" {
		p = stripFilePrefix(p)
		if st, err := os.Stat(p); err == nil && st.Size() > 0 {
			return true
		}
	}
	return false
}

func stripFilePrefix(p string) string {
	const prefix = "FILE:"
	if len(p) > len(prefix) && p[:len(prefix)] == prefix {
		return p[len(prefix):]
	}
	return p
}
