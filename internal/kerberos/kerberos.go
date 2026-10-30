// Package kerberos provides a thin availability probe for CredSSP mech
// advertisement. Full AP-REQ construction is out of scope; this package only
// discovers whether a usable ccache or keytab is present.
package kerberos

import (
	"os"
	"path/filepath"
	"strings"
)

// Kind classifies the discovered Kerberos material.
const (
	KindNone   = "none"
	KindCCache = "ccache"
	KindKeytab = "keytab"
)

// Status describes local Kerberos material without reading ticket contents.
type Status struct {
	Available bool   `json:"available"`
	Kind      string `json:"kind"`
	Path      string `json:"path,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

// Available reports whether a Kerberos credential cache or keytab appears usable
// so CredSSP can advertise the Kerberos mechanism alongside NTLM.
func Available() bool {
	return Probe().Available
}

// Probe inspects common ccache/keytab locations and returns a discovery status.
func Probe() Status {
	if p := os.Getenv("KRB5CCNAME"); p != "" {
		p = stripFilePrefix(p)
		if st, err := os.Stat(p); err == nil && st.Size() > 0 {
			return Status{
				Available: true, Kind: KindCCache, Path: p,
				Detail: "KRB5CCNAME points to a non-empty ccache",
			}
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		cc := filepath.Join(home, ".krb5", "cache")
		if st, err := os.Stat(cc); err == nil && st.Size() > 0 {
			return Status{
				Available: true, Kind: KindCCache, Path: cc,
				Detail: "found ~/.krb5/cache",
			}
		}
		matches, _ := filepath.Glob("/tmp/krb5cc_*")
		for _, m := range matches {
			if st, err := os.Stat(m); err == nil && st.Size() > 0 {
				return Status{
					Available: true, Kind: KindCCache, Path: m,
					Detail: "found /tmp/krb5cc_* ccache",
				}
			}
		}
	}
	if p := os.Getenv("KRB5_KTNAME"); p != "" {
		p = stripFilePrefix(p)
		if st, err := os.Stat(p); err == nil && st.Size() > 0 {
			return Status{
				Available: true, Kind: KindKeytab, Path: p,
				Detail: "KRB5_KTNAME points to a non-empty keytab",
			}
		}
	}
	return Status{Available: false, Kind: KindNone, Detail: "no usable ccache or keytab"}
}

// SummaryLine is a short evidence string for ServiceInfo.Evidence maps.
func SummaryLine(st Status) string {
	if !st.Available {
		return st.Detail
	}
	parts := []string{"client offered Kerberos mech"}
	if st.Kind != "" && st.Kind != KindNone {
		parts = append(parts, "kind="+st.Kind)
	}
	if st.Detail != "" {
		parts = append(parts, st.Detail)
	}
	return strings.Join(parts, "; ")
}

func stripFilePrefix(p string) string {
	const prefix = "FILE:"
	if len(p) > len(prefix) && p[:len(prefix)] == prefix {
		return p[len(prefix):]
	}
	return p
}
