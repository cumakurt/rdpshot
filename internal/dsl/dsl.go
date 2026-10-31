// Package dsl implements a tiny filter language for querying rdpshot hosts
// and findings.  The syntax is intentionally minimal so analysts can type
// it without consulting documentation.
//
// Grammar (informal):
//
//	query   := term (WS+ term)*
//	term    := field ":" value
//	field   := "nla" | "tls" | "port" | "state" | "creds" | "severity" |
//	           "cve" | "os" | "grade"
//	value   := unquoted token (no whitespace)
//
// Whitespace between terms acts as AND.  There is no OR operator.
//
// Examples:
//
//	nla:false
//	nla:false tls:1.0
//	severity:critical creds:true
//	port:3389 state:open grade:F
//	cve:CVE-2019-0708
package dsl

import (
	"fmt"
	"strings"

	"rdpshot/internal/model"
)

// Filter holds the parsed predicates from a DSL query.
type Filter struct {
	NLA      *bool   // nla:true|false
	TLS      string  // tls:1.0 / 1.1 / 1.2 / 1.3
	Port     uint16  // port:3389
	State    string  // state:open|closed|filtered
	Creds    *bool   // creds:true|false (has verified cred)
	Severity string  // severity:critical|high|medium|low|info
	CVE      string  // cve:CVE-2019-0708
	OS       string  // os:windows (substring match on os_guess)
	Grade    string  // grade:A|B|C|D|F
}

// ParseError describes a syntax problem.
type ParseError struct {
	Token   string
	Message string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("dsl: near %q: %s", e.Token, e.Message)
}

// Parse converts a DSL query string into a Filter.
// An empty or whitespace-only query returns an empty Filter (matches everything).
func Parse(query string) (Filter, error) {
	var f Filter
	tokens := tokenise(query)
	for _, tok := range tokens {
		parts := strings.SplitN(tok, ":", 2)
		if len(parts) != 2 {
			return Filter{}, &ParseError{Token: tok, Message: "expected field:value syntax"}
		}
		field := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])
		if value == "" {
			return Filter{}, &ParseError{Token: tok, Message: "empty value"}
		}
		if err := applyToken(&f, field, value); err != nil {
			return Filter{}, err
		}
	}
	return f, nil
}

func applyToken(f *Filter, field, value string) error {
	switch field {
	case "nla":
		b, err := parseBool(value, field)
		if err != nil {
			return err
		}
		f.NLA = &b

	case "tls":
		// Accept "1.0", "1.1", "1.2", "1.3", or full "TLS 1.2"
		v := normaliseTLS(value)
		if v == "" {
			return &ParseError{Token: field + ":" + value, Message: "unknown TLS version (use 1.0/1.1/1.2/1.3)"}
		}
		f.TLS = v

	case "port":
		p, err := parsePort(value)
		if err != nil {
			return err
		}
		f.Port = p

	case "state":
		s := strings.ToLower(value)
		if s != "open" && s != "closed" && s != "filtered" {
			return &ParseError{Token: field + ":" + value, Message: "state must be open, closed, or filtered"}
		}
		f.State = s

	case "creds":
		b, err := parseBool(value, field)
		if err != nil {
			return err
		}
		f.Creds = &b

	case "severity":
		s := model.Severity(strings.ToLower(value))
		if !s.Valid() {
			return &ParseError{Token: field + ":" + value, Message: "severity must be critical, high, medium, low, or info"}
		}
		f.Severity = string(s)

	case "cve":
		f.CVE = strings.ToUpper(value)

	case "os":
		f.OS = strings.ToLower(value)

	case "grade":
		g := strings.ToUpper(value)
		if g != "A" && g != "B" && g != "C" && g != "D" && g != "F" {
			return &ParseError{Token: field + ":" + value, Message: "grade must be A, B, C, D, or F"}
		}
		f.Grade = g

	default:
		return &ParseError{Token: field + ":" + value, Message: "unknown field (nla, tls, port, state, creds, severity, cve, os, grade)"}
	}
	return nil
}

// HostMatch holds a host together with its best matching severity (derived
// from associated findings), whether it has verified creds, and its grade.
type HostMatch struct {
	model.Host
	MaxSeverity string
	HasCreds    bool
	Grade       string
	CVEs        []string
	OSGuess     string
}

// ApplyToHosts filters a slice of hosts using the parsed DSL Filter.
// findings and credAddrs are indexed by "address:port" key.
func ApplyToHosts(f Filter, hosts []model.Host, findings []model.Finding, credAddrs map[string]bool) []model.Host {
	// Index findings.
	sevByHost := map[string]string{}
	cvesByHost := map[string][]string{}
	for _, fi := range findings {
		k := fi.Address + ":" + portStr(fi.Port)
		if fi.Status != model.FindingVulnerable && fi.Status != model.FindingPotential {
			continue
		}
		if model.Severity(sevByHost[k]).Rank() < fi.Severity.Rank() {
			sevByHost[k] = string(fi.Severity)
		}
		if fi.CVE != "" {
			cvesByHost[k] = appendUniq(cvesByHost[k], strings.ToUpper(fi.CVE))
		}
	}

	var out []model.Host
	for _, h := range hosts {
		k := h.Endpoint.Address + ":" + portStr(h.Endpoint.Port)

		if f.NLA != nil {
			nla := false
			if h.Service != nil {
				nla = h.Service.NLARequired
			}
			if nla != *f.NLA {
				continue
			}
		}

		if f.TLS != "" {
			got := ""
			if h.Service != nil {
				got = normaliseTLS(h.Service.TLSVersion)
			}
			if got != f.TLS {
				continue
			}
		}

		if f.Port != 0 && h.Endpoint.Port != f.Port {
			continue
		}

		if f.State != "" && h.State != f.State {
			continue
		}

		if f.Creds != nil {
			has := credAddrs[k]
			if has != *f.Creds {
				continue
			}
		}

		if f.Severity != "" {
			if sevByHost[k] != f.Severity {
				continue
			}
		}

		if f.CVE != "" {
			found := false
			for _, cve := range cvesByHost[k] {
				if cve == f.CVE {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		if f.OS != "" {
			osGuess := ""
			if h.Service != nil {
				osGuess = strings.ToLower(h.Service.OSGuess)
			}
			if !strings.Contains(osGuess, f.OS) {
				continue
			}
		}

		// Grade is not computed here (requires score package); include if unset.
		// The frontend can post-filter by grade after receiving results.

		out = append(out, h)
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func tokenise(query string) []string {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil
	}
	return strings.Fields(query)
}

func parseBool(value, field string) (bool, error) {
	switch strings.ToLower(value) {
	case "true", "yes", "1":
		return true, nil
	case "false", "no", "0":
		return false, nil
	}
	return false, &ParseError{Token: field + ":" + value, Message: "expected true or false"}
}

func parsePort(value string) (uint16, error) {
	var n int
	for _, c := range value {
		if c < '0' || c > '9' {
			return 0, &ParseError{Token: "port:" + value, Message: "port must be a number"}
		}
		n = n*10 + int(c-'0')
		if n > 65535 {
			return 0, &ParseError{Token: "port:" + value, Message: "port out of range"}
		}
	}
	return uint16(n), nil
}

func normaliseTLS(v string) string {
	v = strings.ToUpper(strings.TrimSpace(v))
	// Handle "TLS 1.2" or "1.2" formats.
	v = strings.TrimPrefix(v, "TLS ")
	v = strings.TrimPrefix(v, "TLS")
	v = strings.TrimSpace(v)
	switch v {
	case "1.0":
		return "TLS 1.0"
	case "1.1":
		return "TLS 1.1"
	case "1.2":
		return "TLS 1.2"
	case "1.3":
		return "TLS 1.3"
	}
	// Also accept the already-normalised form.
	switch v {
	case "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3":
		return v
	}
	return ""
}

func portStr(p uint16) string {
	if p == 0 {
		return "0"
	}
	var b [5]byte
	i := len(b)
	for p > 0 {
		i--
		b[i] = byte('0' + p%10)
		p /= 10
	}
	return string(b[i:])
}

func appendUniq(ss []string, s string) []string {
	for _, x := range ss {
		if x == s {
			return ss
		}
	}
	return append(ss, s)
}
