package credssp

import (
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// Credential types for TSCredentials.credType (MS-CSSP 2.2.1.2).
const (
	CredTypePassword    = 1
	CredTypeSmartCard   = 2
	CredTypeRemoteGuard = 6
)

// TSPasswordCreds is the password credential structure (MS-CSSP 2.2.1.2.1).
// Domain, User and Password are UTF-16LE without a trailing NUL (the wire
// OCTET STRING carries the raw UTF-16LE bytes).
type TSPasswordCreds struct {
	Domain   string
	User     string
	Password string
}

// Marshal encodes TSPasswordCreds as DER.
func (c TSPasswordCreds) Marshal() ([]byte, error) {
	fields := make([]byte, 0, 64)
	for i, s := range []string{c.Domain, c.User, c.Password} {
		octet, err := asn1.Marshal(utf16LE(s))
		if err != nil {
			return nil, fmt.Errorf("credssp: marshal password cred field %d: %w", i, err)
		}
		fields = append(fields, derExplicit(i, octet)...)
	}
	seq := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      fields,
	}
	return asn1.Marshal(seq)
}

// TSCredentials wraps a credential blob for CredSSP authInfo (MS-CSSP 2.2.1.2).
type TSCredentials struct {
	CredType    int
	Credentials []byte // DER of TSPasswordCreds / smartcard / …
}

// Marshal encodes TSCredentials as DER.
func (c TSCredentials) Marshal() ([]byte, error) {
	if c.CredType <= 0 {
		c.CredType = CredTypePassword
	}
	typeDER, err := asn1.Marshal(c.CredType)
	if err != nil {
		return nil, fmt.Errorf("credssp: marshal credType: %w", err)
	}
	credDER, err := asn1.Marshal(c.Credentials)
	if err != nil {
		return nil, fmt.Errorf("credssp: marshal credentials: %w", err)
	}
	fields := append(derExplicit(0, typeDER), derExplicit(1, credDER)...)
	seq := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      fields,
	}
	return asn1.Marshal(seq)
}

// BuildPasswordCredentials returns the DER-encoded TSCredentials for a
// password logon suitable for sealing into TSRequest.authInfo.
func BuildPasswordCredentials(domain, user, password string) ([]byte, error) {
	inner, err := (TSPasswordCreds{Domain: domain, User: user, Password: password}).Marshal()
	if err != nil {
		return nil, err
	}
	return (TSCredentials{CredType: CredTypePassword, Credentials: inner}).Marshal()
}

// utf16LE encodes s as little-endian UTF-16 without a trailing NUL.
func utf16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, 2*len(u))
	for i, r := range u {
		binary.LittleEndian.PutUint16(out[i*2:], r)
	}
	return out
}
