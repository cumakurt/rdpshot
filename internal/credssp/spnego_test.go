package credssp

import (
	"bytes"
	"encoding/asn1"
	"testing"
)

func TestWrapUnwrapNegTokenInit(t *testing.T) {
	token := []byte("NTLMSSP\x00fake-negotiate")
	wrapped, err := WrapNegTokenInit(token)
	if err != nil {
		t.Fatal(err)
	}
	// Windows CredSSP expects the GSS-API Application 0 wrapper around
	// the RFC 4178 NegTokenInit ([0] EXPLICIT SEQUENCE).
	if wrapped[0] != 0x60 {
		t.Fatalf("NegTokenInit must start with GSS APPLICATION 0, got 0x%02x", wrapped[0])
	}
	got, err := UnwrapSPNEGO(wrapped)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if !bytes.Equal(got, token) {
		t.Fatalf("token = %x, want %x", got, token)
	}
}

func TestWrapUnwrapNegTokenResp(t *testing.T) {
	token := []byte("NTLMSSP\x00fake-authenticate")
	wrapped, err := WrapNegTokenResp(token)
	if err != nil {
		t.Fatal(err)
	}
	if wrapped[0] != 0x60 {
		t.Fatalf("NegTokenResp must start with GSS APPLICATION 0, got 0x%02x", wrapped[0])
	}
	got, err := UnwrapSPNEGO(wrapped)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if !bytes.Equal(got, token) {
		t.Fatalf("token = %x, want %x", got, token)
	}
}

// TestUnwrapSPNEGOGSSWrapper accepts the GSS-API framing produced by SSPI:
// APPLICATION 0 { SPNEGO OID, NegotiationToken }.
func TestUnwrapSPNEGOGSSWrapper(t *testing.T) {
	token := []byte("NTLMSSP\x00inner")
	inner, err := WrapNegTokenInit(token)
	if err != nil {
		t.Fatal(err)
	}
	oid, err := asn1.Marshal(spnegoOID)
	if err != nil {
		t.Fatal(err)
	}
	content := append(append([]byte(nil), oid...), inner...)
	gss := append([]byte{0x60}, derLength(len(content))...)
	gss = append(gss, content...)

	got, err := UnwrapSPNEGO(gss)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if !bytes.Equal(got, token) {
		t.Fatalf("token = %x, want %x", got, token)
	}
}

// TestUnwrapSPNEGOBareNTLM passes an NTLM token through unchanged.
func TestUnwrapSPNEGOBareNTLM(t *testing.T) {
	token := []byte("NTLMSSP\x00raw")
	got, err := UnwrapSPNEGO(token)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, token) {
		t.Fatalf("token = %x, want %x", got, token)
	}
}

func TestUnwrapSPNEGOMalformed(t *testing.T) {
	empty := derExplicit(0, derSequence(nil)) // NegTokenInit with no fields
	cases := map[string][]byte{
		"empty":        {},
		"junk":         {0xff, 0x01, 0x02},
		"not-token":    {0x30, 0x00},
		"no-payload":   empty,
		"wrong-choice": derExplicit(3, derSequence(nil)),
	}
	for name, b := range cases {
		if _, err := UnwrapSPNEGO(b); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

// TestUnwrapSPNEGOEmptyPayload rejects an empty mechToken OCTET STRING.
func TestUnwrapSPNEGOEmptyPayload(t *testing.T) {
	octet, err := asn1.Marshal([]byte{})
	if err != nil {
		t.Fatal(err)
	}
	init := derExplicit(0, derSequence(derExplicit(2, octet)))
	if _, err := UnwrapSPNEGO(init); err == nil {
		t.Fatal("empty mechToken must be rejected")
	}
}
