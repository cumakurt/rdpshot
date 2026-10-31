package credssp

import (
	"encoding/asn1"
	"fmt"
)

// ntlmMechOID is the NTLM SSP mechanism identifier 1.3.6.1.4.1.311.2.2.10
// (MS-SPNG appendix; RFC 4178 MechType).
var ntlmMechOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}

// kerberosMechOID is the Kerberos V5 mechanism 1.2.840.113554.1.2.2.
var kerberosMechOID = asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}

// spnegoOID is the GSS-API security mechanism OID 1.3.6.1.5.5.2 that frames
// SPNEGO tokens produced by SSPI (RFC 2743 wrapper).
var spnegoOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 2}

// OfferKerberos, when true, advertises Kerberos ahead of NTLM in NegTokenInit.
// The initial mechToken remains NTLM until a full AP-REQ builder is available.
var OfferKerberos bool

// WrapNegTokenInit wraps a raw NTLM token in a SPNEGO NegTokenInit
// (RFC 4178) advertising the NTLM mechanism, then frames it with the
// GSS-API Application 0 wrapper that Windows CredSSP/SSPI expects:
//
//	APPLICATION 0 { OID 1.3.6.1.5.5.2, [0] NegTokenInit }
//
//	[0] NegTokenInit ::= SEQUENCE {
//	    mechTypes [0] MechTypeList,
//	    mechToken [2] OCTET STRING }
func WrapNegTokenInit(ntlmToken []byte) ([]byte, error) {
	mechs := []asn1.ObjectIdentifier{ntlmMechOID}
	if OfferKerberos {
		mechs = []asn1.ObjectIdentifier{kerberosMechOID, ntlmMechOID}
	}
	mechTypes, err := asn1.Marshal(mechs)
	if err != nil {
		return nil, fmt.Errorf("credssp: marshal mechTypes: %w", err)
	}
	mechToken, err := asn1.Marshal(ntlmToken)
	if err != nil {
		return nil, fmt.Errorf("credssp: marshal mechToken: %w", err)
	}
	fields := append(derExplicit(0, mechTypes), derExplicit(2, mechToken)...)
	return wrapGSS(wrapChoice(0, fields))
}

// WrapNegTokenResp wraps a raw NTLM token in a SPNEGO NegTokenResp
// (RFC 4178) carrying only the responseToken, then frames it with the
// GSS-API Application 0 wrapper used by Windows CredSSP/SSPI.
//
//	[1] NegTokenResp ::= SEQUENCE { responseToken [2] OCTET STRING }
func WrapNegTokenResp(ntlmToken []byte) ([]byte, error) {
	mechToken, err := asn1.Marshal(ntlmToken)
	if err != nil {
		return nil, fmt.Errorf("credssp: marshal responseToken: %w", err)
	}
	return wrapGSS(wrapChoice(1, derExplicit(2, mechToken)))
}

// wrapGSS frames a NegotiationToken as APPLICATION 0 { SPNEGO OID, token }
// (RFC 2743 / MS-SPNG). Windows CredSSP rejects bare NegTokenInit on some
// builds with a TLS internal_error alert during the first TSRequest.
func wrapGSS(negotiationToken []byte) ([]byte, error) {
	oid, err := asn1.Marshal(spnegoOID)
	if err != nil {
		return nil, fmt.Errorf("credssp: marshal SPNEGO OID: %w", err)
	}
	content := append(append([]byte(nil), oid...), negotiationToken...)
	out := make([]byte, 0, 1+len(derLength(len(content)))+len(content))
	out = append(out, 0x60) // APPLICATION 0, constructed
	out = append(out, derLength(len(content))...)
	return append(out, content...), nil
}

// wrapChoice encodes a NegotiationToken CHOICE member as [tag] EXPLICIT
// SEQUENCE { fields... }. It builds the DER directly and cannot fail.
func wrapChoice(tag int, fields []byte) []byte {
	return derExplicit(tag, derSequence(fields))
}

// derSequence encodes content as a DER SEQUENCE.
func derSequence(content []byte) []byte {
	out := make([]byte, 0, len(content)+6)
	out = append(out, 0x30)
	out = append(out, derLength(len(content))...)
	return append(out, content...)
}

// UnwrapSPNEGO extracts the inner NTLM token from a SPNEGO NegotiationToken.
// It accepts NegTokenInit, NegTokenResp, the GSS-API wrapper used by SSPI,
// and a bare NTLM token passed through unchanged.
func UnwrapSPNEGO(b []byte) ([]byte, error) {
	if len(b) >= 8 && string(b[:8]) == "NTLMSSP\x00" {
		return b, nil
	}
	var top asn1.RawValue
	rest, err := asn1.Unmarshal(b, &top)
	if err != nil {
		return nil, fmt.Errorf("credssp: parse SPNEGO token: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("credssp: %d trailing bytes after SPNEGO token", len(rest))
	}
	return unwrapToken(top)
}

// unwrapToken unwraps one decoded DER value as a NegotiationToken or
// GSS-API wrapper.
func unwrapToken(top asn1.RawValue) ([]byte, error) {
	// GSS-API wrapper: APPLICATION 0 { OID, inner NegotiationToken }.
	if top.Class == asn1.ClassApplication && top.Tag == 0 && top.IsCompound {
		return unwrapGSS(top.Bytes)
	}
	if top.Class != asn1.ClassContextSpecific || !top.IsCompound || (top.Tag != 0 && top.Tag != 1) {
		return nil, fmt.Errorf("credssp: not a SPNEGO NegotiationToken")
	}
	seq, err := parseTokenSequence(top.Bytes)
	if err != nil {
		return nil, err
	}
	inner := seq.Bytes
	for len(inner) > 0 {
		var field asn1.RawValue
		inner, err = asn1.Unmarshal(inner, &field)
		if err != nil {
			return nil, fmt.Errorf("credssp: parse NegToken field: %w", err)
		}
		if field.Class != asn1.ClassContextSpecific {
			continue
		}
		// NegTokenInit mechToken and NegTokenResp responseToken both use [2].
		if field.Tag != 2 {
			continue
		}
		var token []byte
		if err := decodeInner(field, &token); err != nil {
			return nil, fmt.Errorf("credssp: SPNEGO token payload: %w", err)
		}
		if len(token) == 0 {
			return nil, fmt.Errorf("credssp: empty SPNEGO token payload")
		}
		return token, nil
	}
	return nil, fmt.Errorf("credssp: SPNEGO token carries no NTLM payload")
}

// unwrapGSS handles the SSPI GSS-API framing: APPLICATION 0 { mechOID,
// NegotiationToken }.
func unwrapGSS(content []byte) ([]byte, error) {
	var oid asn1.RawValue
	rest, err := asn1.Unmarshal(content, &oid)
	if err != nil {
		return nil, fmt.Errorf("credssp: parse GSS mechanism OID: %w", err)
	}
	if oid.Class != asn1.ClassUniversal || oid.Tag != asn1.TagOID {
		return nil, fmt.Errorf("credssp: GSS wrapper without mechanism OID")
	}
	var mech asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(oid.FullBytes, &mech); err != nil {
		return nil, fmt.Errorf("credssp: parse GSS mechanism OID: %w", err)
	}
	if !mech.Equal(spnegoOID) {
		return nil, fmt.Errorf("credssp: GSS wrapper mechanism %s is not SPNEGO", mech)
	}
	var inner asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &inner)
	if err != nil {
		return nil, fmt.Errorf("credssp: parse GSS inner token: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("credssp: trailing bytes in GSS wrapper")
	}
	return unwrapToken(inner)
}

// parseTokenSequence decodes the SEQUENCE payload of a NegTokenInit or
// NegTokenResp.
func parseTokenSequence(content []byte) (asn1.RawValue, error) {
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(content, &seq)
	if err != nil {
		return seq, fmt.Errorf("credssp: parse NegToken SEQUENCE: %w", err)
	}
	if len(rest) != 0 {
		return seq, fmt.Errorf("credssp: trailing bytes after NegToken SEQUENCE")
	}
	if seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence || !seq.IsCompound {
		return seq, fmt.Errorf("credssp: NegToken payload is not a DER SEQUENCE")
	}
	return seq, nil
}
