// Package credssp implements the CredSSP (MS-CSSP) client used for RDP
// network level authentication: the TSRequest ASN.1 framing, the minimal
// SPNEGO wrapping of NTLM tokens, and the handshake state machine.
package credssp

import (
	"encoding/asn1"
	"fmt"
)

// TSRequest is the CredSSP PDU (MS-CSSP 2.2.1.1):
//
//	TSRequest ::= SEQUENCE {
//	    version    [0] INTEGER,
//	    negoTokens [1] NegoData OPTIONAL,
//	    authInfo   [2] OCTET STRING OPTIONAL,
//	    pubKeyAuth [3] OCTET STRING OPTIONAL,
//	    errorCode  [4] INTEGER OPTIONAL,
//	    clientNonce[5] OCTET STRING OPTIONAL }
type TSRequest struct {
	// Version is the CredSSP protocol version (2..6).
	Version int
	// NegoTokens holds SPNEGO-wrapped NTLM tokens (MS-CSSP 2.2.1.1 NegoData).
	NegoTokens [][]byte
	// AuthInfo carries the sealed TSCredentials during the final exchange
	// (MS-CSSP 2.2.1.2). It is not used during the NTLM phase.
	AuthInfo []byte
	// PubKeyAuth carries the sealed public key binding (MS-CSSP 2.2.2.2).
	PubKeyAuth []byte
	// ErrorCode carries an NTSTATUS failure reported by the server.
	ErrorCode *uint32
	// ClientNonce carries the 32-byte hash-binding nonce (CredSSP >= 5).
	// The field name follows the specification; both peers use it.
	ClientNonce []byte
}

// negoDataItem is NegoData ::= SEQUENCE OF SEQUENCE { negoToken [0] OCTET STRING }.
type negoDataItem struct {
	NegoToken []byte
}

// Marshal encodes the TSRequest as DER.
func (r TSRequest) Marshal() ([]byte, error) {
	if r.Version < 0 {
		return nil, fmt.Errorf("credssp: negative version %d", r.Version)
	}
	fields := make([]byte, 0, 64)

	version, err := asn1.Marshal(r.Version)
	if err != nil {
		return nil, fmt.Errorf("credssp: marshal version: %w", err)
	}
	fields = append(fields, derExplicit(0, version)...)

	if r.NegoTokens != nil {
		var items []byte
		for _, token := range r.NegoTokens {
			octet, err := asn1.Marshal(token)
			if err != nil {
				return nil, fmt.Errorf("credssp: marshal negoToken: %w", err)
			}
			item := asn1.RawValue{
				Class:      asn1.ClassUniversal,
				Tag:        asn1.TagSequence,
				IsCompound: true,
				Bytes:      derExplicit(0, octet),
			}
			itemDER, err := asn1.Marshal(item)
			if err != nil {
				return nil, fmt.Errorf("credssp: marshal negoData item: %w", err)
			}
			items = append(items, itemDER...)
		}
		list := asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSequence,
			IsCompound: true,
			Bytes:      items,
		}
		listDER, err := asn1.Marshal(list)
		if err != nil {
			return nil, fmt.Errorf("credssp: marshal negoData: %w", err)
		}
		fields = append(fields, derExplicit(1, listDER)...)
	}

	for _, f := range []struct {
		tag   int
		value []byte
	}{
		{2, r.AuthInfo},
		{3, r.PubKeyAuth},
		{5, r.ClientNonce},
	} {
		if f.value == nil {
			continue
		}
		octet, err := asn1.Marshal(f.value)
		if err != nil {
			return nil, fmt.Errorf("credssp: marshal field %d: %w", f.tag, err)
		}
		fields = append(fields, derExplicit(f.tag, octet)...)
	}

	if r.ErrorCode != nil {
		code, err := asn1.Marshal(int64(*r.ErrorCode))
		if err != nil {
			return nil, fmt.Errorf("credssp: marshal errorCode: %w", err)
		}
		fields = append(fields, derExplicit(4, code)...)
	}

	top := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      fields,
	}
	out, err := asn1.Marshal(top)
	if err != nil {
		return nil, fmt.Errorf("credssp: marshal TSRequest: %w", err)
	}
	return out, nil
}

// ParseTSRequest decodes one DER TSRequest. Unknown context tags are skipped
// for forward compatibility; malformed input returns an error and never
// panics.
func ParseTSRequest(b []byte) (*TSRequest, error) {
	var top asn1.RawValue
	rest, err := asn1.Unmarshal(b, &top)
	if err != nil {
		return nil, fmt.Errorf("credssp: parse TSRequest: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("credssp: %d trailing bytes after TSRequest", len(rest))
	}
	if top.Class != asn1.ClassUniversal || top.Tag != asn1.TagSequence || !top.IsCompound {
		return nil, fmt.Errorf("credssp: TSRequest is not a DER SEQUENCE")
	}

	r := &TSRequest{Version: -1}
	seen := map[int]bool{}
	inner := top.Bytes
	for len(inner) > 0 {
		var field asn1.RawValue
		inner, err = asn1.Unmarshal(inner, &field)
		if err != nil {
			return nil, fmt.Errorf("credssp: parse TSRequest field: %w", err)
		}
		if field.Class != asn1.ClassContextSpecific {
			return nil, fmt.Errorf("credssp: unexpected universal field with tag %d", field.Tag)
		}
		if seen[field.Tag] && field.Tag <= 5 {
			return nil, fmt.Errorf("credssp: duplicate TSRequest field [%d]", field.Tag)
		}
		seen[field.Tag] = true

		switch field.Tag {
		case 0:
			var version int64
			if err := decodeInner(field, &version); err != nil {
				return nil, fmt.Errorf("credssp: version: %w", err)
			}
			if version < 0 || version > 0x7FFFFFFF {
				return nil, fmt.Errorf("credssp: version %d out of range", version)
			}
			r.Version = int(version)
		case 1:
			tokens, err := parseNegoData(field.Bytes)
			if err != nil {
				return nil, err
			}
			r.NegoTokens = tokens
		case 2:
			if err := decodeInner(field, &r.AuthInfo); err != nil {
				return nil, fmt.Errorf("credssp: authInfo: %w", err)
			}
		case 3:
			if err := decodeInner(field, &r.PubKeyAuth); err != nil {
				return nil, fmt.Errorf("credssp: pubKeyAuth: %w", err)
			}
		case 4:
			var code int64
			if err := decodeInner(field, &code); err != nil {
				return nil, fmt.Errorf("credssp: errorCode: %w", err)
			}
			// NTSTATUS values are 32-bit; accept both signed and unsigned
			// INTEGER encodings of the same bit pattern.
			if code < -0x80000000 || code > 0xFFFFFFFF {
				return nil, fmt.Errorf("credssp: errorCode %d out of range", code)
			}
			value := uint32(code)
			r.ErrorCode = &value
		case 5:
			if err := decodeInner(field, &r.ClientNonce); err != nil {
				return nil, fmt.Errorf("credssp: clientNonce: %w", err)
			}
		default:
			// Extension fields ("...") are tolerated and ignored.
		}
	}
	if r.Version < 0 {
		return nil, fmt.Errorf("credssp: TSRequest without version")
	}
	return r, nil
}

// parseNegoData decodes NegoData ::= SEQUENCE OF SEQUENCE { negoToken [0]
// OCTET STRING } from the content bytes of the [1] field.
func parseNegoData(content []byte) ([][]byte, error) {
	var list asn1.RawValue
	rest, err := asn1.Unmarshal(content, &list)
	if err != nil {
		return nil, fmt.Errorf("credssp: parse NegoData: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("credssp: trailing bytes after NegoData")
	}
	if list.Class != asn1.ClassUniversal || list.Tag != asn1.TagSequence || !list.IsCompound {
		return nil, fmt.Errorf("credssp: NegoData is not a DER SEQUENCE")
	}
	var tokens [][]byte
	inner := list.Bytes
	for len(inner) > 0 {
		var item asn1.RawValue
		inner, err = asn1.Unmarshal(inner, &item)
		if err != nil {
			return nil, fmt.Errorf("credssp: parse NegoData item: %w", err)
		}
		if item.Class != asn1.ClassUniversal || item.Tag != asn1.TagSequence || !item.IsCompound {
			return nil, fmt.Errorf("credssp: NegoData item is not a DER SEQUENCE")
		}
		token, err := parseNegoToken(item.Bytes)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, token)
	}
	return tokens, nil
}

// parseNegoToken decodes SEQUENCE { negoToken [0] OCTET STRING } content.
func parseNegoToken(content []byte) ([]byte, error) {
	var field asn1.RawValue
	rest, err := asn1.Unmarshal(content, &field)
	if err != nil {
		return nil, fmt.Errorf("credssp: parse negoToken: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("credssp: trailing bytes after negoToken")
	}
	if field.Class != asn1.ClassContextSpecific || field.Tag != 0 {
		return nil, fmt.Errorf("credssp: negoToken field tag [%d], want [0]", field.Tag)
	}
	var token []byte
	if err := decodeInner(field, &token); err != nil {
		return nil, fmt.Errorf("credssp: negoToken: %w", err)
	}
	return token, nil
}

// decodeInner decodes the payload of an EXPLICIT context-tagged field into out.
func decodeInner(field asn1.RawValue, out any) error {
	rest, err := asn1.Unmarshal(field.Bytes, out)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return fmt.Errorf("credssp: trailing bytes in field [%d]", field.Tag)
	}
	return nil
}

// derExplicit wraps inner DER in an EXPLICIT context-specific tag [tag].
// It builds the TLV directly because it cannot fail: the caller controls the
// tag (0..5) and the inner DER is already validated by encoding/asn1.
func derExplicit(tag int, inner []byte) []byte {
	out := make([]byte, 0, len(inner)+6)
	out = append(out, byte(0xa0|tag))
	out = append(out, derLength(len(inner))...)
	return append(out, inner...)
}

// derLength encodes a DER length in short or long definite form.
func derLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var tmp [8]byte
	i := 0
	for v := n; v > 0; v >>= 8 {
		tmp[i] = byte(v)
		i++
	}
	out := make([]byte, 0, i+1)
	out = append(out, byte(0x80|i))
	for j := i - 1; j >= 0; j-- {
		out = append(out, tmp[j])
	}
	return out
}
