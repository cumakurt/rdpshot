// Package ntlm implements the minimal subset of NTLMv2 (MS-NLMP) required by
// the CredSSP client in this project: message marshaling, NTLMv2 response
// computation, and RC4-HMAC session security for pubKeyAuth sealing.
//
// Only the connection-oriented NTLMv2 profile used by CredSSP is supported.
// Legacy LM/NTLMv1 responses are intentionally not implemented.
package ntlm

import (
	"crypto/hmac"
	"crypto/md5"
	"fmt"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

// signature is the NTLMSSP message signature ("NTLMSSP\0").
var signature = [8]byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0}

// Message type codes (MS-NLMP 2.2).
const (
	typeNegotiate    uint32 = 0x00000001
	typeChallenge    uint32 = 0x00000002
	typeAuthenticate uint32 = 0x00000003
)

// Negotiate flags (MS-NLMP 2.2.2.5).
const (
	NEGOTIATE_UNICODE                  uint32 = 0x00000001
	NEGOTIATE_OEM                      uint32 = 0x00000002
	REQUEST_TARGET                     uint32 = 0x00000004
	NEGOTIATE_SIGN                     uint32 = 0x00000010
	NEGOTIATE_SEAL                     uint32 = 0x00000020
	NEGOTIATE_DATAGRAM                 uint32 = 0x00000040
	NEGOTIATE_LM_KEY                   uint32 = 0x00000080
	NEGOTIATE_NTLM                     uint32 = 0x00000200
	NEGOTIATE_ANONYMOUS                uint32 = 0x00000800
	NEGOTIATE_OEM_DOMAIN_SUPPLIED      uint32 = 0x00001000
	NEGOTIATE_OEM_WORKSTATION_SUPPLIED uint32 = 0x00002000
	NEGOTIATE_ALWAYS_SIGN              uint32 = 0x00008000
	NEGOTIATE_TARGET_TYPE_DOMAIN       uint32 = 0x00010000
	NEGOTIATE_TARGET_TYPE_SERVER       uint32 = 0x00020000
	NEGOTIATE_EXTENDED_SESSIONSECURITY uint32 = 0x00080000
	NEGOTIATE_IDENTIFY                 uint32 = 0x00100000
	REQUEST_NON_NT_SESSION_KEY         uint32 = 0x00400000
	NEGOTIATE_TARGET_INFO              uint32 = 0x00800000
	NEGOTIATE_VERSION                  uint32 = 0x02000000
	NEGOTIATE_128                      uint32 = 0x20000000
	NEGOTIATE_KEY_EXCH                 uint32 = 0x40000000
	NEGOTIATE_56                       uint32 = 0x80000000
)

// DefaultNegotiateFlags is the flag set offered by the CredSSP client:
// NTLMv2 with extended session security, sealing and 128-bit keys.
const DefaultNegotiateFlags = NEGOTIATE_UNICODE |
	REQUEST_TARGET |
	NEGOTIATE_NTLM |
	NEGOTIATE_ALWAYS_SIGN |
	NEGOTIATE_EXTENDED_SESSIONSECURITY |
	NEGOTIATE_TARGET_INFO |
	NEGOTIATE_VERSION |
	NEGOTIATE_128 |
	NEGOTIATE_SEAL |
	NEGOTIATE_SIGN |
	NEGOTIATE_56

// securityBufferLen is the size of a security buffer descriptor:
// uint16 length, uint16 allocated, uint32 payload offset (MS-NLMP 2.2.1.2).
const securityBufferLen = 8

// NTHash computes the NT hash of a password: MD4(UTF-16LE(password))
// (MS-NLMP 3.3).
func NTHash(password string) []byte {
	h := md4.New()
	h.Write(encodeUTF16LE(password))
	return h.Sum(nil)
}

// NTLMv2Hash derives the NTLMv2 hash:
// HMAC_MD5(ntHash, UTF-16LE(upper(user) + domain)) (MS-NLMP 3.3).
//
// domain is appended verbatim (Windows does not uppercase it), while user is
// uppercased before encoding. ntHash must be the 16-byte NT hash.
func NTLMv2Hash(user, domain string, ntHash []byte) []byte {
	if len(ntHash) != md5.Size {
		// A wrong-size key silently yields a valid-looking but wrong HMAC;
		// fail loudly instead.
		panic("ntlm: NT hash must be 16 bytes")
	}
	return hmacMD5(ntHash, encodeUTF16LE(strings.ToUpper(user)+domain))
}

// LMv2Response computes the LMv2 challenge response (MS-NLMP 3.3):
//
//	HMAC_MD5(ntLMv2Hash, serverChallenge || clientChallenge) || clientChallenge
//
// The third parameter is the NTLMv2 hash used as the HMAC key (LMv2 is keyed
// by the NTLMv2 hash; NTProofStr is an output of the NTLMv2 exchange and is
// not usable as key material here). Challenges must be 8 bytes each.
func LMv2Response(clientChallenge, serverChallenge, ntLMv2Hash []byte) []byte {
	if len(clientChallenge) != 8 || len(serverChallenge) != 8 {
		panic("ntlm: challenges must be 8 bytes")
	}
	if len(ntLMv2Hash) != md5.Size {
		panic("ntlm: NTLMv2 hash must be 16 bytes")
	}
	mac := hmacMD5(ntLMv2Hash, serverChallenge, clientChallenge)
	return append(mac, clientChallenge...)
}

// ExportedSessionKey returns the exported session key for NTLMv2. Without
// key exchange the exported session key is the session base key itself
// (MS-NLMP 3.4.4).
func ExportedSessionKey(sessionBaseKey []byte) []byte {
	out := make([]byte, len(sessionBaseKey))
	copy(out, sessionBaseKey)
	return out
}

// hmacMD5 returns HMAC_MD5(key, parts...).
func hmacMD5(key []byte, parts ...[]byte) []byte {
	mac := hmac.New(md5.New, key)
	for _, p := range parts {
		mac.Write(p)
	}
	return mac.Sum(nil)
}

// encodeUTF16LE encodes s as little-endian UTF-16 (MS-NLMP "Unicode string").
func encodeUTF16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(u)*2)
	for _, c := range u {
		out = append(out, byte(c), byte(c>>8))
	}
	return out
}

// decodeUTF16LE decodes little-endian UTF-16 bytes to a Go string.
func decodeUTF16LE(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", fmt.Errorf("ntlm: UTF-16LE payload has odd length %d", len(b))
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
	}
	return string(utf16.Decode(u)), nil
}
