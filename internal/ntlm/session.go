package ntlm

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"
)

// SignatureLen is the size of the NTLMSSP_MESSAGE_SIGNATURE structure:
// version(4) + checksum(8) + seqNum(4) (MS-NLMP 2.2.2.3).
const SignatureLen = 16

// signatureVersion is the only defined NTLMSSP_MESSAGE_SIGNATURE version.
const signatureVersion uint32 = 0x00000001

// Magic constants for the signing/sealing key derivation (MS-NLMP 3.4.4).
var (
	magicClientSigning = []byte("session key to client-to-server signing key magic constant\x00")
	magicClientSealing = []byte("session key to client-to-server sealing key magic constant\x00")
	magicServerSigning = []byte("session key to server-to-client signing key magic constant\x00")
	magicServerSealing = []byte("session key to server-to-client sealing key magic constant\x00")
)

// SessionSecurity implements the RC4-HMAC signing and sealing of
// MS-NLMP 3.4 for one NTLM session, used by CredSSP to protect the
// AUTHENTICATE message and the public key binding.
//
// Sealing layout: the 16-byte signature block is prepended to the plaintext
// and the whole buffer is encrypted with the per-direction RC4 handle keyed
// by the derived sealing key. The checksum inside the signature block is
// therefore transmitted XORed with the RC4 keystream, as required by
// MS-NLMP 3.4.1.1.
//
// The RC4 handle is persistent per direction (send/recv), matching the
// MS-NLMP handle semantics: both peers must seal and unseal in lockstep.
type SessionSecurity struct {
	sendSignKey []byte
	recvSignKey []byte
	sendSeal    *rc4
	recvSeal    *rc4
	sendSeq     uint32
	recvSeq     uint32
}

// NewSessionSecurity derives the per-direction signing and sealing keys from
// the exported session key. When client is true the send direction is
// client-to-server; a server session passes false and the directions swap.
func NewSessionSecurity(sessionBaseKey []byte, negotiateFlags uint32, client bool) *SessionSecurity {
	if len(sessionBaseKey) != 16 {
		panic("ntlm: session base key must be 16 bytes")
	}
	exported := ExportedSessionKey(sessionBaseKey)
	_ = negotiateFlags // NTLMv2 always uses the extended-session-security derivation.
	c2sSign := hmacMD5(exported, magicClientSigning)
	c2sSeal := hmacMD5(exported, magicClientSealing)
	s2cSign := hmacMD5(exported, magicServerSigning)
	s2cSeal := hmacMD5(exported, magicServerSealing)
	s := &SessionSecurity{}
	if client {
		s.sendSignKey, s.recvSignKey = c2sSign, s2cSign
		s.sendSeal, s.recvSeal = newRC4(c2sSeal), newRC4(s2cSeal)
	} else {
		s.sendSignKey, s.recvSignKey = s2cSign, c2sSign
		s.sendSeal, s.recvSeal = newRC4(s2cSeal), newRC4(c2sSeal)
	}
	return s
}

// Seal produces signatureBlock || RC4(plaintext) as one encrypted buffer and
// advances the send sequence number.
func (s *SessionSecurity) Seal(plaintext []byte) []byte {
	sig := buildSignature(s.sendSignKey, plaintext, s.sendSeq)
	s.sendSeq++

	buf := make([]byte, 0, SignatureLen+len(plaintext))
	buf = append(buf, sig...)
	buf = append(buf, plaintext...)
	s.sendSeal.xorKeyStream(buf, buf)
	return buf
}

// Unseal reverses Seal: it decrypts the buffer, verifies the embedded
// signature and returns the plaintext. A tampered or misordered message
// yields an error rather than corrupted output.
func (s *SessionSecurity) Unseal(sealed []byte) ([]byte, error) {
	if len(sealed) < SignatureLen {
		return nil, fmt.Errorf("ntlm: sealed message too short: %d bytes", len(sealed))
	}
	buf := make([]byte, len(sealed))
	s.recvSeal.xorKeyStream(buf, sealed)

	seqNum := binary.LittleEndian.Uint32(buf[12:16])
	if seqNum != s.recvSeq {
		return nil, fmt.Errorf("ntlm: unexpected sequence number %d, want %d", seqNum, s.recvSeq)
	}
	plaintext := buf[SignatureLen:]
	want := buildSignature(s.recvSignKey, plaintext, seqNum)
	if subtle.ConstantTimeCompare(buf[:SignatureLen], want) != 1 {
		return nil, fmt.Errorf("ntlm: signature verification failed")
	}
	s.recvSeq++
	return plaintext, nil
}

// Sign returns the 16-byte signature block for message and advances the send
// sequence number, without encrypting anything.
func (s *SessionSecurity) Sign(message []byte) []byte {
	sig := buildSignature(s.sendSignKey, message, s.sendSeq)
	s.sendSeq++
	return sig
}

// buildSignature computes the NTLMSSP_MESSAGE_SIGNATURE for message at
// sequence number seqNum: version(4) || checksum(8) || seqNum(4), where the
// checksum is the first 8 bytes of
// HMAC_MD5(signingKey, seqNum_LE(4) || message) (MS-NLMP 3.4.1.1).
func buildSignature(signingKey, message []byte, seqNum uint32) []byte {
	seq := make([]byte, 4)
	binary.LittleEndian.PutUint32(seq, seqNum)
	mac := hmacMD5(signingKey, seq, message)

	sig := make([]byte, SignatureLen)
	binary.LittleEndian.PutUint32(sig[0:4], signatureVersion)
	copy(sig[4:12], mac[:8])
	binary.LittleEndian.PutUint32(sig[12:16], seqNum)
	return sig
}
