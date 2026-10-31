package ntlm

import (
	"crypto/md5"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
)

// SignatureLen is the size of the NTLMSSP_MESSAGE_SIGNATURE structure:
// version(4) + checksum(8) + seqNum(4) (MS-NLMP 2.2.2.3).
const SignatureLen = 16

// signatureVersion is the only defined NTLMSSP_MESSAGE_SIGNATURE version.
const signatureVersion uint32 = 0x00000001

// Magic constants for the signing/sealing key derivation (MS-NLMP 3.4.5.2).
// Each trailing NUL is part of the MD5 input.
var (
	magicClientSigning = []byte("session key to client-to-server signing key magic constant\x00")
	magicClientSealing = []byte("session key to client-to-server sealing key magic constant\x00")
	magicServerSigning = []byte("session key to server-to-client signing key magic constant\x00")
	magicServerSealing = []byte("session key to server-to-client sealing key magic constant\x00")
)

// SessionSecurity implements the RC4-HMAC signing and sealing of
// MS-NLMP 3.4 for one NTLM session, used by CredSSP to protect the
// pubKeyAuth binding and TSCredentials authInfo.
//
// Wire layout for a sealed record (MS-NLMP 3.4.3 / FreeRDP EncryptMessage):
//
//	Version(4 LE, plaintext) || Checksum(8) || SeqNum(4 LE, plaintext) || RC4(message)
//
// With NEGOTIATE_KEY_EXCH the checksum is RC4(HMAC_MD5(...)[0:8]) using the
// same sealing handle after the message ciphertext (MS-NLMP 3.4.4.2).
// Without KEY_EXCH the checksum is the raw HMAC prefix.
//
// The RC4 handle is persistent per direction: peers must seal/unseal in lockstep.
type SessionSecurity struct {
	sendSignKey      []byte
	recvSignKey      []byte
	sendSeal         *rc4
	recvSeal         *rc4
	sendSeq          uint32
	recvSeq          uint32
	encryptChecksum  bool
}

// NewSessionSecurity derives the per-direction signing and sealing keys from
// the exported session key (MS-NLMP 3.4.5.2: MD5(ExportedSessionKey || magic)).
// When client is true the send direction is client-to-server; a server session
// passes false and the directions swap.
//
// negotiateFlags control KEY_EXCH checksum encryption on the wire.
func NewSessionSecurity(exportedSessionKey []byte, negotiateFlags uint32, client bool) *SessionSecurity {
	if len(exportedSessionKey) != 16 {
		panic("ntlm: exported session key must be 16 bytes")
	}
	exported := ExportedSessionKey(exportedSessionKey)
	c2sSign := md5Concat(exported, magicClientSigning)
	c2sSeal := md5Concat(exported, magicClientSealing)
	s2cSign := md5Concat(exported, magicServerSigning)
	s2cSeal := md5Concat(exported, magicServerSealing)
	s := &SessionSecurity{
		encryptChecksum: negotiateFlags&NEGOTIATE_KEY_EXCH != 0,
	}
	if client {
		s.sendSignKey, s.recvSignKey = c2sSign, s2cSign
		s.sendSeal, s.recvSeal = newRC4(c2sSeal), newRC4(s2cSeal)
	} else {
		s.sendSignKey, s.recvSignKey = s2cSign, c2sSign
		s.sendSeal, s.recvSeal = newRC4(s2cSeal), newRC4(c2sSeal)
	}
	return s
}

// md5Concat returns MD5(parts...), used for NTLM key derivation.
func md5Concat(parts ...[]byte) []byte {
	h := md5.New()
	for _, p := range parts {
		_, _ = h.Write(p)
	}
	return h.Sum(nil)
}

// Seal produces Version || Checksum || SeqNum || RC4(plaintext) and advances
// the send sequence number (and the sealing RC4 handle).
func (s *SessionSecurity) Seal(plaintext []byte) []byte {
	seqNum := s.sendSeq
	s.sendSeq++

	sig := make([]byte, SignatureLen)
	binary.LittleEndian.PutUint32(sig[0:4], signatureVersion)
	binary.LittleEndian.PutUint32(sig[12:16], seqNum)

	seq := make([]byte, 4)
	binary.LittleEndian.PutUint32(seq, seqNum)
	mac := hmacMD5(s.sendSignKey, seq, plaintext)

	sealed := make([]byte, len(plaintext))
	s.sendSeal.xorKeyStream(sealed, plaintext)

	checksum := make([]byte, 8)
	copy(checksum, mac[:8])
	if s.encryptChecksum {
		// MS-NLMP 3.4.3 SEAL then MAC: message RC4 first, then checksum RC4.
		s.sendSeal.xorKeyStream(checksum, checksum)
	}
	copy(sig[4:12], checksum)

	out := make([]byte, 0, SignatureLen+len(sealed))
	out = append(out, sig...)
	out = append(out, sealed...)
	return out
}

// Unseal reverses Seal: decrypts the message (and KEY_EXCH checksum), verifies
// the signature, and returns the plaintext.
func (s *SessionSecurity) Unseal(sealed []byte) ([]byte, error) {
	if len(sealed) < SignatureLen {
		return nil, fmt.Errorf("ntlm: sealed message too short: %d bytes", len(sealed))
	}
	sig := sealed[:SignatureLen]
	ciphertext := sealed[SignatureLen:]

	seqNum := binary.LittleEndian.Uint32(sig[12:16])
	if seqNum != s.recvSeq {
		return nil, fmt.Errorf("ntlm: unexpected sequence number %d, want %d", seqNum, s.recvSeq)
	}

	plaintext := make([]byte, len(ciphertext))
	s.recvSeal.xorKeyStream(plaintext, ciphertext)

	gotChecksum := make([]byte, 8)
	copy(gotChecksum, sig[4:12])
	if s.encryptChecksum {
		s.recvSeal.xorKeyStream(gotChecksum, gotChecksum)
	}

	seq := make([]byte, 4)
	binary.LittleEndian.PutUint32(seq, seqNum)
	mac := hmacMD5(s.recvSignKey, seq, plaintext)
	if subtle.ConstantTimeCompare(gotChecksum, mac[:8]) != 1 {
		return nil, fmt.Errorf("ntlm: signature verification failed")
	}
	s.recvSeq++
	return plaintext, nil
}

// Sign returns the 16-byte signature block for message and advances the send
// sequence number. With KEY_EXCH the checksum is RC4-encrypted with the sealing
// handle (MS-NLMP 3.4.4.2), advancing that stream by 8 bytes.
func (s *SessionSecurity) Sign(message []byte) []byte {
	seqNum := s.sendSeq
	s.sendSeq++

	sig := make([]byte, SignatureLen)
	binary.LittleEndian.PutUint32(sig[0:4], signatureVersion)
	binary.LittleEndian.PutUint32(sig[12:16], seqNum)

	seq := make([]byte, 4)
	binary.LittleEndian.PutUint32(seq, seqNum)
	mac := hmacMD5(s.sendSignKey, seq, message)

	checksum := make([]byte, 8)
	copy(checksum, mac[:8])
	if s.encryptChecksum {
		s.sendSeal.xorKeyStream(checksum, checksum)
	}
	copy(sig[4:12], checksum)
	return sig
}
