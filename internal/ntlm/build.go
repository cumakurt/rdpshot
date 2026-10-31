package ntlm

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// rc4Once encrypts plaintext with a fresh RC4 cipher keyed by key (MS-NLMP
// EncryptedRandomSessionKey derivation). RC4 is symmetric, so the same helper
// also recovers the exported session key on the server side.
func rc4Once(key, plaintext []byte) []byte {
	c := newRC4(key)
	out := make([]byte, len(plaintext))
	c.xorKeyStream(out, plaintext)
	return out
}

// UnwrapExportedSessionKey recovers the exported session key from the
// AUTHENTICATE EncryptedRandomSessionKey field (MS-NLMP 3.4.4).
func UnwrapExportedSessionKey(sessionBaseKey, encrypted []byte) []byte {
	return rc4Once(sessionBaseKey, encrypted)
}

// ClientChallengeLen is the size of the client-chosen nonce used in the
// NTLMv2 response (MS-NLMP 2.2.1.3.1).
const ClientChallengeLen = 8

// TimestampLen is the size of the FILETIME timestamp (100ns ticks since
// 1601-01-01) embedded in the NTLMv2 blob.
const TimestampLen = 8

// BuildAuthenticate computes the NTLMv2 challenge response and assembles the
// complete AUTHENTICATE_MESSAGE.
//
// password is required to derive the NT hash; it is used only to compute the
// response material and is never stored on the returned message.
//
// timestamp is the 8-byte FILETIME value placed in the NTLMv2 blob; when the
// server supplied an MsvAvTimestamp AV pair it must be echoed verbatim here.
// clientChallenge is 8 random bytes. targetInfo is the raw AV pair blob from
// the CHALLENGE message, replayed as required by MS-NLMP 2.2.1.3.1.
//
// The returned session base key is HMAC_MD5(NTLMv2Hash, NTProofStr); the
// exported session key equals it when key exchange is not negotiated.
//
// The MIC field is left nil; callers that set MsvAvFlagsMIC in target info
// must call SetMIC after BuildAuthenticate with the raw NEGOTIATE and
// CHALLENGE messages.
func BuildAuthenticate(flags uint32, domain, user, password, workstation string, serverChallenge [8]byte,
	targetInfo, timestamp, clientChallenge []byte) (*AuthenticateMessage, []byte, error) {
	return BuildAuthenticateFromNTHash(flags, domain, user, NTHash(password), workstation,
		serverChallenge, targetInfo, timestamp, clientChallenge)
}

// BuildAuthenticateFromNTHash is the pass-the-hash variant of BuildAuthenticate:
// the caller supplies a 16-byte NT hash instead of a cleartext password.
func BuildAuthenticateFromNTHash(flags uint32, domain, user string, ntHash []byte, workstation string,
	serverChallenge [8]byte, targetInfo, timestamp, clientChallenge []byte) (*AuthenticateMessage, []byte, error) {
	if len(timestamp) != TimestampLen {
		return nil, nil, fmt.Errorf("ntlm: timestamp must be %d bytes, got %d", TimestampLen, len(timestamp))
	}
	if len(clientChallenge) != ClientChallengeLen {
		return nil, nil, fmt.Errorf("ntlm: client challenge must be %d bytes, got %d", ClientChallengeLen, len(clientChallenge))
	}
	if len(ntHash) != NTHashSize {
		return nil, nil, fmt.Errorf("ntlm: NT hash must be %d bytes, got %d", NTHashSize, len(ntHash))
	}

	ntLMv2Hash := NTLMv2Hash(user, domain, ntHash)
	blob := ntlmBlob(timestamp, clientChallenge, targetInfo)
	proof := ntProofStr(ntLMv2Hash, serverChallenge[:], blob)

	ntResponse := make([]byte, 0, len(proof)+len(blob))
	ntResponse = append(ntResponse, proof...)
	ntResponse = append(ntResponse, blob...)

	baseKey := sessionBaseKey(ntLMv2Hash, proof)
	exported := baseKey
	var encKey []byte
	if flags&NEGOTIATE_KEY_EXCH != 0 {
		// MS-NLMP 3.4.4: client picks a random exported session key and
		// encrypts it with RC4 keyed by the session base key.
		exported = make([]byte, 16)
		if _, err := rand.Read(exported); err != nil {
			return nil, nil, fmt.Errorf("ntlm: generate exported session key: %w", err)
		}
		encKey = rc4Once(baseKey, exported)
	}

	msg := &AuthenticateMessage{
		Flags:                     flags,
		Domain:                    domain,
		User:                      user,
		Workstation:               workstation,
		NTChallengeResponse:       ntResponse,
		LMChallengeResponse:       LMv2Response(clientChallenge, serverChallenge[:], ntLMv2Hash),
		EncryptedRandomSessionKey: encKey,
	}
	if flags&NEGOTIATE_VERSION != 0 {
		msg.Version = newVersion()
	}
	return msg, exported, nil
}

// SetMIC computes and installs the AUTHENTICATE MIC (MS-NLMP 3.1.5.1.2):
//
//	MIC = HMAC_MD5(ExportedSessionKey, NEGOTIATE || CHALLENGE || AUTHENTICATE)
//
// AUTHENTICATE is serialized with a zeroed 16-byte MIC field for the hash,
// then rewritten with the real MIC. negotiate and challenge must be the raw
// NTLMSSP messages (not SPNEGO wrappers).
func (m *AuthenticateMessage) SetMIC(exportedSessionKey, negotiate, challenge []byte) error {
	if m == nil {
		return fmt.Errorf("ntlm: nil AuthenticateMessage")
	}
	if len(exportedSessionKey) != 16 {
		return fmt.Errorf("ntlm: exported session key must be 16 bytes, got %d", len(exportedSessionKey))
	}
	var zero [16]byte
	m.MIC = &zero
	withZero, err := m.Marshal()
	if err != nil {
		return err
	}
	mic := hmacMD5(exportedSessionKey, negotiate, challenge, withZero)
	var out [16]byte
	copy(out[:], mic)
	m.MIC = &out
	return nil
}

// ntlmBlob builds the NTLMv2 "blob" from the timestamp, client challenge and
// target info (MS-NLMP 2.2.1.3.1):
//
//	RespType(1)=1, HiRespType(1)=1, Reserved1(2)=0, Reserved2(4)=0,
//	Timestamp(8), ChallengeFromClient(8), Reserved3(4)=0,
//	AvPairs (terminated by MsvAvEOL), Reserved4(4)=0
func ntlmBlob(timestamp, clientChallenge, targetInfo []byte) []byte {
	info := targetInfo
	if !endsWithEOL(info) {
		info = append(append([]byte(nil), info...), 0x00, 0x00, 0x00, 0x00)
	}
	blob := make([]byte, 0, 8+TimestampLen+ClientChallengeLen+4+len(info)+4)
	blob = append(blob, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	blob = append(blob, timestamp...)
	blob = append(blob, clientChallenge...)
	blob = append(blob, 0x00, 0x00, 0x00, 0x00)
	blob = append(blob, info...)
	blob = append(blob, 0x00, 0x00, 0x00, 0x00)
	return blob
}

// endsWithEOL reports whether the AV pair list already carries the 4-byte
// MsvAvEOL terminator.
func endsWithEOL(info []byte) bool {
	if len(info) < AVPairLen {
		return false
	}
	tail := info[len(info)-AVPairLen:]
	return tail[0] == 0 && tail[1] == 0 && tail[2] == 0 && tail[3] == 0
}

// ntProofStr computes NTProofStr =
// HMAC_MD5(NTLMv2Hash, serverChallenge || blob) (MS-NLMP 3.3).
func ntProofStr(ntLMv2Hash []byte, serverChallenge, blob []byte) []byte {
	return hmacMD5(ntLMv2Hash, serverChallenge, blob)
}

// sessionBaseKey computes HMAC_MD5(NTLMv2Hash, NTProofStr) (MS-NLMP 3.3).
func sessionBaseKey(ntLMv2Hash, proof []byte) []byte {
	return hmacMD5(ntLMv2Hash, proof)
}

// newVersion returns the NTLM version structure reported by the client:
// Windows 10 build 19041 (10.0), NTLM current revision 15.
func newVersion() *[8]byte {
	v := [8]byte{0x0A, 0x00, 0x61, 0x4A, 0x00, 0x00, 0x00, 0x0F}
	return &v
}

// filetimeFromUnix returns a FILETIME value for a Unix timestamp in seconds.
// It backs the deterministic timestamps used by the tests.
func filetimeFromUnix(sec int64) []byte {
	const ticksPerSecond = 10000000
	const epochDiff = 11644473600
	ft := make([]byte, 8)
	binary.LittleEndian.PutUint64(ft, uint64(sec+epochDiff)*ticksPerSecond)
	return ft
}
