package ntlm

import (
	"encoding/binary"
	"fmt"
)

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
// The MIC field is left nil: computing it requires the raw NEGOTIATE and
// CHALLENGE bytes and the CredSSP profile used by RDP does not request
// message integrity (MsvAvFlags bit 0x2 is not set by RDP servers).
func BuildAuthenticate(flags uint32, domain, user, password, workstation string, serverChallenge [8]byte,
	targetInfo, timestamp, clientChallenge []byte) (*AuthenticateMessage, []byte, error) {
	if len(timestamp) != TimestampLen {
		return nil, nil, fmt.Errorf("ntlm: timestamp must be %d bytes, got %d", TimestampLen, len(timestamp))
	}
	if len(clientChallenge) != ClientChallengeLen {
		return nil, nil, fmt.Errorf("ntlm: client challenge must be %d bytes, got %d", ClientChallengeLen, len(clientChallenge))
	}

	ntLMv2Hash := NTLMv2Hash(user, domain, NTHash(password))
	blob := ntlmBlob(timestamp, clientChallenge, targetInfo)
	proof := ntProofStr(ntLMv2Hash, serverChallenge[:], blob)

	ntResponse := make([]byte, 0, len(proof)+len(blob))
	ntResponse = append(ntResponse, proof...)
	ntResponse = append(ntResponse, blob...)

	msg := &AuthenticateMessage{
		Flags:                     flags,
		Domain:                    domain,
		User:                      user,
		Workstation:               workstation,
		NTChallengeResponse:       ntResponse,
		LMChallengeResponse:       LMv2Response(clientChallenge, serverChallenge[:], ntLMv2Hash),
		EncryptedRandomSessionKey: nil,
	}
	if flags&NEGOTIATE_VERSION != 0 {
		msg.Version = newVersion()
	}
	return msg, sessionBaseKey(ntLMv2Hash, proof), nil
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
