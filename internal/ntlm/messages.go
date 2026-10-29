package ntlm

import (
	"encoding/binary"
	"fmt"
)

// Message size constants for the fixed headers (MS-NLMP 2.2.1.1 - 2.2.1.3).
const (
	negotiateHeaderLen    = 32
	challengeHeaderLen    = 48
	authenticateHeaderLen = 64
	versionLen            = 8
	micLen                = 16
)

// NegotiateMessage is the NTLM NEGOTIATE_MESSAGE (type 1).
type NegotiateMessage struct {
	Flags       uint32
	Domain      string
	Workstation string
	Version     *[8]byte
}

// Marshal encodes the NEGOTIATE_MESSAGE. The version field is serialized
// whenever the NTLMSSP_NEGOTIATE_VERSION flag is set (zeroed when Version is
// nil) or when Version is set (forcing the flag on), because the field is
// only legal with that flag (MS-NLMP 2.2.1.1).
func (m NegotiateMessage) Marshal() ([]byte, error) {
	flags := m.Flags
	includeVersion := flags&NEGOTIATE_VERSION != 0 || m.Version != nil
	headerLen := negotiateHeaderLen
	if includeVersion {
		flags |= NEGOTIATE_VERSION
		headerLen += versionLen
	}
	domain := encodeString(m.Domain, flags)
	workstation := encodeString(m.Workstation, flags)

	out := make([]byte, headerLen)
	copy(out[0:8], signature[:])
	binary.LittleEndian.PutUint32(out[8:12], typeNegotiate)
	binary.LittleEndian.PutUint32(out[12:16], flags)
	writeSecBuf(out[16:24], len(domain), headerLen)
	writeSecBuf(out[24:32], len(workstation), headerLen+len(domain))
	if includeVersion && m.Version != nil {
		copy(out[negotiateHeaderLen:], m.Version[:])
	}
	out = append(out, domain...)
	out = append(out, workstation...)
	return out, nil
}

// ParseNegotiate decodes a NEGOTIATE_MESSAGE. Malformed input returns an
// error; the parser never panics.
func ParseNegotiate(b []byte) (*NegotiateMessage, error) {
	if err := checkHeader(b, negotiateHeaderLen, typeNegotiate); err != nil {
		return nil, err
	}
	m := &NegotiateMessage{Flags: binary.LittleEndian.Uint32(b[12:16])}
	headerLen := negotiateHeaderLen
	if m.Flags&NEGOTIATE_VERSION != 0 {
		if len(b) < negotiateHeaderLen+versionLen {
			return nil, fmt.Errorf("ntlm: negotiate message truncated before version field")
		}
		var v [8]byte
		copy(v[:], b[negotiateHeaderLen:negotiateHeaderLen+versionLen])
		m.Version = &v
		headerLen += versionLen
	}
	domain, err := readSecBuf(b, 16, headerLen, m.Flags)
	if err != nil {
		return nil, fmt.Errorf("ntlm: negotiate domain: %w", err)
	}
	workstation, err := readSecBuf(b, 24, headerLen, m.Flags)
	if err != nil {
		return nil, fmt.Errorf("ntlm: negotiate workstation: %w", err)
	}
	m.Domain = domain
	m.Workstation = workstation
	return m, nil
}

// ChallengeMessage is the NTLM CHALLENGE_MESSAGE (type 2).
type ChallengeMessage struct {
	Flags           uint32
	ServerChallenge [8]byte
	TargetName      string
	TargetInfo      []byte // raw AV pair bytes as sent by the server
	Version         *[8]byte
}

// Marshal encodes the CHALLENGE_MESSAGE using the same version-field rule as
// NegotiateMessage.Marshal.
func (m ChallengeMessage) Marshal() ([]byte, error) {
	flags := m.Flags
	includeVersion := flags&NEGOTIATE_VERSION != 0 || m.Version != nil
	headerLen := challengeHeaderLen
	if includeVersion {
		flags |= NEGOTIATE_VERSION
		headerLen += versionLen
	}
	targetName := encodeString(m.TargetName, flags)

	out := make([]byte, headerLen)
	copy(out[0:8], signature[:])
	binary.LittleEndian.PutUint32(out[8:12], typeChallenge)
	writeSecBuf(out[12:20], len(targetName), headerLen)
	binary.LittleEndian.PutUint32(out[20:24], flags)
	copy(out[24:32], m.ServerChallenge[:])
	// 32:40 is the reserved field and must be zero.
	writeSecBuf(out[40:48], len(m.TargetInfo), headerLen+len(targetName))
	if includeVersion && m.Version != nil {
		copy(out[challengeHeaderLen:], m.Version[:])
	}
	out = append(out, targetName...)
	out = append(out, m.TargetInfo...)
	return out, nil
}

// ParseChallenge decodes a CHALLENGE_MESSAGE.
func ParseChallenge(b []byte) (*ChallengeMessage, error) {
	if err := checkHeader(b, challengeHeaderLen, typeChallenge); err != nil {
		return nil, err
	}
	m := &ChallengeMessage{Flags: binary.LittleEndian.Uint32(b[20:24])}
	copy(m.ServerChallenge[:], b[24:32])
	headerLen := challengeHeaderLen
	if m.Flags&NEGOTIATE_VERSION != 0 {
		if len(b) < challengeHeaderLen+versionLen {
			return nil, fmt.Errorf("ntlm: challenge message truncated before version field")
		}
		var v [8]byte
		copy(v[:], b[challengeHeaderLen:challengeHeaderLen+versionLen])
		m.Version = &v
		headerLen += versionLen
	}
	targetName, err := readSecBuf(b, 12, headerLen, m.Flags)
	if err != nil {
		return nil, fmt.Errorf("ntlm: challenge target name: %w", err)
	}
	info, err := readSecBufRaw(b, 40, headerLen)
	if err != nil {
		return nil, fmt.Errorf("ntlm: challenge target info: %w", err)
	}
	m.TargetName = targetName
	m.TargetInfo = info
	return m, nil
}

// AuthenticateMessage is the NTLM AUTHENTICATE_MESSAGE (type 3).
type AuthenticateMessage struct {
	Flags       uint32
	Domain      string
	User        string
	Workstation string
	// EncryptedRandomSessionKey is empty unless NEGOTIATE_KEY_EXCH is used.
	EncryptedRandomSessionKey []byte
	// NTChallengeResponse is NTProofStr (16 bytes) followed by the NTLMv2 blob.
	NTChallengeResponse []byte
	LMChallengeResponse []byte
	// MIC is the message integrity code over the negotiate/challenge/authenticate
	// triple, present only when the server requested it.
	MIC     *[16]byte
	Version *[8]byte
}

// Marshal encodes the AUTHENTICATE_MESSAGE. The version field follows the
// same rule as NegotiateMessage.Marshal; MIC is serialized when set. Payload
// offsets are computed in wire order: LM, NT, domain, user, workstation,
// session key.
func (m AuthenticateMessage) Marshal() ([]byte, error) {
	flags := m.Flags
	includeVersion := flags&NEGOTIATE_VERSION != 0 || m.Version != nil
	headerLen := authenticateHeaderLen
	if includeVersion {
		flags |= NEGOTIATE_VERSION
		headerLen += versionLen
	}
	if m.MIC != nil {
		headerLen += micLen
	}

	lm := m.LMChallengeResponse
	nt := m.NTChallengeResponse
	domain := encodeString(m.Domain, flags)
	user := encodeString(m.User, flags)
	workstation := encodeString(m.Workstation, flags)
	key := m.EncryptedRandomSessionKey

	out := make([]byte, headerLen)
	copy(out[0:8], signature[:])
	binary.LittleEndian.PutUint32(out[8:12], typeAuthenticate)
	offset := headerLen
	writeSecBuf(out[12:20], len(lm), offset)
	offset += len(lm)
	writeSecBuf(out[20:28], len(nt), offset)
	offset += len(nt)
	writeSecBuf(out[28:36], len(domain), offset)
	offset += len(domain)
	writeSecBuf(out[36:44], len(user), offset)
	offset += len(user)
	writeSecBuf(out[44:52], len(workstation), offset)
	offset += len(workstation)
	writeSecBuf(out[52:60], len(key), offset)
	binary.LittleEndian.PutUint32(out[60:64], flags)
	if includeVersion {
		if m.Version != nil {
			copy(out[authenticateHeaderLen:], m.Version[:])
		}
	}
	if m.MIC != nil {
		micOff := authenticateHeaderLen
		if includeVersion {
			micOff += versionLen
		}
		copy(out[micOff:], m.MIC[:])
	}

	out = append(out, lm...)
	out = append(out, nt...)
	out = append(out, domain...)
	out = append(out, user...)
	out = append(out, workstation...)
	out = append(out, key...)
	return out, nil
}

// ParseAuthenticate decodes an AUTHENTICATE_MESSAGE. The optional MIC field
// is detected from the payload start offset: the security buffers begin after
// the fixed header (plus version and MIC when present), so a first payload
// offset beyond header+MIC proves the MIC is there (MS-NLMP 2.2.1.3).
func ParseAuthenticate(b []byte) (*AuthenticateMessage, error) {
	if err := checkHeader(b, authenticateHeaderLen, typeAuthenticate); err != nil {
		return nil, err
	}
	m := &AuthenticateMessage{Flags: binary.LittleEndian.Uint32(b[60:64])}
	headerLen := authenticateHeaderLen
	if m.Flags&NEGOTIATE_VERSION != 0 {
		if len(b) < authenticateHeaderLen+versionLen {
			return nil, fmt.Errorf("ntlm: authenticate message truncated before version field")
		}
		var v [8]byte
		copy(v[:], b[authenticateHeaderLen:authenticateHeaderLen+versionLen])
		m.Version = &v
		headerLen += versionLen
	}
	if minPayloadOffset(b, 6) >= headerLen+micLen {
		var mic [16]byte
		copy(mic[:], b[headerLen:headerLen+micLen])
		m.MIC = &mic
		headerLen += micLen
	}

	lm, err := readSecBufRaw(b, 12, headerLen)
	if err != nil {
		return nil, fmt.Errorf("ntlm: authenticate LM response: %w", err)
	}
	nt, err := readSecBufRaw(b, 20, headerLen)
	if err != nil {
		return nil, fmt.Errorf("ntlm: authenticate NT response: %w", err)
	}
	domain, err := readSecBuf(b, 28, headerLen, m.Flags)
	if err != nil {
		return nil, fmt.Errorf("ntlm: authenticate domain: %w", err)
	}
	user, err := readSecBuf(b, 36, headerLen, m.Flags)
	if err != nil {
		return nil, fmt.Errorf("ntlm: authenticate user: %w", err)
	}
	workstation, err := readSecBuf(b, 44, headerLen, m.Flags)
	if err != nil {
		return nil, fmt.Errorf("ntlm: authenticate workstation: %w", err)
	}
	key, err := readSecBufRaw(b, 52, headerLen)
	if err != nil {
		return nil, fmt.Errorf("ntlm: authenticate session key: %w", err)
	}
	m.LMChallengeResponse = lm
	m.NTChallengeResponse = nt
	m.Domain = domain
	m.User = user
	m.Workstation = workstation
	m.EncryptedRandomSessionKey = key
	return m, nil
}

// checkHeader validates the NTLMSSP signature and message type.
func checkHeader(b []byte, minLen int, msgType uint32) error {
	if len(b) < minLen {
		return fmt.Errorf("ntlm: message too short: %d bytes, need %d", len(b), minLen)
	}
	for i := 0; i < len(signature); i++ {
		if b[i] != signature[i] {
			return fmt.Errorf("ntlm: bad message signature")
		}
	}
	if got := binary.LittleEndian.Uint32(b[8:12]); got != msgType {
		return fmt.Errorf("ntlm: unexpected message type 0x%08x, want 0x%08x", got, msgType)
	}
	return nil
}

// writeSecBuf writes an 8-byte security buffer descriptor at b[0:8].
func writeSecBuf(b []byte, length, offset int) {
	binary.LittleEndian.PutUint16(b[0:2], uint16(length))
	binary.LittleEndian.PutUint16(b[2:4], uint16(length))
	binary.LittleEndian.PutUint32(b[4:8], uint32(offset))
}

// readSecBufRaw extracts the payload referenced by the descriptor at descOff
// and validates that it lies inside b and outside the fixed header region.
func readSecBufRaw(b []byte, descOff, headerLen int) ([]byte, error) {
	if descOff+securityBufferLen > len(b) {
		return nil, fmt.Errorf("ntlm: security buffer descriptor at %d out of range", descOff)
	}
	length := int(binary.LittleEndian.Uint16(b[descOff : descOff+2]))
	offset := int(binary.LittleEndian.Uint32(b[descOff+4 : descOff+8]))
	if length == 0 {
		return nil, nil
	}
	if offset < headerLen {
		return nil, fmt.Errorf("ntlm: security buffer offset %d inside %d-byte header", offset, headerLen)
	}
	if offset > len(b) || length > len(b)-offset {
		return nil, fmt.Errorf("ntlm: security buffer [%d:%d] out of range for %d-byte message", offset, offset+length, len(b))
	}
	return b[offset : offset+length], nil
}

// readSecBuf reads a security buffer and decodes it as a string according to
// the NEGOTIATE_UNICODE flag.
func readSecBuf(b []byte, descOff, headerLen int, flags uint32) (string, error) {
	raw, err := readSecBufRaw(b, descOff, headerLen)
	if err != nil {
		return "", err
	}
	return decodeString(raw, flags)
}

// minPayloadOffset returns the lowest security buffer payload offset of the
// first count descriptors, or len(b) when all of them are empty.
func minPayloadOffset(b []byte, count int) int {
	min := len(b)
	for i := 0; i < count; i++ {
		desc := 12 + i*securityBufferLen // all messages: first descriptor at 12
		if desc+securityBufferLen > len(b) {
			return len(b)
		}
		length := binary.LittleEndian.Uint16(b[desc : desc+2])
		offset := int(binary.LittleEndian.Uint32(b[desc+4 : desc+8]))
		if length > 0 && offset < min {
			min = offset
		}
	}
	return min
}

// encodeString encodes an NTLM string field per the UNICODE flag.
func encodeString(s string, flags uint32) []byte {
	if s == "" {
		return nil
	}
	if flags&NEGOTIATE_UNICODE != 0 {
		return encodeUTF16LE(s)
	}
	return []byte(s)
}

// decodeString decodes an NTLM string field per the UNICODE flag.
func decodeString(b []byte, flags uint32) (string, error) {
	if len(b) == 0 {
		return "", nil
	}
	if flags&NEGOTIATE_UNICODE != 0 {
		return decodeUTF16LE(b)
	}
	return string(b), nil
}
