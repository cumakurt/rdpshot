package ntlm

import (
	"encoding/binary"
	"fmt"
)

// AV pair identifiers (MS-NLMP 2.2.2.1).
const (
	MsvAvEOL             uint16 = 0x0000
	MsvAvNbComputerName  uint16 = 0x0001
	MsvAvNbDomainName    uint16 = 0x0002
	MsvAvDnsComputerName uint16 = 0x0003
	MsvAvDnsDomainName   uint16 = 0x0004
	MsvAvDnsTreeName     uint16 = 0x0005
	MsvAvFlags           uint16 = 0x0006
	MsvAvTimestamp       uint16 = 0x0007
	MsvAvSingleHost      uint16 = 0x0008
	MsvAvTargetName      uint16 = 0x0009
	MsvAvChannelBindings uint16 = 0x000A
)

// AVPairLen is the fixed size of an AV_PAIR header (id + length).
const AVPairLen = 4

// AVPair is one attribute/value pair from the CHALLENGE target info.
// Data holds the raw value bytes; string values are UTF-16LE.
type AVPair struct {
	ID   uint16
	Data []byte
}

// ParseAVPairs decodes a target info blob into AV pairs. The terminating
// MsvAvEOL pair is consumed but not returned. Malformed input returns an
// error; the parser never panics.
func ParseAVPairs(b []byte) ([]AVPair, error) {
	var pairs []AVPair
	for len(b) > 0 {
		if len(b) < AVPairLen {
			return nil, fmt.Errorf("ntlm: truncated AV pair header (%d bytes left)", len(b))
		}
		id := binary.LittleEndian.Uint16(b[0:2])
		length := int(binary.LittleEndian.Uint16(b[2:4]))
		b = b[AVPairLen:]
		if length > len(b) {
			return nil, fmt.Errorf("ntlm: AV pair 0x%04x length %d exceeds remaining %d bytes", id, length, len(b))
		}
		if id == MsvAvEOL {
			// Per MS-NLMP the EOL pair carries no data and must be last;
			// trailing bytes are tolerated but ignored.
			if length != 0 {
				return nil, fmt.Errorf("ntlm: MsvAvEOL pair has non-zero length %d", length)
			}
			return pairs, nil
		}
		pairs = append(pairs, AVPair{ID: id, Data: append([]byte(nil), b[:length]...)})
		b = b[length:]
	}
	// A target info without an explicit EOL terminator is tolerated by
	// Windows; mirror that leniency.
	return pairs, nil
}

// MarshalAVPairs encodes AV pairs and appends the mandatory MsvAvEOL
// terminator. If the input already ends with an EOL pair it is not duplicated.
func MarshalAVPairs(pairs []AVPair) []byte {
	out := make([]byte, 0, 16+len(pairs)*8)
	for _, p := range pairs {
		out = append(out, byte(p.ID), byte(p.ID>>8),
			byte(len(p.Data)), byte(len(p.Data)>>8))
		out = append(out, p.Data...)
	}
	if len(pairs) == 0 || pairs[len(pairs)-1].ID != MsvAvEOL {
		out = append(out, 0x00, 0x00, 0x00, 0x00)
	}
	return out
}

// WithTargetName returns a copy of pairs with an MsvAvTargetName entry set to
// the given SPN-style target, used when binding the NTLM exchange to the
// service being accessed.
func WithTargetName(pairs []AVPair, target string) []AVPair {
	out := make([]AVPair, 0, len(pairs)+1)
	for _, p := range pairs {
		if p.ID == MsvAvTargetName {
			continue
		}
		out = append(out, p)
	}
	out = append(out, AVPair{ID: MsvAvTargetName, Data: encodeUTF16LE(target)})
	return out
}
