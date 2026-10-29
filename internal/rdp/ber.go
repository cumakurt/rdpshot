package rdp

import (
	"encoding/binary"
	"fmt"
)

// BER tags used by the MCS layer (ASN.1 BER).
const (
	berTagBoolean      = 0x01
	berTagInteger      = 0x02
	berTagOctetString  = 0x04
	berTagEnumerated   = 0x0A
	berTagDomainParams = 0x30
)

// berAppendHeader appends an ASN.1 BER header for tag and content length.
func berAppendHeader(dst []byte, tag int, length int) []byte {
	if tag > 0xff {
		dst = append(dst, byte(tag>>8), byte(tag))
	} else {
		dst = append(dst, byte(tag))
	}
	if length >= 0x80 {
		dst = append(dst, 0x82)
		dst = binary.BigEndian.AppendUint16(dst, uint16(length))
		return dst
	}
	return append(dst, byte(length))
}

// berAppendInteger appends a small BER INTEGER (2 byte payload).
func berAppendInteger(dst []byte, value int) []byte {
	dst = berAppendHeader(dst, berTagInteger, 2)
	return binary.BigEndian.AppendUint16(dst, uint16(value))
}

// berReadHeader parses a BER header and returns the content length and the
// remaining bytes. The tag must match expectTag.
func berReadHeader(buf []byte, expectTag int) (content []byte, rest []byte, err error) {
	tagBytes := 1
	if expectTag > 0xff {
		tagBytes = 2
	}
	if len(buf) < tagBytes+1 {
		return nil, nil, fmt.Errorf("rdp: truncated BER header for tag %#x", expectTag)
	}
	if tagBytes == 2 {
		if int(binary.BigEndian.Uint16(buf)) != expectTag {
			return nil, nil, fmt.Errorf("rdp: expected BER tag %#x, got %#x", expectTag, binary.BigEndian.Uint16(buf))
		}
		buf = buf[2:]
	} else {
		if int(buf[0]) != expectTag {
			return nil, nil, fmt.Errorf("rdp: expected BER tag %#x, got %#x", expectTag, buf[0])
		}
		buf = buf[1:]
	}

	length := int(buf[0])
	buf = buf[1:]
	if length&0x80 != 0 {
		octets := length & 0x7f
		if octets == 0 || octets > 2 || len(buf) < octets {
			return nil, nil, fmt.Errorf("rdp: unsupported BER length encoding %#x", length)
		}
		length = 0
		for i := 0; i < octets; i++ {
			length = length<<8 | int(buf[i])
		}
		buf = buf[octets:]
	}
	if len(buf) < length {
		return nil, nil, fmt.Errorf("rdp: BER content length %d exceeds buffer %d", length, len(buf))
	}
	return buf[:length], buf[length:], nil
}
