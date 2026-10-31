package rdp

import (
	"encoding/binary"
	"fmt"
)

// Share Control / Data PDU type constants (MS-RDPBCGR 2.2.8.1.1.1.1).
const (
	pduTypeDemandActive  uint16 = 0x1
	pduTypeConfirmActive uint16 = 0x3
	pduTypeDeactivateAll uint16 = 0x6
	pduTypeData          uint16 = 0x7

	pduVersionMask uint16 = 0xFF0
	pduTypeMask    uint16 = 0xF
	pduVersion1    uint16 = 0x10

	pduType2Update   byte = 0x02
	pduType2Control  byte = 0x14
	pduType2Pointer  byte = 0x1B
	pduType2Sync     byte = 0x1F
	pduType2FontList byte = 0x27
	pduType2FontMap  byte = 0x28
	pduType2SetError byte = 0x2F
	pduType2SaveInfo byte = 0x26

	updateTypeOrders  uint16 = 0
	updateTypeBitmap  uint16 = 1
	updateTypePalette uint16 = 2
	updateTypeSync    uint16 = 3

	ctrlActionCooperate      uint16 = 0x0004
	ctrlActionRequestControl uint16 = 0x0001
)

// shareControlHeader builds a TS_SHARECONTROLHEADER.
func shareControlHeader(totalLen uint16, pduType uint16, source uint16) []byte {
	out := make([]byte, 6)
	binary.LittleEndian.PutUint16(out[0:2], totalLen)
	binary.LittleEndian.PutUint16(out[2:4], pduVersion1|pduType)
	binary.LittleEndian.PutUint16(out[4:6], source)
	return out
}

func parseShareControlHeader(b []byte) (totalLen, pduType, source uint16, err error) {
	if len(b) < 6 {
		return 0, 0, 0, fmt.Errorf("rdp: short share control header")
	}
	totalLen = binary.LittleEndian.Uint16(b[0:2])
	raw := binary.LittleEndian.Uint16(b[2:4])
	pduType = raw & pduTypeMask
	source = binary.LittleEndian.Uint16(b[4:6])
	return totalLen, pduType, source, nil
}

// buildShareDataPDU wraps a type2 payload in Share Control + Share Data headers.
func buildShareDataPDU(shareID uint32, source uint16, pduType2 byte, payload []byte) []byte {
	// share data header is 12 bytes after the 6-byte control header.
	uncompressed := uint16(12 + len(payload))
	total := uint16(6 + uncompressed)
	out := shareControlHeader(total, pduTypeData, source)
	out = binary.LittleEndian.AppendUint32(out, shareID)
	out = append(out, 0x00) // pad1
	out = append(out, 0x01) // streamID = STREAM_LOW
	out = binary.LittleEndian.AppendUint16(out, uncompressed)
	out = append(out, pduType2, 0x00)              // compressedType
	out = binary.LittleEndian.AppendUint16(out, 0) // compressedLength
	return append(out, payload...)
}

func parseShareDataHeader(b []byte) (shareID uint32, pduType2 byte, payload []byte, err error) {
	if len(b) < 12 {
		return 0, 0, nil, fmt.Errorf("rdp: short share data header")
	}
	shareID = binary.LittleEndian.Uint32(b[0:4])
	pduType2 = b[6]
	payload = b[12:]
	return shareID, pduType2, payload, nil
}
