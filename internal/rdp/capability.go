package rdp

import "encoding/binary"

// Capability set types (MS-RDPBCGR 2.2.7).
const (
	capGeneral         uint16 = 0x0001
	capBitmap          uint16 = 0x0002
	capOrder           uint16 = 0x0003
	capBitmapCache     uint16 = 0x0004
	capPointer         uint16 = 0x0008
	capShare           uint16 = 0x0009
	capColorCache      uint16 = 0x000A
	capSound           uint16 = 0x000C
	capInput           uint16 = 0x000D
	capFont            uint16 = 0x000E
	capBrush           uint16 = 0x000F
	capGlyphCache      uint16 = 0x0010
	capOffscreenCache  uint16 = 0x0011
	capBitmapCacheHost uint16 = 0x0012
	capBitmapCacheRev2 uint16 = 0x0013
	capVirtualChannel  uint16 = 0x0014
	capDrawNineGrid    uint16 = 0x0015
	capDrawGDIPlus     uint16 = 0x0016
	capRail            uint16 = 0x0017
	capWindow          uint16 = 0x0018
	capCompDesk        uint16 = 0x0019
	capMultifragment   uint16 = 0x001A
	capLargePointer    uint16 = 0x001B
	capSurfaceCommands uint16 = 0x001C
	capBitmapCodecs    uint16 = 0x001D
	capFrameAck        uint16 = 0x001E
)

const (
	osMajorWindows uint16 = 0x0001
	osMinorNT      uint16 = 0x0003
	protocolVer    uint16 = 0x0200
)

// buildConfirmActivePDU builds a Confirm Active PDU advertising classic
// bitmap support and declining RDPGFX / surface commands.
func buildConfirmActivePDU(shareID uint32, source uint16, desktopWidth, desktopHeight uint16) []byte {
	caps := concatCaps(
		capSetGeneral(),
		capSetBitmap(desktopWidth, desktopHeight),
		capSetOrder(),
		capSetBitmapCache(),
		capSetPointer(),
		capSetShare(),
		capSetInput(),
		capSetBrush(),
		capSetGlyphCache(),
		capSetOffscreen(),
		capSetVirtualChannel(),
		capSetSound(),
		capSetFont(),
	)

	sourceDesc := append([]byte("rdpshot\x00"), make([]byte, 0)...)
	// Confirm Active body (without share control header):
	// shareID(4) + originatorID(2) + lengthSourceDescriptor(2) +
	// lengthCombinedCapabilities(2) + sourceDescriptor + numberCapabilities(2) +
	// pad2Octets(2) + capabilitySets
	numberCaps := uint16(13)
	combinedLen := uint16(4 + len(caps)) // numberCapabilities+pad + sets
	body := make([]byte, 0, 16+len(sourceDesc)+len(caps))
	body = binary.LittleEndian.AppendUint32(body, shareID)
	body = binary.LittleEndian.AppendUint16(body, 0x03EA) // originatorID (server user)
	body = binary.LittleEndian.AppendUint16(body, uint16(len(sourceDesc)))
	body = binary.LittleEndian.AppendUint16(body, combinedLen)
	body = append(body, sourceDesc...)
	body = binary.LittleEndian.AppendUint16(body, numberCaps)
	body = binary.LittleEndian.AppendUint16(body, 0) // pad
	body = append(body, caps...)

	total := uint16(6 + len(body))
	out := shareControlHeader(total, pduTypeConfirmActive, source)
	return append(out, body...)
}

func concatCaps(sets ...[]byte) []byte {
	var out []byte
	for _, s := range sets {
		out = append(out, s...)
	}
	return out
}

func capHeader(capType, length uint16, body []byte) []byte {
	out := make([]byte, 0, 4+len(body))
	out = binary.LittleEndian.AppendUint16(out, capType)
	out = binary.LittleEndian.AppendUint16(out, length)
	return append(out, body...)
}

func capSetGeneral() []byte {
	b := make([]byte, 0, 24)
	b = binary.LittleEndian.AppendUint16(b, osMajorWindows)
	b = binary.LittleEndian.AppendUint16(b, osMinorNT)
	b = binary.LittleEndian.AppendUint16(b, protocolVer)
	b = binary.LittleEndian.AppendUint16(b, 0)      // pad
	b = binary.LittleEndian.AppendUint16(b, 0)      // compressionTypes
	b = binary.LittleEndian.AppendUint16(b, 0x0401) // extraFlags: NO_BITMAP_COMPRESSION_HDR | FASTPATH_OUTPUT_SUPPORTED off
	b = binary.LittleEndian.AppendUint16(b, 0)
	b = binary.LittleEndian.AppendUint16(b, 0)
	b = binary.LittleEndian.AppendUint16(b, 0)
	b = binary.LittleEndian.AppendUint16(b, 0)
	return capHeader(capGeneral, uint16(4+len(b)), b)
}

func capSetBitmap(w, h uint16) []byte {
	b := make([]byte, 0, 24)
	b = binary.LittleEndian.AppendUint16(b, 1) // preferredBitsPerPixel = 16 initially; server may pick 24/32
	b = binary.LittleEndian.AppendUint16(b, 1) // receive1Bit
	b = binary.LittleEndian.AppendUint16(b, 1) // receive4Bit
	b = binary.LittleEndian.AppendUint16(b, 1) // receive8Bit
	b = binary.LittleEndian.AppendUint16(b, w)
	b = binary.LittleEndian.AppendUint16(b, h)
	b = binary.LittleEndian.AppendUint16(b, 0) // pad
	b = binary.LittleEndian.AppendUint16(b, 1) // allowResize
	b = binary.LittleEndian.AppendUint16(b, 1) // bitmapCompression
	b = binary.LittleEndian.AppendUint16(b, 0) // highColorFlags
	b = binary.LittleEndian.AppendUint16(b, 1) // drawingFlags: DRAW_ALLOW_SKIP
	b = binary.LittleEndian.AppendUint16(b, 1) // multipleRectangleSupport
	b = binary.LittleEndian.AppendUint16(b, 0) // pad
	return capHeader(capBitmap, uint16(4+len(b)), b)
}

func capSetOrder() []byte {
	b := make([]byte, 0, 88)
	b = append(b, make([]byte, 16)...) // terminalDescriptor
	b = binary.LittleEndian.AppendUint32(b, 0)
	b = binary.LittleEndian.AppendUint16(b, 1) // maximumOrderLevel
	b = binary.LittleEndian.AppendUint16(b, 20)
	b = binary.LittleEndian.AppendUint16(b, 0)      // numberFonts
	b = binary.LittleEndian.AppendUint16(b, 0x0022) // orderFlags: NEGOTIATEORDERSUPPORT | COLORINDEXSUPPORT
	b = append(b, make([]byte, 32)...)              // orderSupport — all zero (no drawing orders)
	b = binary.LittleEndian.AppendUint16(b, 0)
	b = binary.LittleEndian.AppendUint16(b, 0)
	b = binary.LittleEndian.AppendUint16(b, 0)
	b = binary.LittleEndian.AppendUint16(b, 0)
	b = binary.LittleEndian.AppendUint16(b, 0)
	b = binary.LittleEndian.AppendUint16(b, 0)
	b = binary.LittleEndian.AppendUint32(b, 0)
	b = binary.LittleEndian.AppendUint32(b, 0)
	b = binary.LittleEndian.AppendUint16(b, 0)
	b = binary.LittleEndian.AppendUint16(b, 0)
	return capHeader(capOrder, uint16(4+len(b)), b)
}

func capSetBitmapCache() []byte {
	b := make([]byte, 0, 36)
	b = append(b, make([]byte, 24)...) // pad
	b = binary.LittleEndian.AppendUint16(b, 0)
	b = binary.LittleEndian.AppendUint16(b, 0)
	b = binary.LittleEndian.AppendUint16(b, 0)
	b = binary.LittleEndian.AppendUint16(b, 0)
	b = binary.LittleEndian.AppendUint16(b, 0)
	b = binary.LittleEndian.AppendUint16(b, 0)
	return capHeader(capBitmapCache, uint16(4+len(b)), b)
}

func capSetPointer() []byte {
	b := make([]byte, 0, 6)
	b = binary.LittleEndian.AppendUint16(b, 1) // colorPointerFlag
	b = binary.LittleEndian.AppendUint16(b, 20)
	b = binary.LittleEndian.AppendUint16(b, 20)
	return capHeader(capPointer, uint16(4+len(b)), b)
}

func capSetShare() []byte {
	b := make([]byte, 0, 4)
	b = binary.LittleEndian.AppendUint16(b, 0)
	b = binary.LittleEndian.AppendUint16(b, 0)
	return capHeader(capShare, uint16(4+len(b)), b)
}

func capSetInput() []byte {
	b := make([]byte, 0, 84)
	b = binary.LittleEndian.AppendUint16(b, 0x0015) // inputFlags: SCANCODES | MOUSEX | UNICODE
	b = binary.LittleEndian.AppendUint16(b, 0)
	b = binary.LittleEndian.AppendUint32(b, 0x00000409)
	b = append(b, make([]byte, 64)...) // keyboardType etc simplified
	b = binary.LittleEndian.AppendUint32(b, 4)
	b = binary.LittleEndian.AppendUint32(b, 0)
	b = binary.LittleEndian.AppendUint32(b, 12)
	return capHeader(capInput, uint16(4+len(b)), b)
}

func capSetBrush() []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, 1) // BRUSH_DEFAULT
	return capHeader(capBrush, 8, b)
}

func capSetGlyphCache() []byte {
	b := make([]byte, 0, 48)
	for i := 0; i < 10; i++ {
		b = binary.LittleEndian.AppendUint16(b, 254)
		b = binary.LittleEndian.AppendUint16(b, 4)
	}
	b = binary.LittleEndian.AppendUint32(b, 0x01000100)
	b = binary.LittleEndian.AppendUint16(b, 256)
	b = binary.LittleEndian.AppendUint16(b, 256)
	return capHeader(capGlyphCache, uint16(4+len(b)), b)
}

func capSetOffscreen() []byte {
	b := make([]byte, 0, 8)
	b = binary.LittleEndian.AppendUint32(b, 0) // disabled
	b = binary.LittleEndian.AppendUint16(b, 0)
	b = binary.LittleEndian.AppendUint16(b, 0)
	return capHeader(capOffscreenCache, uint16(4+len(b)), b)
}

func capSetVirtualChannel() []byte {
	b := make([]byte, 0, 8)
	b = binary.LittleEndian.AppendUint32(b, 0xFFFFFFFF)
	b = binary.LittleEndian.AppendUint32(b, 0)
	return capHeader(capVirtualChannel, uint16(4+len(b)), b)
}

func capSetSound() []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint16(b[0:2], 0) // soundFlags
	return capHeader(capSound, 8, b)
}

func capSetFont() []byte {
	b := make([]byte, 4)
	return capHeader(capFont, 8, b)
}

func buildSynchronizePDU(shareID uint32, source uint16) []byte {
	payload := make([]byte, 4)
	binary.LittleEndian.PutUint16(payload[0:2], 1) // SYNCMSGTYPE_SYNC
	binary.LittleEndian.PutUint16(payload[2:4], source)
	return buildShareDataPDU(shareID, source, pduType2Sync, payload)
}

func buildControlPDU(shareID uint32, source uint16, action uint16) []byte {
	payload := make([]byte, 8)
	binary.LittleEndian.PutUint16(payload[0:2], action)
	binary.LittleEndian.PutUint16(payload[2:4], 0) // grantId
	binary.LittleEndian.PutUint32(payload[4:8], 0) // controlId
	return buildShareDataPDU(shareID, source, pduType2Control, payload)
}

func buildFontListPDU(shareID uint32, source uint16) []byte {
	payload := make([]byte, 8)
	binary.LittleEndian.PutUint16(payload[0:2], 0)      // numberFonts
	binary.LittleEndian.PutUint16(payload[2:4], 0)      // totalNumFonts
	binary.LittleEndian.PutUint16(payload[4:6], 0x0003) // listFlags: FIRST | LAST
	binary.LittleEndian.PutUint16(payload[6:8], 0x0032) // entrySize
	return buildShareDataPDU(shareID, source, pduType2FontList, payload)
}
