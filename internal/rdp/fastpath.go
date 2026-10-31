package rdp

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
)

// Fast-path update codes (MS-RDPBCGR 2.2.9.1.2.1).
const (
	fastPathOrders      byte = 0x0
	fastPathBitmap      byte = 0x1
	fastPathPalette     byte = 0x2
	fastPathSynchronize byte = 0x3
)

// isFastPathHeader reports whether b looks like a fast-path TPKT alternative
// (action bits in the low nibble of the first byte, length follows).
func isFastPathHeader(b []byte) bool {
	if len(b) < 2 {
		return false
	}
	// Classic TPKT starts with version 0x03. Fast-path does not.
	return b[0] != 0x03
}

// parseFastPathLength returns the total PDU length and header size.
func parseFastPathLength(b []byte) (total, header int, err error) {
	if len(b) < 2 {
		return 0, 0, fmt.Errorf("rdp: short fast-path header")
	}
	if b[1]&0x80 == 0 {
		return int(b[1]), 2, nil
	}
	if len(b) < 3 {
		return 0, 0, fmt.Errorf("rdp: short fast-path length")
	}
	return (int(b[1]&0x7f) << 8) | int(b[2]), 3, nil
}

// applyFastPathUpdates walks fast-path update packets and applies bitmap /
// orders fragments to the framebuffer. Unknown codes are skipped.
func (fb *Framebuffer) applyFastPathUpdates(payload []byte, cache *bitmapCache) (bitmaps, orders int, err error) {
	off := 0
	for off < len(payload) {
		if off >= len(payload) {
			break
		}
		code := payload[off] & 0x0f
		frag := (payload[off] >> 4) & 0x03
		off++
		if off+1 > len(payload) {
			break
		}
		size := int(payload[off])
		off++
		if size&0x80 != 0 {
			if off >= len(payload) {
				break
			}
			size = ((size & 0x7f) << 8) | int(payload[off])
			off++
		}
		if frag == 0x2 || frag == 0x3 {
			// Fragmented; skip incomplete pieces in this MVP.
			if off+size > len(payload) {
				break
			}
			off += size
			continue
		}
		if off+size > len(payload) {
			size = len(payload) - off
		}
		body := payload[off : off+size]
		off += size
		switch code {
		case fastPathBitmap:
			n, e := fb.ApplyBitmapUpdate(body)
			if e == nil {
				bitmaps += n
			}
		case fastPathOrders:
			n := applyOrders(fb, body, cache)
			orders += n
		}
	}
	return bitmaps, orders, nil
}

// readFastPathPayload strips the fast-path header and optional encryption
// flags, returning the update stream. Enhanced RDP Security (TLS) carries
// no FIPS signature here.
func readFastPathPayload(frame []byte) ([]byte, error) {
	total, header, err := parseFastPathLength(frame)
	if err != nil {
		return nil, err
	}
	if total > len(frame) {
		total = len(frame)
	}
	body := frame[header:total]
	_ = binary.LittleEndian
	return body, nil
}

// readCaptureFrame reads either a classic TPKT/X.224 data PDU body or a
// fast-path update stream. fast=true means payload is the fast-path update body.
func readCaptureFrame(br *bufio.Reader) (fast bool, payload []byte, err error) {
	peek, err := br.Peek(1)
	if err != nil {
		return false, nil, err
	}
	if peek[0] == tpktVersion {
		frame, err := ReadTPKT(br)
		if err != nil {
			return false, nil, err
		}
		// X.224 Data TPDU: LI + 0xF0 + EOT, then MCS payload.
		if len(frame) >= 3 && frame[1] == 0xF0 {
			return false, frame[3:], nil
		}
		return false, frame, nil
	}
	// Fast-path: read length-prefixed PDU from the wire.
	hdr := make([]byte, 3)
	if _, err := io.ReadFull(br, hdr[:2]); err != nil {
		return false, nil, err
	}
	total, headerLen, err := parseFastPathLength(hdr[:2])
	if err != nil {
		return false, nil, err
	}
	if headerLen == 3 {
		if _, err := io.ReadFull(br, hdr[2:3]); err != nil {
			return false, nil, err
		}
		total, headerLen, err = parseFastPathLength(hdr[:3])
		if err != nil {
			return false, nil, err
		}
	}
	if total < headerLen {
		return false, nil, fmt.Errorf("rdp: invalid fast-path length %d", total)
	}
	rest := make([]byte, total-headerLen)
	if len(rest) > 0 {
		if _, err := io.ReadFull(br, rest); err != nil {
			return false, nil, err
		}
	}
	frame := append(hdr[:headerLen], rest...)
	body, err := readFastPathPayload(frame)
	if err != nil {
		return false, nil, err
	}
	return true, body, nil
}
