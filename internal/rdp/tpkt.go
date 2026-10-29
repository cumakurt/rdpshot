package rdp

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	tpktVersion byte = 3
	// maxTPKTLength bounds a single TPKT frame; the length field is 16-bit and
	// includes the 4 byte header. The limit rejects malformed/truncated frames.
	maxTPKTLength int = 65535
	tpktHeaderLen int = 4
)

// WriteTPKT writes payload framed as one TPKT packet.
func WriteTPKT(w io.Writer, payload []byte) error {
	if len(payload)+tpktHeaderLen > maxTPKTLength {
		return fmt.Errorf("rdp: TPKT payload too large: %d bytes", len(payload))
	}
	header := []byte{tpktVersion, 0, 0, 0}
	binary.BigEndian.PutUint16(header[2:], uint16(len(payload)+tpktHeaderLen))
	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("rdp: write TPKT header: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("rdp: write TPKT payload: %w", err)
	}
	return nil
}

// ReadTPKT reads and validates one TPKT packet, returning its payload.
func ReadTPKT(r io.Reader) ([]byte, error) {
	header := make([]byte, tpktHeaderLen)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("rdp: read TPKT header: %w", err)
	}
	if header[0] != tpktVersion {
		return nil, fmt.Errorf("%w: unexpected TPKT version %d", ErrNotRDP, header[0])
	}
	if header[1] != 0 {
		return nil, fmt.Errorf("rdp: unexpected TPKT reserved byte %d", header[1])
	}
	total := int(binary.BigEndian.Uint16(header[2:]))
	if total < tpktHeaderLen {
		return nil, fmt.Errorf("rdp: TPKT length %d smaller than header", total)
	}
	payload := make([]byte, total-tpktHeaderLen)
	if len(payload) > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, fmt.Errorf("rdp: read TPKT payload: %w", err)
		}
	}
	return payload, nil
}
