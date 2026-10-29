package rdp

import (
	"encoding/binary"
	"fmt"
	"io"
)

// X.224 TPDU type codes used by RDP (MS-RDPBCGR 2.2.1.1).
const (
	x224ConnectionRequest byte = 0xE0
	x224ConnectionConfirm byte = 0xD0
	x224NegotiationLength int  = 8
)

// BuildConnectionRequest builds the TPKT-framed X.224 Connection Request with
// an embedded RDP_NEG_REQ. cookie is optional (mstshash value) and may be empty.
func BuildConnectionRequest(cookie string, requestedProtocols uint32) []byte {
	variable := make([]byte, 0, 64)
	if cookie != "" {
		variable = append(variable, []byte("Cookie: mstshash="+cookie+"\r\n")...)
	}
	neg := make([]byte, x224NegotiationLength)
	neg[0] = negTypeRequest
	neg[1] = 0x00 // flags
	binary.LittleEndian.PutUint16(neg[2:], uint16(x224NegotiationLength))
	binary.LittleEndian.PutUint32(neg[4:], requestedProtocols)
	variable = append(variable, neg...)

	tpdu := make([]byte, 0, 7+len(variable))
	tpdu = append(tpdu, byte(6+len(variable))) // length indicator: bytes after LI
	tpdu = append(tpdu, x224ConnectionRequest)
	tpdu = append(tpdu, 0x00, 0x00) // dst-ref
	tpdu = append(tpdu, 0x00, 0x00) // src-ref
	tpdu = append(tpdu, 0x00)       // class 0
	tpdu = append(tpdu, variable...)

	frame := make([]byte, 0, tpktHeaderLen+len(tpdu))
	header := []byte{tpktVersion, 0, 0, 0}
	binary.BigEndian.PutUint16(header[2:], uint16(tpktHeaderLen+len(tpdu)))
	frame = append(frame, header...)
	frame = append(frame, tpdu...)
	return frame
}

// WriteConnectionRequest writes a single X.224 Connection Request to w.
func WriteConnectionRequest(w io.Writer, cookie string, requestedProtocols uint32) error {
	frame := BuildConnectionRequest(cookie, requestedProtocols)
	if _, err := w.Write(frame); err != nil {
		return fmt.Errorf("rdp: write connection request: %w", err)
	}
	return nil
}

// ParseConnectionConfirm parses an X.224 Connection Confirm TPDU payload
// (without the TPKT header) and extracts the RDP negotiation result.
func ParseConnectionConfirm(tpdu []byte) (NegotiationResult, error) {
	var result NegotiationResult
	if len(tpdu) < 7 {
		return result, fmt.Errorf("rdp: connection confirm too short: %d bytes", len(tpdu))
	}
	li := int(tpdu[0])
	if li+1 > len(tpdu) {
		return result, fmt.Errorf("rdp: connection confirm length indicator %d exceeds payload %d", li, len(tpdu))
	}
	if tpdu[1] != x224ConnectionConfirm {
		return result, fmt.Errorf("rdp: expected X.224 Connection Confirm (0xD0), got 0x%02x", tpdu[1])
	}
	variable := tpdu[7 : li+1]
	if len(variable) == 0 {
		// Legacy server: standard RDP security without negotiation.
		result.SelectedProtocol = ProtocolRDP
		return result, nil
	}
	// The variable part may hold a cookie first; the negotiation structure is
	// identified by its type byte and its self-declared length of 8.
	neg := variable
	for len(neg) >= x224NegotiationLength {
		if neg[0] == negTypeResponse || neg[0] == negTypeFailure {
			if int(binary.LittleEndian.Uint16(neg[2:])) == x224NegotiationLength {
				break
			}
		}
		// Skip a cookie line ("Cookie: ...\r\n") before the negotiation struct.
		skip := indexCRLF(neg)
		if skip < 0 {
			return result, fmt.Errorf("rdp: no negotiation structure in connection confirm")
		}
		neg = neg[skip+2:]
	}
	if len(neg) < x224NegotiationLength {
		return result, fmt.Errorf("rdp: truncated negotiation structure")
	}

	result.NegotiationType = neg[0]
	result.Flags = neg[1]
	result.Raw = append([]byte(nil), neg[:x224NegotiationLength]...)
	switch neg[0] {
	case negTypeResponse:
		result.SelectedProtocol = binary.LittleEndian.Uint32(neg[4:8])
	case negTypeFailure:
		code := binary.LittleEndian.Uint32(neg[4:8])
		result.FailureCode = &code
		result.SelectedProtocol = ProtocolRDP
	default:
		return NegotiationResult{}, fmt.Errorf("rdp: unknown negotiation type 0x%02x", neg[0])
	}
	return result, nil
}

// ReadConnectionConfirm reads one TPKT-framed X.224 Connection Confirm and
// returns its negotiation result.
func ReadConnectionConfirm(r io.Reader) (NegotiationResult, error) {
	payload, err := ReadTPKT(r)
	if err != nil {
		return NegotiationResult{}, err
	}
	return ParseConnectionConfirm(payload)
}

func indexCRLF(b []byte) int {
	for i := 0; i+1 < len(b); i++ {
		if b[i] == '\r' && b[i+1] == '\n' {
			return i
		}
	}
	return -1
}
