package rdp

import (
	"encoding/binary"
	"fmt"
	"io"
)

// ErrDisconnected is returned when the peer closes or rejects the session.
var ErrDisconnected = fmt.Errorf("rdp: peer disconnected")

// writeDataTPDU writes payload as an X.224 Data TPDU inside a TPKT frame.
func writeDataTPDU(w io.Writer, payload []byte) error {
	frame := make([]byte, 0, 3+len(payload))
	frame = append(frame, 0x02, 0xF0, 0x80) // LI=2, DT, EOT
	frame = append(frame, payload...)
	return WriteTPKT(w, frame)
}

// readDataTPDU reads one X.224 Data TPDU payload.
func readDataTPDU(r io.Reader) ([]byte, error) {
	frame, err := ReadTPKT(r)
	if err != nil {
		return nil, err
	}
	if len(frame) < 3 {
		return nil, fmt.Errorf("rdp: X.224 data TPDU too short: %d bytes", len(frame))
	}
	code := frame[1]
	switch code {
	case 0xF0: // DT
		return frame[3:], nil
	case 0x80: // DR (disconnect request)
		return nil, fmt.Errorf("%w: X.224 disconnect request", ErrDisconnected)
	case 0x70: // ER (error)
		return nil, fmt.Errorf("%w: X.224 error TPDU", ErrDisconnected)
	}
	return nil, fmt.Errorf("rdp: unexpected X.224 TPDU code %#x", code)
}

// buildErectDomainRequest builds the MCS Erect Domain Request PDU.
func buildErectDomainRequest() []byte {
	return []byte{mcsErectDomainRequest << 2, 0x00, 0x01, 0x00, 0x01}
}

// buildAttachUserRequest builds the MCS Attach User Request PDU.
func buildAttachUserRequest() []byte {
	return []byte{mcsAttachUserRequest << 2}
}

// buildChannelJoinRequest builds the MCS Channel Join Request PDU.
func buildChannelJoinRequest(userID, channelID uint16) []byte {
	out := []byte{mcsChannelJoinRequest << 2}
	out = binary.BigEndian.AppendUint16(out, userID)
	return binary.BigEndian.AppendUint16(out, channelID)
}

// buildSendDataRequest builds the MCS Send Data Request PDU carrying payload
// on the given channel. The length determinant uses the two byte form.
func buildSendDataRequest(userID, channelID uint16, payload []byte) []byte {
	out := []byte{mcsSendDataRequest << 2}
	out = binary.BigEndian.AppendUint16(out, userID)
	out = binary.BigEndian.AppendUint16(out, channelID)
	out = append(out, 0x70) // priority + segmentation flags
	out = binary.BigEndian.AppendUint16(out, uint16(len(payload))|0x8000)
	return append(out, payload...)
}

// MCSPDU is a decoded MCS domain or data PDU.
type MCSPDU struct {
	Type byte
	// Result is set for confirm PDUs.
	Result byte
	// UserID is the assigned user id (Attach User Confirm) or the sender id.
	UserID uint16
	// ChannelID is the joined or addressed channel id.
	ChannelID uint16
	// Payload is the user data of a Send Data Indication.
	Payload []byte
}

// ParseMCSPDU decodes one MCS PDU payload.
func ParseMCSPDU(payload []byte) (MCSPDU, error) {
	var pdu MCSPDU
	if len(payload) < 1 {
		return pdu, fmt.Errorf("rdp: empty MCS PDU")
	}
	pdu.Type = payload[0] >> 2
	switch pdu.Type {
	case mcsAttachUserConfirm:
		if len(payload) < 2 {
			return pdu, fmt.Errorf("rdp: short MCS Attach User Confirm")
		}
		pdu.Result = payload[1]
		if payload[0]&0x02 != 0 && len(payload) >= 4 {
			pdu.UserID = binary.BigEndian.Uint16(payload[2:4])
		}
	case mcsChannelJoinConfirm:
		if len(payload) < 6 {
			return pdu, fmt.Errorf("rdp: short MCS Channel Join Confirm")
		}
		pdu.Result = payload[1]
		pdu.UserID = binary.BigEndian.Uint16(payload[2:4])
		pdu.ChannelID = binary.BigEndian.Uint16(payload[4:6])
	case mcsSendDataIndication:
		if len(payload) < 7 {
			return pdu, fmt.Errorf("rdp: short MCS Send Data Indication")
		}
		pdu.UserID = binary.BigEndian.Uint16(payload[1:3])
		pdu.ChannelID = binary.BigEndian.Uint16(payload[3:5])
		// Byte 5 carries priority/segmentation flags, byte 6 starts the PER
		// length determinant of the user data (1 or 2 bytes).
		length := int(payload[6])
		offset := 7
		if length&0x80 != 0 {
			if len(payload) < 8 {
				return pdu, fmt.Errorf("rdp: truncated MCS data length")
			}
			length = (length&0x7f)<<8 | int(payload[7])
			offset = 8
		}
		if len(payload) < offset+length {
			// Servers may pad; accept what is available but keep it bounded.
			length = len(payload) - offset
		}
		pdu.Payload = payload[offset : offset+length]
	case mcsDisconnectProvider:
		// Reason code follows; kept for evidence.
		if len(payload) >= 2 {
			pdu.Result = payload[1]
		}
	default:
		// Domain PDUs such as Erect Domain Request carry no useful fields here.
	}
	return pdu, nil
}

// buildChannelPDU wraps payload in the virtual channel PDU header used by RDP
// static virtual channels (MS-RDPBCGR 2.2.6.1).
func buildChannelPDU(payload []byte) []byte {
	out := make([]byte, 0, channelHeaderSize+len(payload))
	out = binary.LittleEndian.AppendUint32(out, uint32(len(payload)))
	out = binary.LittleEndian.AppendUint32(out, channelFlagFirst|channelFlagLast)
	return append(out, payload...)
}

// buildMS_T120CheckPayloads returns the two benign channel messages used by
// the safe CVE-2019-0708 detection probe. They contain no shellcode; they only
// exercise the MS_T120 channel handling that patched servers ignore.
func buildMS_T120CheckPayloads() [][]byte {
	first := make([]byte, 0x20)
	first[8] = 2
	second := make([]byte, 0x10)
	second[4] = 2
	return [][]byte{first, second}
}
