package rdp

import (
	"encoding/binary"
	"fmt"
)

// MCS PDU type codes (T.125) used by the RDP connection sequence.
const (
	mcsErectDomainRequest byte = 1
	mcsDisconnectProvider byte = 8
	mcsAttachUserRequest  byte = 10
	mcsAttachUserConfirm  byte = 11
	mcsChannelJoinRequest byte = 14
	mcsChannelJoinConfirm byte = 15
	mcsSendDataRequest    byte = 25
	mcsSendDataIndication byte = 26
)

// MCS connect PDUs carried in X.224 data TPDUs (application BER tags).
const (
	mcsConnectInitial  = 0x7f65
	mcsConnectResponse = 0x7f66
)

// GCC server data block types (MS-RDPBCGR 2.2.1.4).
const (
	scCore     uint16 = 0x0C00
	scNet      uint16 = 0x0C01
	scSecurity uint16 = 0x0C02
)

// GCC client data block types (MS-RDPBCGR 2.2.1.3).
const (
	csCore     uint16 = 0xC001
	csSecurity uint16 = 0xC002
	csNet      uint16 = 0xC003
	csCluster  uint16 = 0xC004
)

// MCS channel identifiers used by RDP (MS-RDPBCGR 2.2.1.3.4).
const (
	// MCSGlobalChannel is the well-known MCS user channel id used by RDP.
	MCSGlobalChannel uint16 = 1003
	// MCSUserChannelBase is added to the MCS user id to form the user channel.
	MCSUserChannelBase uint16 = 1001
	// firstStaticChannelID is the first client-assigned static virtual channel id.
	firstStaticChannelID uint16 = MCSGlobalChannel + 1

	channelOptionInitialized uint32 = 0x80000000
	channelOptionCompressRDP uint32 = 0x00800000
	channelFlagFirst         uint32 = 0x01
	channelFlagLast          uint32 = 0x02
	// channelHeaderSize is the virtual channel PDU header (length + flags).
	channelHeaderSize = 8
)

// ChannelDef is one static virtual channel requested in the GCC client data.
type ChannelDef struct {
	Name    string
	Options uint32
	// ID is the client-assigned MCS channel id (firstStaticChannelID + index).
	ID uint16
}

// ServerData is the parsed GCC server data of an MCS Connect Response.
type ServerData struct {
	// Version is the server core version field (raw protocol value).
	Version uint32
	// RequestedProtocols echoes the protocols supported by the client.
	RequestedProtocols uint32
	// MCSChannelID is the server's MCS channel id (normally 1003).
	MCSChannelID uint16
	// ChannelIDs lists the static virtual channel ids offered by the server.
	ChannelIDs []uint16
	// EncryptionMethod/Level describe standard RDP security (MS-RDPBCGR 2.2.1.4.3).
	EncryptionMethod uint32
	EncryptionLevel  uint32
	// Raw keeps hex evidence of the parsed blocks for reporting.
	Raw map[string]string
}

// EncryptionLevelName maps the server encryption level to a display name.
func EncryptionLevelName(level uint32) string {
	switch level {
	case 0:
		return "none"
	case 1:
		return "low"
	case 2:
		return "client_compatible"
	case 3:
		return "high"
	case 4:
		return "fips"
	}
	return fmt.Sprintf("unknown(%d)", level)
}

// berAppendDomainParams appends a DOMAIN_PARAMS structure.
func berAppendDomainParams(dst []byte, maxChannels, maxUsers, maxTokens, maxPDUSize int) []byte {
	content := make([]byte, 0, 32)
	for _, v := range []int{maxChannels, maxUsers, maxTokens, 1, 0, 1, maxPDUSize, 2} {
		content = berAppendInteger(content, v)
	}
	dst = berAppendHeader(dst, berTagDomainParams, len(content))
	return append(dst, content...)
}

// BuildConnectInitial builds the MCS Connect Initial PDU wrapping the given
// GCC (T.124 ConferenceCreateRequest) user data.
func BuildConnectInitial(gcc []byte) []byte {
	content := make([]byte, 0, len(gcc)+128)
	content = berAppendHeader(content, berTagOctetString, 1) // calling domain selector
	content = append(content, 0x01)
	content = berAppendHeader(content, berTagOctetString, 1) // called domain selector
	content = append(content, 0x01)
	content = berAppendHeader(content, berTagBoolean, 1) // upward flag
	content = append(content, 0xff)
	content = berAppendDomainParams(content, 34, 2, 0, 0xffff)               // target
	content = berAppendDomainParams(content, 1, 1, 1, 0x420)                 // minimum
	content = berAppendDomainParams(content, 0xffff, 0xfc17, 0xffff, 0xffff) // maximum
	content = berAppendHeader(content, berTagOctetString, len(gcc))
	content = append(content, gcc...)

	out := berAppendHeader(nil, mcsConnectInitial, len(content))
	return append(out, content...)
}

// BuildGCCClientData builds the T.124 ConferenceCreateRequest user data with
// the client core, cluster, security and network data blocks.
func BuildGCCClientData(requestedProtocols uint32, channels []ChannelDef) []byte {
	core := buildClientCoreData(requestedProtocols)
	cluster := buildClientClusterData()
	security := buildClientSecurityData()
	network := buildClientNetworkData(channels)

	blocks := make([]byte, 0, 300)
	blocks = append(blocks, core...)
	blocks = append(blocks, cluster...)
	blocks = append(blocks, security...)
	blocks = append(blocks, network...)

	// T.124 ConferenceCreateRequest envelope. The two PER length determinants
	// cover (envelope tail + blocks) and (blocks) respectively; the byte layout
	// is fixed by the wire format used by every common RDP client.
	out := []byte{0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01}
	out = appendPERLength(out, 14+len(blocks))
	out = append(out, 0x00, 0x08, 0x00, 0x10, 0x00, 0x01, 0xc0, 0x00)
	out = append(out, []byte("Duca")...) // OEM identifier
	out = appendPERLength(out, len(blocks))
	return append(out, blocks...)
}

// appendPERLength appends a 15-bit PER length determinant (2 bytes).
func appendPERLength(dst []byte, length int) []byte {
	return binary.BigEndian.AppendUint16(dst, uint16(length)|0x8000)
}

func buildClientCoreData(requestedProtocols uint32) []byte {
	body := make([]byte, 0, 212)
	body = binary.LittleEndian.AppendUint32(body, 0x00080004) // RDP 5.0+
	body = binary.LittleEndian.AppendUint16(body, 1024)       // desktopWidth
	body = binary.LittleEndian.AppendUint16(body, 768)        // desktopHeight
	body = binary.LittleEndian.AppendUint16(body, 0xCA01)     // colorDepth (8BPP)
	body = binary.LittleEndian.AppendUint16(body, 0xAA03)     // SASSequence
	body = binary.LittleEndian.AppendUint32(body, 0x00000409) // keyboardLayout (en-US)
	body = binary.LittleEndian.AppendUint32(body, 2600)       // clientBuild
	name := make([]byte, 32)
	for i, r := range "rdpshot" {
		name[i*2] = byte(r)
	}
	body = append(body, name...)
	body = binary.LittleEndian.AppendUint32(body, 4)                  // keyboardType
	body = binary.LittleEndian.AppendUint32(body, 0)                  // keyboardSubType
	body = binary.LittleEndian.AppendUint32(body, 0)                  // keyboardFunctionKey
	body = append(body, make([]byte, 64)...)                          // imeFileName
	body = binary.LittleEndian.AppendUint16(body, 0xCA01)             // postBeta2ColorDepth
	body = binary.LittleEndian.AppendUint16(body, 1)                  // clientProductId
	body = binary.LittleEndian.AppendUint32(body, 0)                  // serialNumber
	body = binary.LittleEndian.AppendUint16(body, 24)                 // highColorDepth
	body = binary.LittleEndian.AppendUint16(body, 0x0700)             // supportedColorDepths
	body = binary.LittleEndian.AppendUint16(body, 0x0001)             // earlyCapabilityFlags
	body = append(body, make([]byte, 64)...)                          // clientDigProductId
	body = append(body, 0x00, 0x00)                                   // connectionType + pad
	body = binary.LittleEndian.AppendUint32(body, requestedProtocols) // serverSelectedProtocol
	return appendBlock(nil, csCore, body)
}

func buildClientClusterData() []byte {
	body := make([]byte, 0, 8)
	// Redirection supported with redirect version 3 (MS-RDPBCGR 2.2.1.3.5).
	body = binary.LittleEndian.AppendUint32(body, 0x00000001|(3<<2))
	body = binary.LittleEndian.AppendUint32(body, 0) // redirectedSessionID
	return appendBlock(nil, csCluster, body)
}

func buildClientSecurityData() []byte {
	body := make([]byte, 0, 8)
	// 40-bit and 128-bit RC4 support advertised; the probe itself never
	// negotiates legacy encryption keys.
	body = binary.LittleEndian.AppendUint32(body, 0x00000003)
	body = binary.LittleEndian.AppendUint32(body, 0) // extEncryptionMethods
	return appendBlock(nil, csSecurity, body)
}

func buildClientNetworkData(channels []ChannelDef) []byte {
	if len(channels) == 0 {
		return nil
	}
	body := make([]byte, 0, 8+12*len(channels))
	body = binary.LittleEndian.AppendUint32(body, uint32(len(channels)))
	for _, ch := range channels {
		name := make([]byte, 8)
		copy(name, ch.Name)
		body = append(body, name...)
		body = binary.LittleEndian.AppendUint32(body, ch.Options)
	}
	return appendBlock(nil, csNet, body)
}

// appendBlock appends a GCC data block header (type + length) and its body.
func appendBlock(dst []byte, blockType uint16, body []byte) []byte {
	dst = binary.LittleEndian.AppendUint16(dst, blockType)
	dst = binary.LittleEndian.AppendUint16(dst, uint16(4+len(body)))
	return append(dst, body...)
}

// ParseConnectResponse parses an MCS Connect Response and extracts the GCC
// server data blocks.
func ParseConnectResponse(pdu []byte) (ServerData, error) {
	var server ServerData
	server.Raw = map[string]string{}

	content, _, err := berReadHeader(pdu, mcsConnectResponse)
	if err != nil {
		return server, err
	}
	result, content, err := berReadHeader(content, berTagEnumerated)
	if err != nil {
		return server, err
	}
	if len(result) < 1 {
		return server, fmt.Errorf("rdp: empty MCS connect result")
	}
	if result[0] != 0 {
		return server, fmt.Errorf("rdp: MCS connect rejected with result %d", result[0])
	}
	if _, content, err = berReadHeader(content, berTagInteger); err != nil {
		return server, err // connectId
	}
	if _, content, err = berReadHeader(content, berTagDomainParams); err != nil {
		return server, err
	}
	userData, _, err := berReadHeader(content, berTagOctetString)
	if err != nil {
		return server, err
	}
	return parseServerDataBlocks(userData)
}

// parseServerDataBlocks walks the T.124 ConferenceCreateResponse user data and
// decodes the TS_UD_SC_* blocks.
func parseServerDataBlocks(userData []byte) (ServerData, error) {
	var server ServerData
	server.Raw = map[string]string{}

	if len(userData) < 23 {
		return server, fmt.Errorf("rdp: MCS connect response user data too short: %d bytes", len(userData))
	}
	// Fixed T.124 ConferenceCreateResponse envelope followed by a PER length
	// determinant (1 or 2 bytes), then the data blocks.
	blocks := userData[21:]
	if blocks[0]&0x80 != 0 {
		if len(blocks) < 2 {
			return server, fmt.Errorf("rdp: truncated PER length determinant")
		}
		blocks = blocks[2:]
	} else {
		blocks = blocks[1:]
	}

	for len(blocks) > 0 {
		if len(blocks) < 4 {
			return server, fmt.Errorf("rdp: truncated server data block header")
		}
		blockType := binary.LittleEndian.Uint16(blocks[0:2])
		blockLen := int(binary.LittleEndian.Uint16(blocks[2:4]))
		if blockLen < 4 || blockLen > len(blocks) {
			return server, fmt.Errorf("rdp: invalid server data block length %d for type %#x", blockLen, blockType)
		}
		body := blocks[4:blockLen]
		blocks = blocks[blockLen:]

		switch blockType {
		case scCore:
			if len(body) < 4 {
				return server, fmt.Errorf("rdp: short SC_CORE block")
			}
			server.Version = binary.LittleEndian.Uint32(body[0:4])
			if len(body) >= 8 {
				server.RequestedProtocols = binary.LittleEndian.Uint32(body[4:8])
			}
		case scNet:
			if len(body) < 4 {
				return server, fmt.Errorf("rdp: short SC_NET block")
			}
			server.MCSChannelID = binary.LittleEndian.Uint16(body[0:2])
			count := int(binary.LittleEndian.Uint16(body[2:4]))
			if 4+2*count > len(body) {
				return server, fmt.Errorf("rdp: SC_NET channel count %d exceeds block", count)
			}
			for i := 0; i < count; i++ {
				server.ChannelIDs = append(server.ChannelIDs,
					binary.LittleEndian.Uint16(body[4+2*i:6+2*i]))
			}
		case scSecurity:
			if len(body) < 8 {
				return server, fmt.Errorf("rdp: short SC_SECURITY block")
			}
			server.EncryptionMethod = binary.LittleEndian.Uint32(body[0:4])
			server.EncryptionLevel = binary.LittleEndian.Uint32(body[4:8])
			server.Raw["sc_security"] = fmt.Sprintf("%x", body)
		default:
			server.Raw[fmt.Sprintf("block_%#04x", blockType)] = fmt.Sprintf("%x", body)
		}
	}
	return server, nil
}
