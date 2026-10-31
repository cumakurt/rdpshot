package rdp

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"rdpshot/internal/model"
)

// MS-RDPEUDP protocol flags (MS-RDPEUDP section 2.2.1)
const (
	RDPEUDP_FLAG_SYN  uint16 = 0x0001
	RDPEUDP_FLAG_FIN  uint16 = 0x0002
	RDPEUDP_FLAG_ACK  uint16 = 0x0004
	RDPEUDP_FLAG_DATA uint16 = 0x0008
	RDPEUDP_FLAG_FEC  uint16 = 0x0010
	RDPEUDP_FLAG_CN   uint16 = 0x0020
	RDPEUDP_FLAG_CWR  uint16 = 0x0040
)

// UDPProbeResult carries the MS-RDPEUDP discovery outcome.
type UDPProbeResult struct {
	Reachable    bool   `json:"reachable"`
	SYNACK       bool   `json:"syn_ack"`
	DTLSSupport  bool   `json:"dtls_support"`
	ResponseSize int    `json:"response_size"`
	Evidence     string `json:"evidence,omitempty"`
}

// BuildRDPEUDPSyn constructs an MS-RDPEUDP SYN packet.
// Structure:
// snSource (4B) | snSourceAck (4B) | uReceiveWindowSize (2B) | uFlags (2B) | uUpStreamMtu (2B) | uDownStreamMtu (2B)
func BuildRDPEUDPSyn(seq uint32) []byte {
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint32(buf[0:4], seq)
	binary.LittleEndian.PutUint32(buf[4:8], 0)                  // snSourceAck
	binary.LittleEndian.PutUint16(buf[8:10], 0x0040)            // uReceiveWindowSize (64)
	binary.LittleEndian.PutUint16(buf[10:12], RDPEUDP_FLAG_SYN) // uFlags
	binary.LittleEndian.PutUint16(buf[12:14], 1232)             // uUpStreamMtu
	binary.LittleEndian.PutUint16(buf[14:16], 1232)             // uDownStreamMtu
	return buf
}

// BuildDTLSClientHello constructs a minimal DTLS 1.0 ClientHello probe packet.
func BuildDTLSClientHello() []byte {
	// DTLS 1.0 record layer header + ClientHello
	return []byte{
		0x16,       // ContentType: Handshake (22)
		0xfe, 0xff, // ProtocolVersion: DTLS 1.0
		0x00, 0x00, // Epoch: 0
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Sequence Number: 0
		0x00, 0x24, // Length: 36
		// Handshake Header
		0x01,             // HandshakeType: ClientHello (1)
		0x00, 0x00, 0x18, // Length: 24
		0x00, 0x00, // MessageSeq: 0
		0x00, 0x00, 0x00, // FragmentOffset: 0
		0x00, 0x00, 0x18, // FragmentLength: 24
		0xfe, 0xff, // ClientVersion: DTLS 1.0
		// Random (16 bytes dummy)
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x00,       // SessionID length: 0
		0x00,       // Cookie length: 0
		0x00, 0x02, // CipherSuites length: 2
		0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
		0x01, 0x00, // CompressionMethods length: 1, method 0
	}
}

// ProbeRDPEUDP sends MS-RDPEUDP SYN and DTLS ClientHello probes to UDP/3389.
func ProbeRDPEUDP(ctx context.Context, ep model.Endpoint, timeout time.Duration) UDPProbeResult {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	res := UDPProbeResult{}

	addr := net.JoinHostPort(ep.Address, strconv.Itoa(int(ep.Port)))
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		return res
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// 1. Try MS-RDPEUDP SYN
	synPkt := BuildRDPEUDPSyn(100)
	if _, err := conn.Write(synPkt); err == nil {
		buf := make([]byte, 512)
		n, err := conn.Read(buf)
		if err == nil && n >= 12 {
			res.Reachable = true
			res.ResponseSize = n
			flags := binary.LittleEndian.Uint16(buf[10:12])
			if flags&(RDPEUDP_FLAG_SYN|RDPEUDP_FLAG_ACK) != 0 {
				res.SYNACK = true
				res.Evidence = fmt.Sprintf("MS-RDPEUDP SYN-ACK received (%d bytes, flags: 0x%04x)", n, flags)
				return res
			}
			res.Evidence = fmt.Sprintf("MS-RDPEUDP response received (%d bytes, flags: 0x%04x)", n, flags)
			return res
		}
	}

	// 2. Try DTLS ClientHello
	_ = conn.SetDeadline(time.Now().Add(timeout))
	dtlsPkt := BuildDTLSClientHello()
	if _, err := conn.Write(dtlsPkt); err == nil {
		buf := make([]byte, 512)
		n, err := conn.Read(buf)
		if err == nil && n > 0 {
			res.Reachable = true
			res.ResponseSize = n
			// Check if DTLS response: ContentType 22 (Handshake) or 21 (Alert)
			if buf[0] == 0x16 || buf[0] == 0x15 {
				res.DTLSSupport = true
				res.Evidence = fmt.Sprintf("DTLS handshake response received on UDP/3389 (%d bytes)", n)
				return res
			}
			res.Evidence = fmt.Sprintf("UDP/3389 responded to DTLS probe (%d bytes)", n)
			return res
		}
	}

	return res
}

// DescribeUDPResult returns a human-readable summary of the UDP probe.
func DescribeUDPResult(res UDPProbeResult) string {
	if !res.Reachable {
		return "UDP/3389 closed or filtered"
	}
	var parts []string
	if res.SYNACK {
		parts = append(parts, "MS-RDPEUDP Acceleration Enabled")
	}
	if res.DTLSSupport {
		parts = append(parts, "DTLS Active")
	}
	if len(parts) == 0 {
		parts = append(parts, "UDP Responsive")
	}
	return strings.Join(parts, ", ") + " (" + res.Evidence + ")"
}
