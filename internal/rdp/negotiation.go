package rdp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// RDP negotiation protocol identifiers (MS-RDPBCGR 2.2.1.2).
const (
	// ProtocolRDP is the legacy standard RDP security layer (no TLS, no NLA).
	ProtocolRDP uint32 = 0x00000000
	// ProtocolSSL is the TLS security layer without network level authentication.
	ProtocolSSL uint32 = 0x00000001
	// ProtocolHybrid is CredSSP/NLA negotiated before the TLS session is established.
	ProtocolHybrid uint32 = 0x00000002
	// ProtocolHybridEx extends ProtocolHybrid with a CredSSP early-user-auth result.
	ProtocolHybridEx uint32 = 0x00000008
	// ProtocolRDSTLS is the RDSTLS security layer used by RD Gateway scenarios.
	ProtocolRDSTLS uint32 = 0x80000000
)

// RequestedProtocols returns the protocol set used for reconnaissance probes:
// everything that lets the server reveal its security posture.
func RequestedProtocols() uint32 {
	return ProtocolSSL | ProtocolHybrid | ProtocolHybridEx
}

// Negotiation message types (MS-RDPBCGR 2.2.1.2.1).
const (
	negTypeRequest  byte = 0x01
	negTypeResponse byte = 0x02
	negTypeFailure  byte = 0x03
)

// RDP_NEG_FAILURE failure codes (MS-RDPBCGR 2.2.1.2.2).
const (
	FailureSSLRequiredByServer     uint32 = 0x00000001
	FailureSSLNotAllowedByServer   uint32 = 0x00000002
	FailureSSLCertNotOnServer      uint32 = 0x00000003
	FailureInconsistentFlags       uint32 = 0x00000004
	FailureHybridRequiredByServer  uint32 = 0x00000005
	FailureSSLWithUserAuthByServer uint32 = 0x00000006
)

// FailureCodeText maps an RDP_NEG_FAILURE code to a human readable explanation.
func FailureCodeText(code uint32) string {
	switch code {
	case FailureSSLRequiredByServer:
		return "SSL_REQUIRED_BY_SERVER: server requires TLS"
	case FailureSSLNotAllowedByServer:
		return "SSL_NOT_ALLOWED_BY_SERVER: server does not allow TLS"
	case FailureSSLCertNotOnServer:
		return "SSL_CERT_NOT_ON_SERVER: server has no certificate configured"
	case FailureInconsistentFlags:
		return "INCONSISTENT_FLAGS: contradictory negotiation flags"
	case FailureHybridRequiredByServer:
		return "HYBRID_REQUIRED_BY_SERVER: server requires NLA (CredSSP)"
	case FailureSSLWithUserAuthByServer:
		return "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER: server requires TLS with user authentication"
	}
	return fmt.Sprintf("UNKNOWN_FAILURE_CODE(0x%08x)", code)
}

// ProtocolName returns the display name of a negotiated protocol identifier.
func ProtocolName(p uint32) string {
	switch p {
	case ProtocolRDP:
		return "RDP (standard security)"
	case ProtocolSSL:
		return "TLS"
	case ProtocolHybrid:
		return "CredSSP/NLA (HYBRID)"
	case ProtocolHybridEx:
		return "CredSSP/NLA (HYBRID_EX)"
	case ProtocolRDSTLS:
		return "RDSTLS"
	}
	return fmt.Sprintf("UNKNOWN(0x%08x)", p)
}

// NegotiationResult is the parsed outcome of an X.224 Connection Confirm.
type NegotiationResult struct {
	// NegotiationType is the raw RDP_NEG_* type byte, or 0 when the server
	// answered with a legacy Connection Confirm without negotiation data.
	NegotiationType byte
	// Flags is the raw negotiation flags byte (e.g. EXTENDED_CLIENT_DATA_SUPPORTED).
	Flags byte
	// SelectedProtocol is the protocol the server chose (RDP_NEG_RSP only).
	SelectedProtocol uint32
	// FailureCode is set when the server answered with RDP_NEG_FAILURE.
	FailureCode *uint32
	// Raw preserves the negotiation payload bytes as evidence.
	Raw []byte
}

// NLARequired reports whether the outcome forces network level authentication.
func (r NegotiationResult) NLARequired() bool {
	return r.SelectedProtocol == ProtocolHybrid || r.SelectedProtocol == ProtocolHybridEx
}

// Early User Authorization Result PDU values (MS-RDPBCGR 2.2.15.2).
const (
	EarlyUserAuthorizationSuccess      uint32 = 0x00000000
	EarlyUserAuthorizationAccessDenied uint32 = 0x00000005
)

// ErrEarlyUserAccessDenied reports that HYBRID_EX early-user authorization
// rejected the delegated credentials after CredSSP completed.
var ErrEarlyUserAccessDenied = errors.New("rdp: early user authorization access denied")

// ReadEarlyUserAuthorizationResult consumes the 4-byte HYBRID_EX Early User
// Authorization Result PDU that follows CredSSP on the TLS stream (not TPKT).
func ReadEarlyUserAuthorizationResult(r io.Reader) error {
	var buf [4]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return fmt.Errorf("rdp: read early user authorization result: %w", err)
	}
	code := binary.LittleEndian.Uint32(buf[:])
	switch code {
	case EarlyUserAuthorizationSuccess:
		return nil
	case EarlyUserAuthorizationAccessDenied:
		return ErrEarlyUserAccessDenied
	default:
		return fmt.Errorf("rdp: unexpected early user authorization result 0x%08x", code)
	}
}

// Failed reports whether the server rejected the negotiation request.
func (r NegotiationResult) Failed() bool { return r.FailureCode != nil }
