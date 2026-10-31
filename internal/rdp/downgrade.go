package rdp

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"rdpshot/internal/model"
)

// DowngradeResult describes the outcome of testing whether the server permits
// downgrading from NLA to TLS or legacy standard RDP.
type DowngradeResult struct {
	Vulnerable bool   `json:"vulnerable"`
	Selected   uint32 `json:"selected"`
	Reason     string `json:"reason"`
	Evidence   string `json:"evidence"`
}

// ProbeNLADowngrade tests if an RDP server allows an active MitM to downgrade
// the connection by requesting only TLS without NLA flags (ProtocolSSL).
func ProbeNLADowngrade(ctx context.Context, ep model.Endpoint, timeout time.Duration) (DowngradeResult, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	addr := net.JoinHostPort(ep.Address, strconv.Itoa(int(ep.Port)))
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return DowngradeResult{}, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Request only ProtocolSSL (TLS without NLA flags)
	if err := WriteConnectionRequest(conn, "", ProtocolSSL); err != nil {
		return DowngradeResult{}, fmt.Errorf("write downgrade CR: %w", err)
	}

	result, err := ReadConnectionConfirm(conn)
	if err != nil {
		return DowngradeResult{}, fmt.Errorf("read downgrade CC: %w", err)
	}

	if result.FailureCode != nil {
		code := *result.FailureCode
		if code == FailureHybridRequiredByServer || code == FailureSSLWithUserAuthByServer {
			return DowngradeResult{
				Vulnerable: false,
				Reason:     "Server rejected TLS-only probe and strictly required NLA",
				Evidence:   FailureCodeText(code),
			}, nil
		}
		return DowngradeResult{
			Vulnerable: false,
			Reason:     "Server rejected connection with failure code",
			Evidence:   FailureCodeText(code),
		}, nil
	}

	if result.SelectedProtocol == ProtocolSSL || result.SelectedProtocol == ProtocolRDP {
		return DowngradeResult{
			Vulnerable: true,
			Selected:   result.SelectedProtocol,
			Reason:     "Server willingly accepted downgrade to TLS without NLA enforcement (MitM / PyRDP susceptible)",
			Evidence:   fmt.Sprintf("Negotiated protocol 0x%08x when client omitted NLA flags", result.SelectedProtocol),
		}, nil
	}

	return DowngradeResult{
		Vulnerable: false,
		Selected:   result.SelectedProtocol,
		Reason:     "Server selected secure protocol",
	}, nil
}
