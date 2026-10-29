// Package auth verifies credentials against RDP endpoints using the
// NLA/CredSSP stack. It classifies every outcome so callers can branch with
// errors.Is without parsing messages.
package auth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"rdpshot/internal/credssp"
	"rdpshot/internal/model"
	"rdpshot/internal/rdp"
)

// Classified errors; callers use errors.Is.
var (
	ErrAuthFailed    = errors.New("authentication failed")
	ErrAccountLocked = errors.New("account locked or disabled")
	ErrNLARequired   = errors.New("endpoint does not support NLA authentication")
	ErrProtocol      = errors.New("protocol error")
	ErrTimeout       = errors.New("timeout")
	ErrNetwork       = errors.New("network error")
)

// Authenticator verifies one credential against one RDP endpoint.
type Authenticator interface {
	Authenticate(ctx context.Context, ep model.Endpoint, cred model.Credential) error
}

// credSSPAuthenticator is the standard NLA/CredSSP authenticator.
type credSSPAuthenticator struct {
	timeout time.Duration
}

// NewCredSSPAuthenticator builds the standard NLA/CredSSP authenticator.
// timeout bounds dialing and the whole protocol exchange.
func NewCredSSPAuthenticator(timeout time.Duration) Authenticator {
	return &credSSPAuthenticator{timeout: timeout}
}

// Authenticate verifies cred against ep with one CredSSP exchange. It never
// logs or returns the secret; error strings carry only protocol context.
func (a *credSSPAuthenticator) Authenticate(ctx context.Context, ep model.Endpoint, cred model.Credential) error {
	conn, err := a.dial(ctx, ep)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := a.setDeadline(ctx, conn); err != nil {
		return err
	}
	// Force a blocked read/write to fail as soon as the caller cancels; the
	// deadline alone cannot interrupt an in-flight exchange.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	if err := rdp.WriteConnectionRequest(conn, "", rdp.RequestedProtocols()); err != nil {
		return a.classify(ctx, err)
	}
	result, err := rdp.ReadConnectionConfirm(conn)
	if err != nil {
		return a.classify(ctx, err)
	}
	if result.FailureCode != nil {
		return fmt.Errorf("%w: %s", ErrNLARequired, rdp.FailureCodeText(*result.FailureCode))
	}
	switch result.SelectedProtocol {
	case rdp.ProtocolHybrid, rdp.ProtocolHybridEx:
		// NLA is available; continue with TLS + CredSSP below.
	case rdp.ProtocolSSL:
		return fmt.Errorf("%w: server selected TLS without NLA", ErrNLARequired)
	case rdp.ProtocolRDP:
		return fmt.Errorf("%w: standard RDP security is not supported for credential checks", ErrNLARequired)
	default:
		return fmt.Errorf("%w: unsupported negotiated protocol 0x%08x", ErrProtocol, result.SelectedProtocol)
	}

	// This is a credential scanner, not a trusted connection: server
	// certificate validation is irrelevant to the question "does this
	// credential work", so chain verification is skipped deliberately.
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return a.classify(ctx, err)
	}

	client := &credssp.Client{Version: 6}
	if err := client.Handshake(ctx, tlsConn, cred.Username, cred.Secret, cred.Domain); err != nil {
		return a.classify(ctx, err)
	}
	return nil
}

// dial opens the TCP connection to the endpoint.
func (a *credSSPAuthenticator) dial(ctx context.Context, ep model.Endpoint) (net.Conn, error) {
	dialer := net.Dialer{Timeout: a.timeout}
	addr := net.JoinHostPort(ep.Address, strconv.Itoa(int(ep.Port)))
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, a.classify(ctx, fmt.Errorf("dial %s: %w", addr, err))
	}
	return conn, nil
}

// setDeadline derives the I/O deadline from the timeout and the context.
func (a *credSSPAuthenticator) setDeadline(ctx context.Context, conn net.Conn) error {
	var deadline time.Time
	if a.timeout > 0 {
		deadline = time.Now().Add(a.timeout)
	}
	if ctxDeadline, ok := ctx.Deadline(); ok && (deadline.IsZero() || ctxDeadline.Before(deadline)) {
		deadline = ctxDeadline
	}
	if deadline.IsZero() {
		return nil
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("%w: set deadline: %v", ErrNetwork, err)
	}
	return nil
}

// classify maps a transport, protocol or CredSSP error onto the sentinels.
// The context state takes precedence so cancellation is never reported as a
// generic protocol failure.
func (a *credSSPAuthenticator) classify(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("%w: %w", ErrTimeout, ctxErr)
	}
	var statusErr *credssp.NTStatusError
	if errors.As(err, &statusErr) {
		return mapNTStatus(statusErr.Code)
	}
	if errors.Is(err, credssp.ErrBindingMismatch) {
		return fmt.Errorf("%w: %v", ErrAuthFailed, err)
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return fmt.Errorf("%w: %w", ErrTimeout, err)
		}
		return fmt.Errorf("%w: %w", ErrNetwork, err)
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("%w: %w", ErrNetwork, err)
	}
	return fmt.Errorf("%w: %w", ErrProtocol, err)
}

// mapNTStatus classifies an NTSTATUS reported through the CredSSP errorCode
// field (MS-ERREF 2.3).
func mapNTStatus(code uint32) error {
	switch code {
	case credssp.StatusWrongPassword, credssp.StatusNoSuchUser, credssp.StatusLogonTypeNotGranted:
		return fmt.Errorf("%w: NTSTATUS 0x%08x", ErrAuthFailed, code)
	case credssp.StatusAccountLockedOut, credssp.StatusAccountDisabled:
		return fmt.Errorf("%w: NTSTATUS 0x%08x", ErrAccountLocked, code)
	case credssp.StatusNotSupported:
		return fmt.Errorf("%w: NTSTATUS 0x%08x", ErrProtocol, code)
	default:
		// Unknown failures from the authentication exchange are rejections,
		// not transport or framing problems.
		return fmt.Errorf("%w: NTSTATUS 0x%08x", ErrAuthFailed, code)
	}
}
