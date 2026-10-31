package rdp

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"strings"
	"time"

	"rdpshot/internal/model"
)

// TLSProfile describes the server's TLS cryptographic posture.
type TLSProfile struct {
	SupportedVersions []string `json:"supported_versions"`
	SupportedCiphers  []string `json:"supported_ciphers"`
	LegacyVersions    []string `json:"legacy_versions"`
	WeakCiphers       []string `json:"weak_ciphers"`
}

// IsLegacyTLSVersion reports whether a TLS version is obsolete.
func IsLegacyTLSVersion(v string) bool {
	switch strings.TrimSpace(v) {
	case "SSL 3.0", "TLS 1.0", "TLS 1.1":
		return true
	default:
		return false
	}
}

// IsWeakCipherSuite reports whether a cipher suite contains weak or deprecated algorithms.
func IsWeakCipherSuite(name string) bool {
	upper := strings.ToUpper(name)
	for _, w := range []string{"RC4", "3DES", "_DES_", "_NULL_", "EXPORT", "_ANON_"} {
		if strings.Contains(upper, w) {
			return true
		}
	}
	return false
}

// InsecureCipherIDs returns the IDs of insecure cipher suites supported by Go stdlib.
func InsecureCipherIDs() []uint16 {
	var ids []uint16
	for _, cs := range tls.InsecureCipherSuites() {
		ids = append(ids, cs.ID)
	}
	return ids
}

// ProbeTLSVersion attempts an RDP negotiation and TLS handshake specifically for the given version.
func ProbeTLSVersion(ctx context.Context, ep model.Endpoint, version uint16, timeout time.Duration) (bool, string, error) {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	addr := net.JoinHostPort(ep.Address, strconv.Itoa(int(ep.Port)))
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, "", err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := WriteConnectionRequest(conn, "rdpshot-tls", ProtocolSSL|ProtocolHybrid); err != nil {
		return false, "", err
	}
	br := bufio.NewReader(conn)
	neg, err := ReadConnectionConfirm(br)
	if err != nil {
		return false, "", err
	}
	if neg.SelectedProtocol != ProtocolSSL && neg.SelectedProtocol != ProtocolHybrid && neg.SelectedProtocol != ProtocolHybridEx {
		return false, "", nil
	}

	allCiphers := InsecureCipherIDs()
	for _, cs := range tls.CipherSuites() {
		allCiphers = append(allCiphers, cs.ID)
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // scanner audit probe
		MinVersion:         version,
		MaxVersion:         version,
		CipherSuites:       allCiphers,
	}
	tlsConn := tls.Client(conn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return false, "", nil
	}
	state := tlsConn.ConnectionState()
	return true, tls.CipherSuiteName(state.CipherSuite), nil
}

// ProbeWeakCiphers checks if the server negotiates any insecure cipher suites when offered.
func ProbeWeakCiphers(ctx context.Context, ep model.Endpoint, timeout time.Duration) ([]string, error) {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	insecure := InsecureCipherIDs()
	if len(insecure) == 0 {
		return nil, nil
	}

	addr := net.JoinHostPort(ep.Address, strconv.Itoa(int(ep.Port)))
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := WriteConnectionRequest(conn, "rdpshot-weakciphers", ProtocolSSL|ProtocolHybrid); err != nil {
		return nil, err
	}
	br := bufio.NewReader(conn)
	neg, err := ReadConnectionConfirm(br)
	if err != nil {
		return nil, err
	}
	if neg.SelectedProtocol != ProtocolSSL && neg.SelectedProtocol != ProtocolHybrid && neg.SelectedProtocol != ProtocolHybridEx {
		return nil, nil
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // scanner audit probe
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS12,
		CipherSuites:       insecure,
	}
	tlsConn := tls.Client(conn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, nil
	}
	state := tlsConn.ConnectionState()
	cipherName := tls.CipherSuiteName(state.CipherSuite)
	if IsWeakCipherSuite(cipherName) {
		return []string{cipherName}, nil
	}
	return nil, nil
}

// ProbeTLSProfile audits the endpoint for supported TLS versions and weak ciphers.
func ProbeTLSProfile(ctx context.Context, ep model.Endpoint, timeout time.Duration) (*TLSProfile, error) {
	profile := &TLSProfile{}
	versions := []struct {
		ver  uint16
		name string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
	}

	for _, v := range versions {
		supported, cipher, err := ProbeTLSVersion(ctx, ep, v.ver, timeout)
		if err != nil {
			continue
		}
		if supported {
			profile.SupportedVersions = append(profile.SupportedVersions, v.name)
			if cipher != "" && !containsStr(profile.SupportedCiphers, cipher) {
				profile.SupportedCiphers = append(profile.SupportedCiphers, cipher)
			}
			if IsLegacyTLSVersion(v.name) && !containsStr(profile.LegacyVersions, v.name) {
				profile.LegacyVersions = append(profile.LegacyVersions, v.name)
			}
			if IsWeakCipherSuite(cipher) && !containsStr(profile.WeakCiphers, cipher) {
				profile.WeakCiphers = append(profile.WeakCiphers, cipher)
			}
		}
	}

	weak, _ := ProbeWeakCiphers(ctx, ep, timeout)
	for _, w := range weak {
		if !containsStr(profile.WeakCiphers, w) {
			profile.WeakCiphers = append(profile.WeakCiphers, w)
		}
	}

	return profile, nil
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
