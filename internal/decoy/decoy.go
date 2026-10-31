// Package decoy implements a fake RDP server (honeypot/decoy listener) that
// simulates a Windows RDP endpoint.  When an attacker connects, the listener:
//
//  1. Completes the RDP Connection Initiation (HYBRID protocol negotiation).
//  2. Accepts and parses the attacker's NTLM Negotiate message (no actual auth).
//  3. Records a DecoyEvent with the attacker's IP, timestamp, and any username
//     material extracted from the NTLM blob.
//  4. Closes the connection — no credentials are ever returned.
//
// The listener fires OnEvent callbacks so the server can persist the event and
// push SIEM/webhook alerts.
package decoy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

// DecoyEvent is one attacker connection recorded by the decoy listener.
type DecoyEvent struct {
	At         time.Time `json:"at"`
	RemoteAddr string    `json:"remote_addr"`
	RemoteIP   string    `json:"remote_ip"`
	RemotePort string    `json:"remote_port,omitempty"`
	// NTLMUsername extracted from NTLM Negotiate (best-effort, may be empty).
	NTLMUsername string `json:"ntlm_username,omitempty"`
	// NTLMDomain extracted from NTLM Negotiate (best-effort, may be empty).
	NTLMDomain string `json:"ntlm_domain,omitempty"`
	// NTLMWorkstation is the attacker's machine name from the Negotiate message.
	NTLMWorkstation string `json:"ntlm_workstation,omitempty"`
	// NTLMFlags are the raw NTLM negotiate flags (hex).
	NTLMFlags string `json:"ntlm_flags,omitempty"`
	// TLSVersion is the TLS version negotiated (if TLS handshake succeeded).
	TLSVersion string `json:"tls_version,omitempty"`
	// TLSCipher is the cipher suite negotiated.
	TLSCipher string `json:"tls_cipher,omitempty"`
	// Stage indicates how far the attacker progressed: "tcp", "rdp_neg", "tls", "ntlm"
	Stage string `json:"stage"`
	// RDPCookie is the mstshash= cookie from the X.224 Connection Request, if present.
	RDPCookie string `json:"rdp_cookie,omitempty"`
	// Raw is the first 64 bytes of the initial TCP payload (hex-encoded).
	Raw string `json:"raw,omitempty"`
}

// Options configures the decoy listener.
type Options struct {
	// BindAddr is "address:port", e.g. "0.0.0.0:3389".
	BindAddr string
	// Hooks
	OnEvent func(DecoyEvent)
	Logger  *slog.Logger
}

// Listener is a running decoy RDP server.
type Listener struct {
	opts     Options
	listener net.Listener
	mu       sync.Mutex
	running  bool
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	logger   *slog.Logger
}

// New creates a new Listener.  Call Start to begin accepting connections.
func New(opts Options) *Listener {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Listener{opts: opts, logger: logger}
}

// Start begins accepting connections in the background.
func (l *Listener) Start(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.running {
		return nil
	}

	bind := l.opts.BindAddr
	if bind == "" {
		bind = "0.0.0.0:3389"
	}

	ln, err := net.Listen("tcp", bind)
	if err != nil {
		return err
	}
	l.listener = ln

	childCtx, cancel := context.WithCancel(ctx)
	l.cancel = cancel
	l.running = true

	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		l.accept(childCtx)
	}()

	l.logger.Info("decoy: listener started", "addr", bind)
	return nil
}

// Stop shuts down the listener and waits for in-flight connections.
func (l *Listener) Stop() {
	l.mu.Lock()
	if !l.running {
		l.mu.Unlock()
		return
	}
	l.running = false
	l.cancel()
	_ = l.listener.Close()
	l.mu.Unlock()
	l.wg.Wait()
	l.logger.Info("decoy: listener stopped")
}

// IsRunning reports whether the listener is active.
func (l *Listener) IsRunning() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.running
}

// ─────────────────────────────────────────────────────────────────────────────
// Accept loop
// ─────────────────────────────────────────────────────────────────────────────

func (l *Listener) accept(ctx context.Context) {
	for {
		conn, err := l.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				l.logger.Warn("decoy: accept error", "err", err)
				return
			}
		}
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			l.handle(conn)
		}()
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Connection handler
// ─────────────────────────────────────────────────────────────────────────────

// rdpConnReq is the RDP Connection Request PDU that starts a session.
// We respond with a Connection Confirm that advertises HYBRID (CredSSP/NLA)
// so the attacker sends NTLM material.
var rdpConnConfirm = []byte{
	// TPKT header: version=3, reserved=0, length=19 (big-endian uint16)
	0x03, 0x00, 0x00, 0x13,
	// X.224 Connection Confirm:
	// length indicator, CC PDU type (0xD0), dst ref, src ref, class
	0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
	// RDP Negotiation Response:
	// type=0x02 (RDP_NEG_RSP), flags=0x1F, length=0x0008, selectedProtocol=HYBRID(2)
	0x02, 0x1f, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
}

func (l *Listener) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	remoteAddr := conn.RemoteAddr().String()
	remoteIP, remotePort, _ := net.SplitHostPort(remoteAddr)

	// ── Step 1: read Connection Request ──────────────────────────────────────
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		// Still record the bare TCP knock.
		l.fireEvent(DecoyEvent{
			RemoteAddr: remoteAddr, RemoteIP: remoteIP, RemotePort: remotePort,
			Stage: "tcp",
		})
		return
	}
	raw := buf[:n]
	rawHex := hex.EncodeToString(raw[:min(len(raw), 64)])
	rdpCookie := extractRDPCookie(raw)

	// ── Step 2: send fake Connection Confirm (HYBRID) ────────────────────────
	if _, err := conn.Write(rdpConnConfirm); err != nil {
		l.fireEvent(DecoyEvent{
			RemoteAddr: remoteAddr, RemoteIP: remoteIP, RemotePort: remotePort,
			Stage: "rdp_neg", RDPCookie: rdpCookie, Raw: rawHex,
		})
		return
	}

	// ── Step 3: upgrade to TLS so CredSSP traffic flows ──────────────────────
	cert, err := selfSignedCert()
	if err != nil {
		l.logger.Warn("decoy: failed to generate cert", "err", err)
		return
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	tlsConn := tls.Server(conn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		// TLS handshake failed — attacker sent raw RDP without TLS.
		l.fireEvent(DecoyEvent{
			RemoteAddr: remoteAddr, RemoteIP: remoteIP, RemotePort: remotePort,
			Stage: "rdp_neg", RDPCookie: rdpCookie, Raw: rawHex,
		})
		return
	}
	defer tlsConn.Close()

	// Extract TLS details.
	cs := tlsConn.ConnectionState()
	tlsVersion := tlsVersionName(cs.Version)
	tlsCipher := tls.CipherSuiteName(cs.CipherSuite)

	// ── Step 4: read NTLM / CredSSP NTLM Negotiate ───────────────────────────
	_ = tlsConn.SetDeadline(time.Now().Add(8 * time.Second))
	nbuf := make([]byte, 4096)
	nn, err := tlsConn.Read(nbuf)
	ntlmUser, ntlmDomain, ntlmWorkstation, ntlmFlags := "", "", "", ""
	stage := "tls"
	if err == nil && nn > 0 {
		ntlmUser, ntlmDomain, ntlmWorkstation, ntlmFlags = parseNTLMNegotiateFull(nbuf[:nn])
		if ntlmUser != "" || ntlmDomain != "" || ntlmWorkstation != "" {
			stage = "ntlm"
		}
	}

	l.logger.Warn("decoy: attacker connection",
		"remote_ip", remoteIP,
		"remote_port", remotePort,
		"stage", stage,
		"tls_version", tlsVersion,
		"ntlm_user", ntlmUser,
		"ntlm_domain", ntlmDomain,
		"ntlm_workstation", ntlmWorkstation,
		"rdp_cookie", rdpCookie,
	)

	l.fireEvent(DecoyEvent{
		RemoteAddr:      remoteAddr,
		RemoteIP:        remoteIP,
		RemotePort:      remotePort,
		NTLMUsername:    ntlmUser,
		NTLMDomain:      ntlmDomain,
		NTLMWorkstation: ntlmWorkstation,
		NTLMFlags:       ntlmFlags,
		TLSVersion:      tlsVersion,
		TLSCipher:       tlsCipher,
		Stage:           stage,
		RDPCookie:       rdpCookie,
		Raw:             rawHex,
	})
}

func (l *Listener) fireEvent(ev DecoyEvent) {
	ev.At = time.Now().UTC()
	if l.opts.OnEvent != nil {
		l.opts.OnEvent(ev)
	}
}

// extractRDPCookie parses the mstshash=<cookie> from an X.224 Connection Request.
func extractRDPCookie(data []byte) string {
	s := string(data)
	const prefix = "mstshash="
	idx := strings.Index(s, prefix)
	if idx < 0 {
		return ""
	}
	rest := s[idx+len(prefix):]
	end := strings.IndexAny(rest, "\r\n\x00")
	if end < 0 {
		end = len(rest)
	}
	if end > 64 {
		end = 64
	}
	return strings.TrimSpace(rest[:end])
}

// tlsVersionName maps a TLS version uint16 to a human-readable string.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		if v != 0 {
			return fmt.Sprintf("0x%04x", v)
		}
		return ""
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// NTLM Negotiate parser
// ─────────────────────────────────────────────────────────────────────────────

// parseNTLMNegotiateFull extracts all available fields from an NTLM Type 1
// Negotiate message, which may be wrapped in a CredSSP/TSRequest ASN.1 blob.
//
//	Layout (Type 1):
//	  [0-7]   Signature "NTLMSSP\x00"
//	  [8-11]  MessageType = 1 (LE uint32)
//	  [12-15] NegotiateFlags (LE uint32)
//	  [16-23] DomainNameFields  (len uint16, maxLen uint16, offset uint32)
//	  [24-31] WorkstationFields (len uint16, maxLen uint16, offset uint32)
//	  ...optional strings at the indicated offsets
func parseNTLMNegotiateFull(data []byte) (domain, workstation, user, flags string) {
	sig := []byte("NTLMSSP\x00")
	idx := bytes.Index(data, sig)
	if idx < 0 {
		return
	}
	msg := data[idx:]
	if len(msg) < 32 {
		return
	}
	if binary.LittleEndian.Uint32(msg[8:12]) != 1 {
		return // only Type 1 Negotiate
	}

	rawFlags := binary.LittleEndian.Uint32(msg[12:16])
	flags = fmt.Sprintf("0x%08X", rawFlags)

	// DomainName fields at offset 16
	if len(msg) >= 24 {
		domLen := binary.LittleEndian.Uint16(msg[16:18])
		domOff := binary.LittleEndian.Uint32(msg[20:24])
		if domLen > 0 && int(domOff)+int(domLen) <= len(msg) {
			domain = decodeUTF16LE(msg[domOff : domOff+uint32(domLen)])
		}
	}
	// WorkstationName fields at offset 24
	if len(msg) >= 32 {
		wsLen := binary.LittleEndian.Uint16(msg[24:26])
		wsOff := binary.LittleEndian.Uint32(msg[28:32])
		if wsLen > 0 && int(wsOff)+int(wsLen) <= len(msg) {
			workstation = decodeUTF16LE(msg[wsOff : wsOff+uint32(wsLen)])
		}
	}
	// In Type 1 the username is typically absent; workstation is the machine name.
	// We expose workstation as "user" for backward compat with older callers.
	user = workstation
	return
}

func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	runes := make([]rune, len(b)/2)
	for i := range runes {
		runes[i] = rune(binary.LittleEndian.Uint16(b[i*2:]))
	}
	s := string(runes)
	return strings.TrimSpace(s)
}

// ─────────────────────────────────────────────────────────────────────────────
// Self-signed TLS certificate
// ─────────────────────────────────────────────────────────────────────────────

func selfSignedCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "RDPSHOT-DECOY",
			Organization: []string{"RDPShot Decoy"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
