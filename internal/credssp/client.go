package credssp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"rdpshot/internal/ntlm"
)

// NTSTATUS codes reported through TSRequest.errorCode (MS-ERREF 2.3).
const (
	StatusWrongPassword       uint32 = 0xC000006A
	StatusNoSuchUser          uint32 = 0xC0000064
	StatusAccountLockedOut    uint32 = 0xC0000234
	StatusAccountDisabled     uint32 = 0xC0000072
	StatusLogonTypeNotGranted uint32 = 0xC000015B
	StatusNotSupported        uint32 = 0xC00000BB
)

// NTStatusError reports that the peer terminated the CredSSP exchange with
// an NTSTATUS failure code (MS-CSSP 2.2.1.1 errorCode).
type NTStatusError struct {
	Code uint32
}

func (e *NTStatusError) Error() string {
	return fmt.Sprintf("credssp: server returned NTSTATUS 0x%08x", e.Code)
}

// ErrBindingMismatch reports that the peer failed the pubKeyAuth server
// verification (MS-CSSP 2.2.2.2 step 5). Callers treat it as an authentication
// failure class error.
var ErrBindingMismatch = errors.New("server binding verification failed")

// Binding-hash magic strings for CredSSP version 5+ (MS-CSSP 2.2.2.2). The
// trailing NUL is part of the hashed input.
var (
	ClientServerHashMagic = []byte("CredSSP Client-To-Server Binding Hash\x00")
	ServerClientHashMagic = []byte("CredSSP Server-To-Client Binding Hash\x00")
)

// maxTSRequestLen bounds a single TSRequest so a hostile peer cannot make the
// client buffer an unbounded message.
const maxTSRequestLen = 1 << 20

// Client performs the CredSSP handshake over an established TLS connection.
type Client struct {
	// Version is the highest CredSSP protocol version to offer (2..6).
	// Zero selects 6 (MS-CSSP 2.2.1.1).
	Version int
	// NTLMFlags are the NTLM NEGOTIATE flags offered to the server. Zero
	// selects ntlm.DefaultNegotiateFlags.
	NTLMFlags uint32
	// Domain is the fallback account domain when the call passes an empty one.
	Domain string
}

// Handshake runs the CredSSP client exchange over conn, which must already
// carry an established TLS session (MS-CSSP 3.1.5 message flow):
//
//  1. TSRequest with the SPNEGO-wrapped NTLM NEGOTIATE message.
//  2. Server TSRequest with the NTLM CHALLENGE (errorCode checked).
//  3. TSRequest with the SPNEGO-wrapped NTLM AUTHENTICATE message and the
//     sealed pubKeyAuth binding.
//  4. Server TSRequest whose pubKeyAuth proves possession of the TLS keying
//     material (errorCode checked).
//
// The final MS-CSSP step (TSRequest with sealed TSCredentials) is a
// credential-delegation step and is intentionally not performed: this client
// only verifies the credential, it does not open a remote session.
//
// ctx cancellation is honored between protocol steps; the caller controls
// per-I/O deadlines on conn.
func (c *Client) Handshake(ctx context.Context, conn net.Conn, user, password, domain string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return fmt.Errorf("credssp: handshake requires a TLS connection")
	}
	serverPublicKey, err := serverSubjectPublicKey(tlsConn)
	if err != nil {
		return err
	}

	version := c.version()
	flags := c.ntlmFlags()
	if domain == "" {
		domain = c.Domain
	}

	// Step 1: client NEGOTIATE.
	negotiate, err := ntlm.NegotiateMessage{Flags: flags}.Marshal()
	if err != nil {
		return fmt.Errorf("credssp: build NTLM NEGOTIATE: %w", err)
	}
	negoInit, err := WrapNegTokenInit(negotiate)
	if err != nil {
		return err
	}
	if err := writeTSRequest(conn, TSRequest{Version: version, NegoTokens: [][]byte{negoInit}}); err != nil {
		return err
	}

	// Step 2: server CHALLENGE.
	resp, err := readTSRequest(ctx, conn)
	if err != nil {
		return err
	}
	if resp.ErrorCode != nil {
		return &NTStatusError{Code: *resp.ErrorCode}
	}
	challengeToken, err := firstNTLMToken(resp.NegoTokens)
	if err != nil {
		return err
	}
	challenge, err := ntlm.ParseChallenge(challengeToken)
	if err != nil {
		return fmt.Errorf("credssp: parse NTLM CHALLENGE: %w", err)
	}

	// Step 3: NTLM AUTHENTICATE plus the public key binding.
	timestamp := challengeTimestamp(challenge.TargetInfo)
	clientChallenge := make([]byte, ntlm.ClientChallengeLen)
	if _, err := rand.Read(clientChallenge); err != nil {
		return fmt.Errorf("credssp: generate client challenge: %w", err)
	}
	const workstation = ""
	authMsg, baseKey, err := ntlm.BuildAuthenticate(flags, domain, user, password, workstation,
		challenge.ServerChallenge, challenge.TargetInfo, timestamp, clientChallenge)
	if err != nil {
		return fmt.Errorf("credssp: build NTLM AUTHENTICATE: %w", err)
	}
	authDER, err := authMsg.Marshal()
	if err != nil {
		return fmt.Errorf("credssp: marshal NTLM AUTHENTICATE: %w", err)
	}
	negoResp, err := WrapNegTokenResp(authDER)
	if err != nil {
		return err
	}

	security := ntlm.NewSessionSecurity(baseKey, flags, true)
	negotiated := minVersion(version, resp.Version)

	request := TSRequest{Version: version, NegoTokens: [][]byte{negoResp}}
	switch {
	case negotiated >= 5:
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return fmt.Errorf("credssp: generate binding nonce: %w", err)
		}
		request.ClientNonce = nonce
		request.PubKeyAuth, err = pubKeyAuthV5(security, ClientServerHashMagic, nonce, serverPublicKey)
		if err != nil {
			return err
		}
	default:
		request.PubKeyAuth, err = pubKeyAuthV2(security, serverPublicKey)
		if err != nil {
			return err
		}
	}
	if err := writeTSRequest(conn, request); err != nil {
		return err
	}

	// Step 4: server proves possession of the TLS keying material.
	final, err := readTSRequest(ctx, conn)
	if err != nil {
		return err
	}
	if final.ErrorCode != nil {
		return &NTStatusError{Code: *final.ErrorCode}
	}
	if final.Version != resp.Version {
		return fmt.Errorf("credssp: server changed version from %d to %d", resp.Version, final.Version)
	}
	if len(final.PubKeyAuth) == 0 {
		return fmt.Errorf("credssp: server did not return a pubKeyAuth binding")
	}
	if negotiated >= 5 {
		want := bindingHash(ServerClientHashMagic, request.ClientNonce, serverPublicKey)
		return verifyServerBinding(security, final.PubKeyAuth, want)
	}
	return verifyServerKeyEcho(security, final.PubKeyAuth, serverPublicKey)
}

func (c *Client) version() int {
	if c.Version == 0 {
		return 6
	}
	return c.Version
}

func (c *Client) ntlmFlags() uint32 {
	if c.NTLMFlags == 0 {
		return ntlm.DefaultNegotiateFlags
	}
	return c.NTLMFlags
}

// pubKeyAuthV2 computes the CredSSP <= 4 public key binding: the server's
// SubjectPublicKey sealed with the NTLM session security (MS-CSSP 2.2.2.2,
// "Version 2, 3, 4").
func pubKeyAuthV2(security *ntlm.SessionSecurity, serverPublicKey []byte) ([]byte, error) {
	if len(serverPublicKey) == 0 {
		return nil, fmt.Errorf("credssp: empty server public key")
	}
	return security.Seal(serverPublicKey), nil
}

// pubKeyAuthV5 computes the CredSSP >= 5 hash binding:
//
//	pubKeyAuth = Seal(SHA256(magic || nonce || SubjectPublicKey))
//
// where magic is "CredSSP Client-To-Server Binding Hash" including its NUL
// terminator and nonce is the 32-byte clientNonce (MS-CSSP 2.2.2.2,
// "Version 5 or 6"). magic selects the direction-specific constant.
func pubKeyAuthV5(security *ntlm.SessionSecurity, magic, nonce, serverPublicKey []byte) ([]byte, error) {
	if len(nonce) != 32 {
		return nil, fmt.Errorf("credssp: binding nonce must be 32 bytes, got %d", len(nonce))
	}
	if len(serverPublicKey) == 0 {
		return nil, fmt.Errorf("credssp: empty server public key")
	}
	return security.Seal(bindingHash(magic, nonce, serverPublicKey)), nil
}

// bindingHash computes the CredSSP 5+ binding hash over the direction magic,
// the nonce and the server SubjectPublicKey (MS-CSSP 2.2.2.2).
func bindingHash(magic, nonce, serverPublicKey []byte) []byte {
	h := sha256.New()
	h.Write(magic)
	h.Write(nonce)
	h.Write(serverPublicKey)
	return h.Sum(nil)
}

// verifyServerBinding decrypts the server's pubKeyAuth and compares it to the
// expected server-to-client binding hash.
func verifyServerBinding(security *ntlm.SessionSecurity, sealed, want []byte) error {
	got, err := security.Unseal(sealed)
	if err != nil {
		return fmt.Errorf("%w: unseal server pubKeyAuth: %v", ErrBindingMismatch, err)
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("%w: server binding hash mismatch", ErrBindingMismatch)
	}
	return nil
}

// verifyServerKeyEcho decrypts the CredSSP <= 4 server pubKeyAuth and checks
// it against the server's public key with one added to its first byte, the
// anti-replay modification from MS-CSSP 2.2.2.2 ("Version 2, 3, and 4").
// The whole-integer increment used by some implementations is accepted too;
// the two differ only on a 0xFF carry.
func verifyServerKeyEcho(security *ntlm.SessionSecurity, sealed, serverPublicKey []byte) error {
	got, err := security.Unseal(sealed)
	if err != nil {
		return fmt.Errorf("%w: unseal server pubKeyAuth: %v", ErrBindingMismatch, err)
	}
	if bytes.Equal(got, incrementFirstByte(serverPublicKey)) ||
		bytes.Equal(got, incrementLEInteger(serverPublicKey)) {
		return nil
	}
	return fmt.Errorf("%w: server public key echo mismatch", ErrBindingMismatch)
}

func incrementFirstByte(key []byte) []byte {
	out := append([]byte(nil), key...)
	if len(out) > 0 {
		out[0]++
	}
	return out
}

func incrementLEInteger(key []byte) []byte {
	out := append([]byte(nil), key...)
	for i := range out {
		out[i]++
		if out[i] != 0 {
			break
		}
	}
	return out
}

// serverSubjectPublicKey extracts the ASN.1-encoded SubjectPublicKey (the
// subjectPublicKey BIT STRING content of SubjectPublicKeyInfo, RFC 3280 4.1)
// from the peer TLS certificate. This is the value CredSSP binds to
// (MS-CSSP 2.2.2.2).
func serverSubjectPublicKey(conn *tls.Conn) ([]byte, error) {
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("credssp: TLS peer presented no certificate")
	}
	return subjectPublicKeyFromSPKI(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
}

// subjectPublicKeyFromSPKI extracts the subjectPublicKey BIT STRING content
// from a DER SubjectPublicKeyInfo structure.
func subjectPublicKeyFromSPKI(rawSPKI []byte) ([]byte, error) {
	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	rest, err := asn1.Unmarshal(rawSPKI, &spki)
	if err != nil {
		return nil, fmt.Errorf("credssp: parse SubjectPublicKeyInfo: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("credssp: trailing bytes after SubjectPublicKeyInfo")
	}
	if len(spki.SubjectPublicKey.Bytes) == 0 {
		return nil, fmt.Errorf("credssp: empty SubjectPublicKey")
	}
	return spki.SubjectPublicKey.Bytes, nil
}

// challengeTimestamp returns the timestamp to place in the NTLMv2 blob: the
// MsvAvTimestamp AV pair from the server target info when present (it must be
// echoed verbatim), otherwise the current time as FILETIME (MS-NLMP 2.2.1.3.1).
func challengeTimestamp(targetInfo []byte) []byte {
	if pairs, err := ntlm.ParseAVPairs(targetInfo); err == nil {
		for _, p := range pairs {
			if p.ID == ntlm.MsvAvTimestamp && len(p.Data) == ntlm.TimestampLen {
				return append([]byte(nil), p.Data...)
			}
		}
	}
	return filetimeNow()
}

// filetimeNow returns the current time as an 8-byte FILETIME value.
func filetimeNow() []byte {
	const ticksPerSecond = 10000000
	const epochDiff = 11644473600
	ft := make([]byte, 8)
	now := time.Now()
	binary.LittleEndian.PutUint64(ft, uint64(now.Unix()+epochDiff)*ticksPerSecond+
		uint64(now.Nanosecond()/100))
	return ft
}

// firstNTLMToken returns the first SPNEGO payload holding an NTLM message.
func firstNTLMToken(tokens [][]byte) ([]byte, error) {
	for _, wrapped := range tokens {
		token, err := UnwrapSPNEGO(wrapped)
		if err != nil {
			continue
		}
		if len(token) >= 8 && string(token[:8]) == "NTLMSSP\x00" {
			return token, nil
		}
	}
	return nil, fmt.Errorf("credssp: no NTLM token in server TSRequest")
}

// writeTSRequest writes one DER-encoded TSRequest to conn. The TSRequest is
// framed by its own DER length (MS-CSSP 3.1.5 step 1 note; no extra header).
func writeTSRequest(conn net.Conn, r TSRequest) error {
	der, err := r.Marshal()
	if err != nil {
		return err
	}
	if _, err := conn.Write(der); err != nil {
		return fmt.Errorf("credssp: write TSRequest: %w", err)
	}
	return nil
}

// readTSRequest reads one DER-length-framed TSRequest from conn. ctx is
// checked before the read; the caller owns conn deadlines.
func readTSRequest(ctx context.Context, conn net.Conn) (*TSRequest, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("credssp: read TSRequest header: %w", err)
	}
	if header[0] != 0x30 {
		return nil, fmt.Errorf("credssp: TSRequest does not start with a DER SEQUENCE")
	}

	contentLen := 0
	lengthBytes := 0
	if header[1]&0x80 == 0 {
		contentLen = int(header[1])
	} else {
		var err error
		lengthBytes, err = longFormLengthBytes(header[1])
		if err != nil {
			return nil, err
		}
		lengthBuf := make([]byte, lengthBytes)
		if _, err := io.ReadFull(conn, lengthBuf); err != nil {
			return nil, fmt.Errorf("credssp: read TSRequest length: %w", err)
		}
		for _, b := range lengthBuf {
			contentLen = contentLen<<8 | int(b)
		}
		header = append(header, lengthBuf...)
	}

	total := 2 + lengthBytes + contentLen
	if total > maxTSRequestLen {
		return nil, fmt.Errorf("credssp: TSRequest length %d exceeds limit %d", total, maxTSRequestLen)
	}
	der := make([]byte, total)
	copy(der, header)
	if contentLen > 0 {
		if _, err := io.ReadFull(conn, der[2+lengthBytes:]); err != nil {
			return nil, fmt.Errorf("credssp: read TSRequest body: %w", err)
		}
	}
	return ParseTSRequest(der)
}

// longFormLengthBytes reports how many length bytes follow the first DER
// length byte. Indefinite lengths and over-long encodings are rejected.
func longFormLengthBytes(first byte) (int, error) {
	if first&0x80 == 0 {
		return 0, nil
	}
	n := int(first & 0x7f)
	if n == 0 || n > 4 {
		return 0, fmt.Errorf("credssp: unsupported DER length encoding 0x%02x", first)
	}
	return n, nil
}

// minVersion returns the lower of the two CredSSP versions; a non-positive
// peer version is treated as the client's own.
func minVersion(client, server int) int {
	if server <= 0 {
		return client
	}
	if server < client {
		return server
	}
	return client
}
