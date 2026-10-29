package auth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"rdpshot/internal/credssp"
	"rdpshot/internal/model"
	"rdpshot/internal/ntlm"
	"rdpshot/internal/rdp"
)

// fakeServerScript configures the scripted RDP/CredSSP responder.
type fakeServerScript struct {
	// selectedProtocol is the protocol in RDP_NEG_RSP.
	selectedProtocol uint32
	// failureCode, when set, makes the server answer RDP_NEG_FAILURE instead.
	failureCode *uint32
	// credSSP controls whether the NLA exchange is served after negotiation.
	credSSP bool
	// failWith is the NTSTATUS answered after the NTLM CHALLENGE (0 = success).
	failWith uint32
	user     string
	password string
	domain   string
}

// startFakeServer runs the scripted responder and returns its address and the
// server-side outcome channel.
func startFakeServer(t *testing.T, script fakeServerScript) (string, chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		done <- serveFakeServer(conn, script)
	}()
	return listener.Addr().String(), done
}

// serveFakeServer speaks the X.224 negotiation and, when scripted, the
// CredSSP exchange on one connection.
func serveFakeServer(conn net.Conn, script fakeServerScript) error {
	if _, err := rdp.ReadTPKT(conn); err != nil {
		return fmt.Errorf("server: read connection request: %w", err)
	}
	confirm := make([]byte, 8)
	binary.LittleEndian.PutUint16(confirm[2:], 8)
	switch {
	case script.failureCode != nil:
		confirm[0] = 0x03 // RDP_NEG_FAILURE
		binary.LittleEndian.PutUint32(confirm[4:], *script.failureCode)
	default:
		confirm[0] = 0x02 // RDP_NEG_RSP
		binary.LittleEndian.PutUint32(confirm[4:], script.selectedProtocol)
	}
	tpdu := append([]byte{14, 0xD0, 0, 0, 0, 0, 0}, confirm...)
	if err := rdp.WriteTPKT(conn, tpdu); err != nil {
		return fmt.Errorf("server: write connection confirm: %w", err)
	}
	if script.failureCode != nil || !script.credSSP {
		return nil
	}

	cert, err := newTestCert()
	if err != nil {
		return err
	}
	tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert.certificate}})
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("server: TLS handshake: %w", err)
	}
	return serveCredSSP(tlsConn, cert.leaf, script)
}

// testCert is a self-signed ECDSA certificate for the fake TLS server.
type testCert struct {
	certificate tls.Certificate
	leaf        *x509.Certificate
}

func newTestCert() (*testCert, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rdpshot-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &testCert{
		certificate: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf},
		leaf:        leaf,
	}, nil
}

// serveCredSSP implements the minimal CredSSP responder: NTLM CHALLENGE and
// then either an NTSTATUS failure or the pubKeyAuth server binding.
func serveCredSSP(conn net.Conn, cert *x509.Certificate, script fakeServerScript) error {
	serverKey, err := subjectPublicKeyFromSPKI(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return fmt.Errorf("server: %w", err)
	}
	req, err := readTSRequest(conn)
	if err != nil {
		return fmt.Errorf("server: read NEGOTIATE request: %w", err)
	}
	if len(req.NegoTokens) == 0 {
		return errors.New("server: client sent no negoTokens")
	}
	if _, err := credssp.UnwrapSPNEGO(req.NegoTokens[0]); err != nil {
		return fmt.Errorf("server: unwrap NEGOTIATE: %w", err)
	}

	var serverChallenge [8]byte
	copy(serverChallenge[:], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	timestamp := filetimeFromUnix(1700000000)
	targetInfo := ntlm.MarshalAVPairs([]ntlm.AVPair{
		{ID: ntlm.MsvAvNbDomainName, Data: utf16LE(script.domain)},
		{ID: ntlm.MsvAvTimestamp, Data: timestamp},
	})
	challengeDER, err := ntlm.ChallengeMessage{
		Flags:           ntlm.DefaultNegotiateFlags,
		ServerChallenge: serverChallenge,
		TargetName:      script.domain,
		TargetInfo:      targetInfo,
	}.Marshal()
	if err != nil {
		return fmt.Errorf("server: marshal CHALLENGE: %w", err)
	}
	challengeToken, err := credssp.WrapNegTokenResp(challengeDER)
	if err != nil {
		return fmt.Errorf("server: wrap CHALLENGE: %w", err)
	}
	if err := writeTSRequest(conn, credssp.TSRequest{Version: 6, NegoTokens: [][]byte{challengeToken}}); err != nil {
		return fmt.Errorf("server: send CHALLENGE: %w", err)
	}

	req, err = readTSRequest(conn)
	if err != nil {
		return fmt.Errorf("server: read AUTHENTICATE request: %w", err)
	}
	if script.failWith != 0 {
		code := script.failWith
		return writeTSRequest(conn, credssp.TSRequest{Version: 6, ErrorCode: &code})
	}

	authn, err := credssp.UnwrapSPNEGO(req.NegoTokens[0])
	if err != nil {
		return fmt.Errorf("server: unwrap AUTHENTICATE: %w", err)
	}
	authMsg, err := ntlm.ParseAuthenticate(authn)
	if err != nil {
		return fmt.Errorf("server: parse AUTHENTICATE: %w", err)
	}
	baseKey, err := verifyNTLMv2(script, authMsg, serverChallenge)
	if err != nil {
		return err
	}
	security := ntlm.NewSessionSecurity(baseKey, ntlm.DefaultNegotiateFlags, false)
	if len(req.ClientNonce) != 32 {
		return fmt.Errorf("server: clientNonce length %d, want 32", len(req.ClientNonce))
	}
	want := bindingHash(credssp.ClientServerHashMagic, req.ClientNonce, serverKey)
	got, err := security.Unseal(req.PubKeyAuth)
	if err != nil {
		return fmt.Errorf("server: unseal client pubKeyAuth: %w", err)
	}
	if !bytes.Equal(got, want) {
		return errors.New("server: client binding hash mismatch")
	}
	response := credssp.TSRequest{
		Version:    6,
		PubKeyAuth: security.Seal(bindingHash(credssp.ServerClientHashMagic, req.ClientNonce, serverKey)),
	}
	return writeTSRequest(conn, response)
}

// verifyNTLMv2 checks the NTLMv2 proof and returns the session base key.
func verifyNTLMv2(script fakeServerScript, authMsg *ntlm.AuthenticateMessage, serverChallenge [8]byte) ([]byte, error) {
	if authMsg.User != script.user || authMsg.Domain != script.domain {
		return nil, fmt.Errorf("server: identity %q/%q, want %q/%q",
			authMsg.User, authMsg.Domain, script.user, script.domain)
	}
	if len(authMsg.NTChallengeResponse) < 16 {
		return nil, errors.New("server: NT response too short")
	}
	ntLMv2Hash := ntlm.NTLMv2Hash(script.user, script.domain, ntlm.NTHash(script.password))
	blob := authMsg.NTChallengeResponse[16:]
	proof := hmacMD5(ntLMv2Hash, serverChallenge[:], blob)
	if !bytes.Equal(authMsg.NTChallengeResponse[:16], proof) {
		return nil, errors.New("server: NTProofStr mismatch")
	}
	return hmacMD5(ntLMv2Hash, proof), nil
}

func hmacMD5(key []byte, parts ...[]byte) []byte {
	mac := hmac.New(md5.New, key)
	for _, p := range parts {
		mac.Write(p)
	}
	return mac.Sum(nil)
}

// bindingHash mirrors the CredSSP 5+ binding hash used by the server side:
// SHA256(magic || nonce || SubjectPublicKey).
func bindingHash(magic, nonce, key []byte) []byte {
	h := sha256.New()
	h.Write(magic)
	h.Write(nonce)
	h.Write(key)
	return h.Sum(nil)
}

// subjectPublicKeyFromSPKI extracts the subjectPublicKey BIT STRING content
// from a DER SubjectPublicKeyInfo (the CredSSP binding target).
func subjectPublicKeyFromSPKI(rawSPKI []byte) ([]byte, error) {
	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	rest, err := asn1.Unmarshal(rawSPKI, &spki)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 || len(spki.SubjectPublicKey.Bytes) == 0 {
		return nil, errors.New("invalid SubjectPublicKeyInfo")
	}
	return spki.SubjectPublicKey.Bytes, nil
}

func utf16LE(s string) []byte {
	var out []byte
	for _, r := range s {
		if r > 0xFFFF {
			r = '?'
		}
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

func filetimeFromUnix(sec int64) []byte {
	const ticksPerSecond = 10000000
	const epochDiff = 11644473600
	out := make([]byte, 8)
	v := uint64(sec+epochDiff) * ticksPerSecond
	for i := 0; i < 8; i++ {
		out[i] = byte(v >> (8 * i))
	}
	return out
}

// readTSRequest reads one DER-length-framed TSRequest from conn.
func readTSRequest(conn net.Conn) (*credssp.TSRequest, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	if header[0] != 0x30 {
		return nil, fmt.Errorf("not a DER SEQUENCE")
	}
	contentLen := 0
	lengthBytes := 0
	if header[1]&0x80 == 0 {
		contentLen = int(header[1])
	} else {
		lengthBytes = int(header[1] & 0x7f)
		if lengthBytes == 0 || lengthBytes > 4 {
			return nil, fmt.Errorf("unsupported DER length 0x%02x", header[1])
		}
		lengthBuf := make([]byte, lengthBytes)
		if _, err := io.ReadFull(conn, lengthBuf); err != nil {
			return nil, err
		}
		for _, b := range lengthBuf {
			contentLen = contentLen<<8 | int(b)
		}
		header = append(header, lengthBuf...)
	}
	der := make([]byte, 2+lengthBytes+contentLen)
	copy(der, header)
	if contentLen > 0 {
		if _, err := io.ReadFull(conn, der[2+lengthBytes:]); err != nil {
			return nil, err
		}
	}
	return credssp.ParseTSRequest(der)
}

func writeTSRequest(conn net.Conn, r credssp.TSRequest) error {
	der, err := r.Marshal()
	if err != nil {
		return err
	}
	_, err = conn.Write(der)
	return err
}

func testEndpoint(addr string) model.Endpoint {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		panic(err)
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		panic(err)
	}
	return model.Endpoint{Address: host, Port: uint16(p)}
}

func TestAuthenticateNegFailure(t *testing.T) {
	code := rdp.FailureHybridRequiredByServer
	addr, done := startFakeServer(t, fakeServerScript{failureCode: &code})

	err := NewCredSSPAuthenticator(5*time.Second).Authenticate(
		context.Background(), testEndpoint(addr), model.Credential{Username: "u", Secret: "p"})
	if !errors.Is(err, ErrNLARequired) {
		t.Fatalf("error = %v, want ErrNLARequired", err)
	}
	if !strings.Contains(err.Error(), "HYBRID_REQUIRED_BY_SERVER") {
		t.Fatalf("error = %v, want failure code text", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestAuthenticateTLSWithoutNLA(t *testing.T) {
	addr, done := startFakeServer(t, fakeServerScript{selectedProtocol: rdp.ProtocolSSL})

	err := NewCredSSPAuthenticator(5*time.Second).Authenticate(
		context.Background(), testEndpoint(addr), model.Credential{Username: "u", Secret: "p"})
	if !errors.Is(err, ErrNLARequired) {
		t.Fatalf("error = %v, want ErrNLARequired", err)
	}
	if !strings.Contains(err.Error(), "TLS without NLA") {
		t.Fatalf("error = %v, want TLS-without-NLA explanation", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestAuthenticateStandardRDP(t *testing.T) {
	addr, done := startFakeServer(t, fakeServerScript{selectedProtocol: rdp.ProtocolRDP})

	err := NewCredSSPAuthenticator(5*time.Second).Authenticate(
		context.Background(), testEndpoint(addr), model.Credential{Username: "u", Secret: "p"})
	if !errors.Is(err, ErrNLARequired) {
		t.Fatalf("error = %v, want ErrNLARequired", err)
	}
	if !strings.Contains(err.Error(), "standard RDP security") {
		t.Fatalf("error = %v, want standard-RDP explanation", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestAuthenticateWrongPassword(t *testing.T) {
	script := fakeServerScript{
		selectedProtocol: rdp.ProtocolHybrid, credSSP: true,
		failWith: credssp.StatusWrongPassword,
		user:     "User", password: "Password", domain: "Domain",
	}
	addr, done := startFakeServer(t, script)

	cred := model.Credential{Username: "User", Secret: "WrongPassword", Domain: "Domain"}
	err := NewCredSSPAuthenticator(5*time.Second).Authenticate(context.Background(), testEndpoint(addr), cred)
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("error = %v, want ErrAuthFailed", err)
	}
	if !strings.Contains(err.Error(), "0xc000006a") {
		t.Fatalf("error = %v, want NTSTATUS hex", err)
	}
	if strings.Contains(err.Error(), cred.Secret) {
		t.Fatal("error message must not contain the secret")
	}
	if err := <-done; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestAuthenticateAccountLocked(t *testing.T) {
	script := fakeServerScript{
		selectedProtocol: rdp.ProtocolHybrid, credSSP: true,
		failWith: credssp.StatusAccountLockedOut,
		user:     "User", password: "Password", domain: "Domain",
	}
	addr, done := startFakeServer(t, script)

	err := NewCredSSPAuthenticator(5*time.Second).Authenticate(
		context.Background(), testEndpoint(addr), model.Credential{Username: "User", Secret: "Password", Domain: "Domain"})
	if !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("error = %v, want ErrAccountLocked", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestAuthenticateSuccess(t *testing.T) {
	for _, protocol := range []uint32{rdp.ProtocolHybrid, rdp.ProtocolHybridEx} {
		script := fakeServerScript{
			selectedProtocol: protocol, credSSP: true,
			user: "User", password: "Password", domain: "Domain",
		}
		addr, done := startFakeServer(t, script)

		err := NewCredSSPAuthenticator(5*time.Second).Authenticate(
			context.Background(), testEndpoint(addr), model.Credential{Username: "User", Secret: "Password", Domain: "Domain"})
		if err != nil {
			t.Fatalf("protocol 0x%x: %v", protocol, err)
		}
		if err := <-done; err != nil {
			t.Fatalf("server: %v", err)
		}
	}
}

func TestAuthenticateContextCancellation(t *testing.T) {
	// The server accepts and stalls; cancellation must interrupt the exchange.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(2 * time.Second)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	err = NewCredSSPAuthenticator(30*time.Second).Authenticate(
		ctx, testEndpoint(listener.Addr().String()), model.Credential{Username: "u", Secret: "p"})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("error = %v, want ErrTimeout", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestAuthenticateDialFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close() // now nothing listens there

	err = NewCredSSPAuthenticator(2*time.Second).Authenticate(
		context.Background(), testEndpoint(addr), model.Credential{Username: "u", Secret: "p"})
	if !errors.Is(err, ErrNetwork) {
		t.Fatalf("error = %v, want ErrNetwork", err)
	}
}

func TestMapNTStatus(t *testing.T) {
	cases := []struct {
		code uint32
		want error
	}{
		{credssp.StatusWrongPassword, ErrAuthFailed},
		{credssp.StatusNoSuchUser, ErrAuthFailed},
		{credssp.StatusLogonTypeNotGranted, ErrAuthFailed},
		{credssp.StatusAccountLockedOut, ErrAccountLocked},
		{credssp.StatusAccountDisabled, ErrAccountLocked},
		{credssp.StatusNotSupported, ErrProtocol},
		{0xC0000001, ErrAuthFailed}, // unknown rejections classify as failures
	}
	for _, c := range cases {
		err := mapNTStatus(c.code)
		if !errors.Is(err, c.want) {
			t.Errorf("mapNTStatus(0x%08x) = %v, want %v", c.code, err, c.want)
		}
		if !strings.Contains(err.Error(), fmt.Sprintf("0x%08x", c.code)) {
			t.Errorf("mapNTStatus(0x%08x) = %v, want NTSTATUS hex in message", c.code, err)
		}
	}
}
