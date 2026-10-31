package credssp

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
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"rdpshot/internal/ntlm"
)

// newTestCert creates a self-signed ECDSA certificate for the fake TLS server.
func newTestCert(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
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
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf
}

// fakeServerScript drives the server side of the CredSSP exchange.
type fakeServerScript struct {
	version     int    // TSRequest version to advertise
	failWith    uint32 // NTSTATUS to answer with after the CHALLENGE (0 = continue)
	corruptBind bool   // seal a wrong server binding to test verification
	changeVer   bool   // change the version in the final TSRequest
	user        string
	password    string
	domain      string
}

// runFakeServer implements a minimal CredSSP responder: NTLM CHALLENGE, then
// either an NTSTATUS failure or the server pubKeyAuth binding. It reports
// problems through its return value so nothing races test completion.
func runFakeServer(conn net.Conn, cert *x509.Certificate, script fakeServerScript) error {
	ctx := context.Background()
	serverKey, err := subjectPublicKeyFromSPKI(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return fmt.Errorf("server: %w", err)
	}

	req, err := readTSRequest(ctx, conn)
	if err != nil {
		return fmt.Errorf("server: read NEGOTIATE request: %w", err)
	}
	if len(req.NegoTokens) == 0 {
		return errors.New("server: client sent no negoTokens")
	}
	negotiate, err := UnwrapSPNEGO(req.NegoTokens[0])
	if err != nil {
		return fmt.Errorf("server: unwrap NEGOTIATE: %w", err)
	}
	if _, err := ntlm.ParseNegotiate(negotiate); err != nil {
		return fmt.Errorf("server: parse NEGOTIATE: %w", err)
	}

	var serverChallenge [8]byte
	copy(serverChallenge[:], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	timestamp := filetimeFromUnixTest(1700000000)
	targetInfo := ntlm.MarshalAVPairs([]ntlm.AVPair{
		{ID: ntlm.MsvAvNbDomainName, Data: testUTF16(script.domain)},
		{ID: ntlm.MsvAvTimestamp, Data: timestamp},
		{ID: ntlm.MsvAvNbComputerName, Data: testUTF16("FAKESERVER")},
	})
	challenge := ntlm.ChallengeMessage{
		Flags:           ntlm.DefaultNegotiateFlags,
		ServerChallenge: serverChallenge,
		TargetName:      script.domain,
		TargetInfo:      targetInfo,
	}
	challengeDER, err := challenge.Marshal()
	if err != nil {
		return fmt.Errorf("server: marshal CHALLENGE: %w", err)
	}
	challengeToken, err := WrapNegTokenResp(challengeDER)
	if err != nil {
		return fmt.Errorf("server: wrap CHALLENGE: %w", err)
	}
	if err := writeTSRequest(conn, TSRequest{Version: script.version, NegoTokens: [][]byte{challengeToken}}); err != nil {
		return fmt.Errorf("server: send CHALLENGE: %w", err)
	}

	req, err = readTSRequest(ctx, conn)
	if err != nil {
		return fmt.Errorf("server: read AUTHENTICATE request: %w", err)
	}
	if script.failWith != 0 {
		code := script.failWith
		if err := writeTSRequest(conn, TSRequest{Version: script.version, ErrorCode: &code}); err != nil {
			return fmt.Errorf("server: send errorCode: %w", err)
		}
		return nil
	}

	if len(req.NegoTokens) == 0 {
		return errors.New("server: client sent no AUTHENTICATE token")
	}
	authn, err := UnwrapSPNEGO(req.NegoTokens[0])
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
	exported := baseKey
	if authMsg.Flags&ntlm.NEGOTIATE_KEY_EXCH != 0 && len(authMsg.EncryptedRandomSessionKey) > 0 {
		exported = ntlm.UnwrapExportedSessionKey(baseKey, authMsg.EncryptedRandomSessionKey)
	}
	security := ntlm.NewSessionSecurity(exported, ntlm.DefaultNegotiateFlags, false)

	response := TSRequest{Version: script.version}
	if script.changeVer {
		response.Version = script.version + 1
	}
	switch {
	case script.version >= 5:
		if len(req.ClientNonce) != 32 {
			return fmt.Errorf("server: clientNonce length %d, want 32", len(req.ClientNonce))
		}
		want := bindingHash(ClientServerHashMagic, req.ClientNonce, serverKey)
		got, err := security.Unseal(req.PubKeyAuth)
		if err != nil {
			return fmt.Errorf("server: unseal client pubKeyAuth: %w", err)
		}
		if !bytes.Equal(got, want) {
			return errors.New("server: client binding hash mismatch")
		}
		magic := ServerClientHashMagic
		if script.corruptBind {
			magic = []byte("corrupted")
		}
		response.PubKeyAuth = security.Seal(bindingHash(magic, req.ClientNonce, serverKey))
	default:
		got, err := security.Unseal(req.PubKeyAuth)
		if err != nil {
			return fmt.Errorf("server: unseal client pubKeyAuth: %w", err)
		}
		if !bytes.Equal(got, serverKey) {
			return errors.New("server: client public key binding mismatch")
		}
		echo := incrementFirstByte(serverKey)
		if script.corruptBind {
			echo = append([]byte(nil), serverKey...)
		}
		response.PubKeyAuth = security.Seal(echo)
	}
	if err := writeTSRequest(conn, response); err != nil {
		return fmt.Errorf("server: send pubKeyAuth: %w", err)
	}
	return nil
}

// verifyNTLMv2 checks the NTLMv2 proof of the AUTHENTICATE message and
// returns the session base key.
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
	proof := hmacMD5Test(ntLMv2Hash, serverChallenge[:], blob)
	if !bytes.Equal(authMsg.NTChallengeResponse[:16], proof) {
		return nil, errors.New("server: NTProofStr mismatch")
	}
	return hmacMD5Test(ntLMv2Hash, proof), nil
}

func hmacMD5Test(key []byte, parts ...[]byte) []byte {
	mac := hmac.New(md5.New, key)
	for _, p := range parts {
		mac.Write(p)
	}
	return mac.Sum(nil)
}

func testUTF16(s string) []byte {
	var out []byte
	for _, r := range s {
		if r > 0xFFFF {
			r = '?'
		}
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

func filetimeFromUnixTest(sec int64) []byte {
	const ticksPerSecond = 10000000
	const epochDiff = 11644473600
	out := make([]byte, 8)
	v := uint64(sec+epochDiff) * ticksPerSecond
	for i := 0; i < 8; i++ {
		out[i] = byte(v >> (8 * i))
	}
	return out
}

// startFakeServer runs the scripted responder on a local TLS listener and
// returns its address plus a channel carrying the server-side outcome.
func startFakeServer(t *testing.T, cert tls.Certificate, leaf *x509.Certificate, script fakeServerScript) (string, chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	done := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		conn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}})
		defer conn.Close()
		if err := conn.Handshake(); err != nil {
			done <- fmt.Errorf("server TLS handshake: %w", err)
			return
		}
		done <- runFakeServer(conn, leaf, script)
	}()
	return listener.Addr().String(), done
}

func dialTLS(t *testing.T, addr string) *tls.Conn {
	t.Helper()
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true}) // test-only: self-signed fake server
	if err := conn.Handshake(); err != nil {
		raw.Close()
		t.Fatalf("client TLS handshake: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func TestHandshakeSuccessVersion6(t *testing.T) {
	cert, leaf := newTestCert(t)
	script := fakeServerScript{version: 6, user: "User", password: "Password", domain: "Domain"}
	addr, done := startFakeServer(t, cert, leaf, script)

	client := &Client{Version: 6}
	if err := client.Handshake(context.Background(), dialTLS(t, addr), script.user, script.password, script.domain); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestHandshakeSuccessVersion2(t *testing.T) {
	cert, leaf := newTestCert(t)
	script := fakeServerScript{version: 2, user: "User", password: "Password", domain: "Domain"}
	addr, done := startFakeServer(t, cert, leaf, script)

	client := &Client{Version: 2}
	if err := client.Handshake(context.Background(), dialTLS(t, addr), script.user, script.password, script.domain); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestHandshakeNTStatusWrongPassword(t *testing.T) {
	cert, leaf := newTestCert(t)
	script := fakeServerScript{
		version: 6, user: "User", password: "Password", domain: "Domain",
		failWith: StatusWrongPassword,
	}
	addr, done := startFakeServer(t, cert, leaf, script)

	err := (&Client{Version: 6}).Handshake(context.Background(), dialTLS(t, addr), "User", "WrongPassword", "Domain")
	var statusErr *NTStatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("error = %v, want *NTStatusError", err)
	}
	if statusErr.Code != StatusWrongPassword {
		t.Fatalf("code = 0x%08x, want 0x%08x", statusErr.Code, StatusWrongPassword)
	}
	if err := <-done; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestHandshakeServerBindingMismatch(t *testing.T) {
	for _, version := range []int{6, 2} {
		cert, leaf := newTestCert(t)
		script := fakeServerScript{
			version: version, user: "User", password: "Password", domain: "Domain",
			corruptBind: true,
		}
		addr, done := startFakeServer(t, cert, leaf, script)

		err := (&Client{Version: version}).Handshake(context.Background(), dialTLS(t, addr),
			script.user, script.password, script.domain)
		if err == nil {
			t.Fatalf("version %d: expected binding mismatch error", version)
		}
		if !bytes.Contains([]byte(err.Error()), []byte("mismatch")) {
			t.Fatalf("version %d: error = %v, want mismatch", version, err)
		}
		if err := <-done; err != nil {
			t.Fatalf("version %d server: %v", version, err)
		}
	}
}

func TestHandshakeRejectsVersionChange(t *testing.T) {
	cert, leaf := newTestCert(t)
	script := fakeServerScript{
		version: 6, user: "User", password: "Password", domain: "Domain",
		changeVer: true,
	}
	addr, done := startFakeServer(t, cert, leaf, script)

	err := (&Client{Version: 6}).Handshake(context.Background(), dialTLS(t, addr),
		script.user, script.password, script.domain)
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("changed version")) {
		t.Fatalf("error = %v, want version change rejection", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestHandshakeHonorsCancelledContext(t *testing.T) {
	cert, leaf := newTestCert(t)
	script := fakeServerScript{version: 6, user: "User", password: "Password", domain: "Domain"}
	addr, done := startFakeServer(t, cert, leaf, script)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn := dialTLS(t, addr)
	err := (&Client{Version: 6}).Handshake(ctx, conn, script.user, script.password, script.domain)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	// Closing the connection unblocks the responder; its outcome is irrelevant
	// here but must be consumed before the test ends.
	conn.Close()
	<-done
}

// TestBindingHashLayout pins the MS-CSSP 2.2.2.2 hash input order and the NUL
// terminator of the magic string.
func TestBindingHashLayout(t *testing.T) {
	magic := []byte("CredSSP Client-To-Server Binding Hash\x00")
	nonce := bytes.Repeat([]byte{0x33}, 32)
	key := []byte{0x04, 0x01, 0x02}
	h := sha256.New()
	h.Write(magic)
	h.Write(nonce)
	h.Write(key)
	want := hex.EncodeToString(h.Sum(nil))
	got := hex.EncodeToString(bindingHash(magic, nonce, key))
	if got != want {
		t.Fatalf("bindingHash = %s, want %s", got, want)
	}
	if bytes.Equal(bindingHash(magic, nonce, key), bindingHash(magic[:len(magic)-1], nonce, key)) {
		t.Fatal("the NUL terminator must be part of the hash input")
	}
}

// TestSubjectPublicKeyExtraction verifies the binding target is the
// subjectPublicKey BIT STRING content of SubjectPublicKeyInfo (MS-CSSP 2.2.2.2).
func TestSubjectPublicKeyExtraction(t *testing.T) {
	_, leaf := newTestCert(t)
	got, err := subjectPublicKeyFromSPKI(leaf.RawSubjectPublicKeyInfo)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got, leaf.RawSubjectPublicKeyInfo) {
		t.Fatal("SubjectPublicKey must not be the full SubjectPublicKeyInfo")
	}
	if len(got) == 0 {
		t.Fatal("empty SubjectPublicKey")
	}
	// The BIT STRING content must be recoverable from the certificate.
	if !bytes.Contains(leaf.RawSubjectPublicKeyInfo, got) {
		t.Fatal("SubjectPublicKey not found inside SubjectPublicKeyInfo")
	}
	if _, err := subjectPublicKeyFromSPKI([]byte{0x30, 0x00}); err == nil {
		t.Fatal("empty SPKI must be rejected")
	}
	if _, err := subjectPublicKeyFromSPKI([]byte{0xff}); err == nil {
		t.Fatal("malformed SPKI must be rejected")
	}
}
