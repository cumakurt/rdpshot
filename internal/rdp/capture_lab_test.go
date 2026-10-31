//go:build lab

package rdp

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"rdpshot/internal/credssp"
	"rdpshot/internal/model"
	"rdpshot/internal/ntlm"
)

// Run with: go test -tags=lab -run TestLabHybridExSteps -v ./internal/rdp/
func TestLabHybridExSteps(t *testing.T) {
	host := envOr("RDPSHOT_LAB_HOST", "172.16.3.128")
	user := envOr("RDPSHOT_LAB_USER", "cmk")
	pass := envOr("RDPSHOT_LAB_PASS", "cumakurt")
	hash := envOr("RDPSHOT_LAB_NTHASH", "dd1709faebc6745c7be95fa7d452a01b")

	t.Run("password", func(t *testing.T) {
		traceHybridEx(t, host, user, ".", credssp.AuthSecret{Password: pass})
	})
	t.Run("pth", func(t *testing.T) {
		h, err := ntlm.ParseNTHash(hash)
		if err != nil {
			t.Fatal(err)
		}
		traceHybridEx(t, host, user, ".", credssp.AuthSecret{NTHash: h})
	})
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func traceHybridEx(t *testing.T, host, user, domain string, secret credssp.AuthSecret) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	raw, err := net.DialTimeout("tcp", net.JoinHostPort(host, "3389"), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(20 * time.Second))

	if err := WriteConnectionRequest(raw, "rdpshot", RequestedProtocols()); err != nil {
		t.Fatalf("x224-req: %v", err)
	}
	neg, err := ReadConnectionConfirm(raw)
	if err != nil {
		t.Fatalf("x224-cc: %v", err)
	}
	t.Logf("selected=%s (0x%x)", ProtocolName(neg.SelectedProtocol), neg.SelectedProtocol)

	tlsConn := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		t.Fatalf("tls: %v", err)
	}
	t.Log("tls ok")

	client := &credssp.Client{
		Version:             6,
		ExpectEarlyUserAuth: neg.SelectedProtocol == ProtocolHybridEx,
	}
	sess, err := client.HandshakeSessionWith(ctx, tlsConn, user, domain, secret)
	if err != nil {
		t.Fatalf("credssp: %v", err)
	}
	t.Logf("credssp ok expectEarly=%v", client.ExpectEarlyUserAuth)
	conn := sess.Conn

	if neg.SelectedProtocol == ProtocolHybridEx {
		var b [4]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			t.Fatalf("early-auth-read: %v", err)
		}
		code := binary.LittleEndian.Uint32(b[:])
		t.Logf("early-auth code=0x%08x bytes=%x", code, b)
		if code != EarlyUserAuthorizationSuccess {
			t.Fatalf("early auth not success: 0x%08x", code)
		}
	}

	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	peek := make([]byte, 16)
	n, perr := conn.Read(peek)
	t.Logf("pre-mcs peek n=%d err=%v data=%x", n, perr, peek[:max0(n)])
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))

	var prefix io.Reader
	if n > 0 {
		prefix = &sliceReader{b: peek[:n]}
	} else {
		prefix = &sliceReader{}
	}
	br := bufio.NewReader(io.MultiReader(prefix, conn))

	variants := []struct {
		name string
		gcc  []byte
	}{
		{"selected+nil-channels", BuildGCCClientData(neg.SelectedProtocol, nil)},
		{"selected+empty-net", buildGCCWithEmptyNet(neg.SelectedProtocol, false)},
		{"selected+empty-net+noenc", buildGCCWithEmptyNet(neg.SelectedProtocol, true)},
		{"requested+empty-net+noenc", buildGCCWithEmptyNet(RequestedProtocols(), true)},
	}
	// Only the first variant can use this live connection; others need fresh dials.
	gcc := variants[0].gcc
	t.Logf("trying variant %s gccLen=%d", variants[0].name, len(gcc))
	if err := writeDataTPDU(conn, BuildConnectInitial(gcc)); err != nil {
		t.Fatalf("write-ci: %v", err)
	}
	t.Log("ConnectInitial sent")
	payload, err := readDataTPDU(br)
	if err != nil {
		t.Logf("variant %s failed: %v — trying fresh dials", variants[0].name, err)
		for _, v := range variants[1:] {
			if err := tryConnectInitialVariant(t, host, user, domain, secret, neg.SelectedProtocol, v.name, v.gcc); err != nil {
				t.Logf("variant %s failed: %v", v.name, err)
				continue
			}
			t.Logf("variant %s SUCCEEDED", v.name)
			return
		}
		t.Fatalf("all ConnectInitial variants failed")
	}
	t.Logf("ConnectResponse len=%d head=%x", len(payload), payload[:min16(len(payload))])
	server, err := ParseConnectResponse(payload)
	if err != nil {
		t.Fatalf("parse-cr: %v", err)
	}
	t.Logf("MCS ok channel=%d", server.MCSChannelID)
}

func buildGCCWithEmptyNet(protocols uint32, noLegacyEnc bool) []byte {
	core := buildClientCoreData(protocols)
	cluster := buildClientClusterData()
	security := buildClientSecurityData()
	if noLegacyEnc {
		security = appendBlock(nil, csSecurity, binary.LittleEndian.AppendUint32(
			binary.LittleEndian.AppendUint32(nil, 0), 0))
	}
	network := appendBlock(nil, csNet, binary.LittleEndian.AppendUint32(nil, 0))
	blocks := append(append(append(append([]byte{}, core...), security...), network...), cluster...)
	out := []byte{0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01}
	out = appendPERLength(out, 14+len(blocks))
	out = append(out, 0x00, 0x08, 0x00, 0x10, 0x00, 0x01, 0xc0, 0x00)
	out = append(out, []byte("Duca")...)
	out = appendPERLength(out, len(blocks))
	return append(out, blocks...)
}

func tryConnectInitialVariant(t *testing.T, host, user, domain string, secret credssp.AuthSecret, selected uint32, name string, gcc []byte) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	raw, err := net.DialTimeout("tcp", net.JoinHostPort(host, "3389"), 5*time.Second)
	if err != nil {
		return err
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(18 * time.Second))
	if err := WriteConnectionRequest(raw, "rdpshot", RequestedProtocols()); err != nil {
		return err
	}
	neg, err := ReadConnectionConfirm(raw)
	if err != nil {
		return err
	}
	tlsConn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return err
	}
	client := &credssp.Client{Version: 6, ExpectEarlyUserAuth: neg.SelectedProtocol == ProtocolHybridEx}
	sess, err := client.HandshakeSessionWith(ctx, tlsConn, user, domain, secret)
	if err != nil {
		return err
	}
	conn := sess.Conn
	if neg.SelectedProtocol == ProtocolHybridEx {
		if err := ReadEarlyUserAuthorizationResult(conn); err != nil {
			return err
		}
	}
	if err := writeDataTPDU(conn, BuildConnectInitial(gcc)); err != nil {
		return err
	}
	br := bufio.NewReader(conn)
	payload, err := readDataTPDU(br)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	server, err := ParseConnectResponse(payload)
	if err != nil {
		return err
	}
	t.Logf("%s MCS ok channel=%d", name, server.MCSChannelID)
	_ = selected
	return nil
}

type sliceReader struct{ b []byte }

func (s *sliceReader) Read(p []byte) (int, error) {
	if len(s.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s.b)
	s.b = s.b[n:]
	return n, nil
}

func max0(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

func min16(n int) int {
	if n > 16 {
		return 16
	}
	return n
}

// silence unused in non-fail paths
var _ = fmt.Sprintf

func TestLabCaptureHYBRID(t *testing.T) {
	host := envOr("RDPSHOT_LAB_HOST", "172.16.3.128")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ep := model.Endpoint{Address: host, Port: 3389}
	credPass := model.Credential{Username: "cmk", Domain: ".", Secret: "cumakurt", Method: model.CredMethodPassword}
	img, err := Capture(ctx, ep, credPass, CaptureOptions{Timeout: 25 * time.Second})
	if err != nil {
		t.Fatalf("password Capture: %v", err)
	}
	b := img.Bounds()
	t.Logf("password Capture OK %dx%d", b.Dx(), b.Dy())

	credHash := model.Credential{Username: "cmk", Domain: ".", Secret: "dd1709faebc6745c7be95fa7d452a01b", Method: model.CredMethodNTHash}
	img, err = Capture(ctx, ep, credHash, CaptureOptions{Timeout: 25 * time.Second})
	if err != nil {
		t.Fatalf("pth Capture: %v", err)
	}
	b = img.Bounds()
	t.Logf("pth Capture OK %dx%d", b.Dx(), b.Dy())
}
