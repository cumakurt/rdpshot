package rdp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"rdpshot/internal/model"
)

func TestIsLegacyTLSVersion(t *testing.T) {
	if !IsLegacyTLSVersion("TLS 1.0") {
		t.Error("TLS 1.0 should be marked legacy")
	}
	if !IsLegacyTLSVersion("TLS 1.1") {
		t.Error("TLS 1.1 should be marked legacy")
	}
	if !IsLegacyTLSVersion("SSL 3.0") {
		t.Error("SSL 3.0 should be marked legacy")
	}
	if IsLegacyTLSVersion("TLS 1.2") {
		t.Error("TLS 1.2 should not be marked legacy")
	}
	if IsLegacyTLSVersion("TLS 1.3") {
		t.Error("TLS 1.3 should not be marked legacy")
	}
}

func TestIsWeakCipherSuite(t *testing.T) {
	weak := []string{
		"TLS_RSA_WITH_RC4_128_SHA",
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
	}
	for _, c := range weak {
		if !IsWeakCipherSuite(c) {
			t.Errorf("%s should be weak", c)
		}
	}
	strong := []string{
		"TLS_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	}
	for _, c := range strong {
		if IsWeakCipherSuite(c) {
			t.Errorf("%s should be strong", c)
		}
	}
}

func generateTestCert(t *testing.T) tls.Certificate {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"rdpshot test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}
}

func TestProbeTLSVersionWithMock(t *testing.T) {
	cert := generateTestCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := net.LookupPort("tcp", portStr)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Read TPKT/X.224 CR
				buf := make([]byte, 1024)
				n, err := c.Read(buf)
				if err != nil || n < 11 {
					return
				}
				// Reply X.224 CC with SSL negotiated
				cc := []byte{
					0x03, 0x00, 0x00, 0x13, // TPKT len 19
					0x0e,             // X.224 len
					0xd0, 0x00, 0x00, // CC
					0x12, 0x34, 0x00, // dst, src, class
					0x02, 0x00, 0x08, 0x00, // RDP_NEG_RSP (type 2, flags 0, len 8)
					0x01, 0x00, 0x00, 0x00, // ProtocolSSL
				}
				if _, err := c.Write(cc); err != nil {
					return
				}
				// Now TLS handshake
				tlsConfig := &tls.Config{
					Certificates: []tls.Certificate{cert},
					MinVersion:   tls.VersionTLS12,
					MaxVersion:   tls.VersionTLS12,
				}
				tlsConn := tls.Server(c, tlsConfig)
				_ = tlsConn.Handshake()
			}(conn)
		}
	}()

	ep := model.Endpoint{Address: host, Port: uint16(port)}
	supported, cipher, err := ProbeTLSVersion(t.Context(), ep, tls.VersionTLS12, 2*time.Second)
	if err != nil {
		t.Fatalf("ProbeTLSVersion err: %v", err)
	}
	if !supported {
		t.Errorf("expected TLS 1.2 supported, got false")
	}
	if cipher == "" {
		t.Errorf("expected non-empty cipher, got %q", cipher)
	}

	// TLS 1.0 should fail on this mock server because MinVersion is TLS 1.2
	supported10, _, _ := ProbeTLSVersion(t.Context(), ep, tls.VersionTLS10, 2*time.Second)
	if supported10 {
		t.Errorf("expected TLS 1.0 not supported, got true")
	}
}
