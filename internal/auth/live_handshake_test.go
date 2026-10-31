package auth

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"testing"
	"time"

	"rdpshot/internal/credssp"
	"rdpshot/internal/model"
	"rdpshot/internal/rdp"
)

func TestLiveHandshakeOnly(t *testing.T) {
	if os.Getenv("RDPSHOT_LIVE") == "" {
		t.Skip("set RDPSHOT_LIVE=1 to run against a lab RDP host")
	}
	host := os.Getenv("RDPSHOT_LIVE_HOST")
	if host == "" {
		host = "172.16.3.128"
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "3389"), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(25 * time.Second))
	if err := rdp.WriteConnectionRequest(conn, "rdpshot", rdp.RequestedProtocols()); err != nil {
		t.Fatal(err)
	}
	if _, err := rdp.ReadConnectionConfirm(conn); err != nil {
		t.Fatal(err)
	}
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	user := os.Getenv("RDPSHOT_LIVE_USER")
	pass := os.Getenv("RDPSHOT_LIVE_PASS")
	if user == "" {
		user = "cmk"
	}
	if pass == "" {
		pass = "cumakurt"
	}
	err = (&credssp.Client{Version: 6}).Handshake(context.Background(), tlsConn, user, pass, "")
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
}

func TestLiveStockAuthenticator(t *testing.T) {
	if os.Getenv("RDPSHOT_LIVE") == "" {
		t.Skip("set RDPSHOT_LIVE=1 to run against a lab RDP host")
	}
	host := os.Getenv("RDPSHOT_LIVE_HOST")
	if host == "" {
		host = "172.16.3.128"
	}
	user := os.Getenv("RDPSHOT_LIVE_USER")
	pass := os.Getenv("RDPSHOT_LIVE_PASS")
	if user == "" {
		user = "cmk"
	}
	if pass == "" {
		pass = "cumakurt"
	}
	a := NewCredSSPAuthenticator(25 * time.Second)
	err := a.Authenticate(context.Background(), model.Endpoint{Address: host, Port: 3389},
		model.Credential{Username: user, Secret: pass})
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
}
