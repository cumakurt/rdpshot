package rdp

import (
	"context"
	"net"
	"testing"
	"time"

	"rdpshot/internal/model"
)

func TestProbeNLADowngrade(t *testing.T) {
	// 1. Strict server that rejects with FailureHybridRequiredByServer
	l1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l1.Close()

	go func() {
		conn, err := l1.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = ReadTPKT(conn)
		code := FailureHybridRequiredByServer
		payload := []byte{0x03, 0x00, 0x08, 0x00, byte(code), byte(code >> 8), byte(code >> 16), byte(code >> 24)}
		cc := append([]byte{0x0e, x224ConnectionConfirm, 0, 0, 0, 0, 0}, payload...)
		_ = WriteTPKT(conn, cc)
	}()

	addr1 := l1.Addr().(*net.TCPAddr)
	ep1 := model.Endpoint{Address: addr1.IP.String(), Port: uint16(addr1.Port)}

	res1, err := ProbeNLADowngrade(context.Background(), ep1, 2*time.Second)
	if err != nil {
		t.Fatalf("ProbeNLADowngrade strict server: %v", err)
	}
	if res1.Vulnerable {
		t.Errorf("Strict server reported vulnerable: %+v", res1)
	}

	// 2. Vulnerable server that accepts ProtocolSSL
	l2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()

	go func() {
		conn, err := l2.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = ReadTPKT(conn)
		protocol := ProtocolSSL
		payload := []byte{0x02, 0x00, 0x08, 0x00, byte(protocol), byte(protocol >> 8), byte(protocol >> 16), byte(protocol >> 24)}
		cc := append([]byte{0x0e, x224ConnectionConfirm, 0, 0, 0, 0, 0}, payload...)
		_ = WriteTPKT(conn, cc)
	}()

	addr2 := l2.Addr().(*net.TCPAddr)
	ep2 := model.Endpoint{Address: addr2.IP.String(), Port: uint16(addr2.Port)}

	res2, err := ProbeNLADowngrade(context.Background(), ep2, 2*time.Second)
	if err != nil {
		t.Fatalf("ProbeNLADowngrade vulnerable server: %v", err)
	}
	if !res2.Vulnerable {
		t.Errorf("Vulnerable server reported safe: %+v", res2)
	}
	if res2.Selected != ProtocolSSL {
		t.Errorf("Selected = 0x%x, want 0x%x", res2.Selected, ProtocolSSL)
	}
}
