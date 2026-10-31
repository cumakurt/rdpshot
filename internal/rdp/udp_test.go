package rdp

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"rdpshot/internal/model"
)

func TestBuildRDPEUDPSyn(t *testing.T) {
	pkt := BuildRDPEUDPSyn(42)
	if len(pkt) != 16 {
		t.Fatalf("expected 16 bytes, got %d", len(pkt))
	}
	seq := binary.LittleEndian.Uint32(pkt[0:4])
	if seq != 42 {
		t.Errorf("seq = %d, want 42", seq)
	}
	flags := binary.LittleEndian.Uint16(pkt[10:12])
	if flags != RDPEUDP_FLAG_SYN {
		t.Errorf("flags = 0x%04x, want 0x%04x", flags, RDPEUDP_FLAG_SYN)
	}
}

func TestProbeRDPEUDPMockServer(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket failed: %v", err)
	}
	defer conn.Close()

	host, portStr, _ := net.SplitHostPort(conn.LocalAddr().String())
	port, _ := net.LookupPort("udp", portStr)

	go func() {
		buf := make([]byte, 1024)
		n, addr, err := conn.ReadFrom(buf)
		if err != nil || n < 12 {
			return
		}
		// Send SYN-ACK
		resp := make([]byte, 16)
		binary.LittleEndian.PutUint32(resp[0:4], 1000)
		binary.LittleEndian.PutUint32(resp[4:8], binary.LittleEndian.Uint32(buf[0:4]))
		binary.LittleEndian.PutUint16(resp[8:10], 0x0040)
		binary.LittleEndian.PutUint16(resp[10:12], RDPEUDP_FLAG_SYN|RDPEUDP_FLAG_ACK)
		binary.LittleEndian.PutUint16(resp[12:14], 1232)
		binary.LittleEndian.PutUint16(resp[14:16], 1232)
		_, _ = conn.WriteTo(resp, addr)
	}()

	ep := model.Endpoint{Address: host, Port: uint16(port)}
	res := ProbeRDPEUDP(context.Background(), ep, 2*time.Second)
	if !res.Reachable {
		t.Fatalf("expected reachable, got false")
	}
	if !res.SYNACK {
		t.Fatalf("expected SYNACK, got false")
	}
}
