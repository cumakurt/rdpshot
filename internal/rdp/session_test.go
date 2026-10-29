package rdp

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"rdpshot/internal/model"
)

// fakeServer is a scripted RDP responder used to exercise the client side of
// the connection sequence without a real Windows target.
type fakeServer struct {
	ln net.Listener
	// mode selects the scripted behaviour.
	mode string // "vulnerable" | "patched" | "nla" | "notrdp" | "legacy-encryption"

	mu       sync.Mutex
	gotCheck bool
}

func newFakeServer(t *testing.T, mode string) *fakeServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &fakeServer{ln: ln, mode: mode}
	go s.serve()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *fakeServer) addr() (string, uint16) {
	addr := s.ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), uint16(addr.Port)
}

func (s *fakeServer) sawCheck() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gotCheck
}

func (s *fakeServer) serve() {
	conn, err := s.ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := ReadTPKT(conn); err != nil { // connection request
		return
	}

	switch s.mode {
	case "notrdp":
		conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		return
	case "nla":
		writeCCFailure(conn, FailureHybridRequiredByServer)
		return
	}

	selected := uint32(ProtocolRDP)
	writeCCResponse(conn, selected)

	if _, err := readDataTPDU(conn); err != nil { // MCS connect initial
		return
	}
	level := uint32(0)
	if s.mode == "legacy-encryption" {
		level = 3
	}
	if err := writeDataTPDU(conn, fakeConnectResponse(level)); err != nil {
		return
	}

	if s.mode == "legacy-encryption" {
		// The client must not send any channel data when legacy RDP
		// encryption keys would be required.
		conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if _, err := readDataTPDU(conn); err == nil {
			s.markCheck()
		}
		return
	}

	// Erect domain request carries no confirm; attach user does.
	if _, err := readDataTPDU(conn); err != nil {
		return
	}
	if _, err := readDataTPDU(conn); err != nil { // attach user request
		return
	}
	if err := writeDataTPDU(conn, []byte{0x2e, 0x00, 0x03, 0xea}); err != nil { // user 1002
		return
	}
	for i := 0; i < 3; i++ { // channel joins: user, global, MS_T120
		payload, err := readDataTPDU(conn)
		if err != nil {
			return
		}
		if err := writeDataTPDU(conn, fakeChannelJoinConfirm(payload)); err != nil {
			return
		}
	}

	// Consume the check messages first so the client finishes sending before
	// the scripted response; closing with unread data would reset the stream.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for i := 0; i < 10; i++ {
		if _, err := readDataTPDU(conn); err != nil {
			break
		}
		s.markCheck()
	}
	if s.mode == "vulnerable" {
		// MCS Disconnect Provider Ultimatum: the signal unpatched servers
		// produce for the MS_T120 check messages.
		writeDataTPDU(conn, []byte{0x21, 0x03})
		time.Sleep(100 * time.Millisecond)
		return
	}
	// A patched server ignores the check messages and keeps the session open;
	// hold the connection past the client observation window.
	time.Sleep(600 * time.Millisecond)
}

func (s *fakeServer) markCheck() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gotCheck = true
}

func writeCCResponse(conn net.Conn, selected uint32) {
	payload := []byte{0x0e, 0xd0, 0, 0, 0, 0, 0, 0x02, 0x00, 0x08, 0x00, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(payload[11:], selected)
	WriteTPKT(conn, payload)
}

func writeCCFailure(conn net.Conn, code uint32) {
	payload := []byte{0x0e, 0xd0, 0, 0, 0, 0, 0, 0x03, 0x00, 0x08, 0x00, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(payload[11:], code)
	WriteTPKT(conn, payload)
}

func fakeConnectResponse(encryptionLevel uint32) []byte {
	userData := make([]byte, 21)
	userData = append(userData, 0x81, 0x1e)

	core := make([]byte, 8)
	binary.LittleEndian.PutUint32(core[0:], 0x00080004)
	userData = appendBlock(userData, scCore, core)

	netBody := make([]byte, 4+2*1)
	binary.LittleEndian.PutUint16(netBody[0:], 1003)
	binary.LittleEndian.PutUint16(netBody[2:], 1)
	binary.LittleEndian.PutUint16(netBody[4:], 1004)
	userData = appendBlock(userData, scNet, netBody)

	secBody := make([]byte, 8)
	binary.LittleEndian.PutUint32(secBody[4:], encryptionLevel)
	userData = appendBlock(userData, scSecurity, secBody)

	content := make([]byte, 0, len(userData)+32)
	content = berAppendHeader(content, berTagEnumerated, 1)
	content = append(content, 0x00)
	content = berAppendInteger(content, 1)
	content = berAppendDomainParams(content, 34, 2, 0, 0xffff)
	content = berAppendHeader(content, berTagOctetString, len(userData))
	content = append(content, userData...)
	pdu := berAppendHeader(nil, mcsConnectResponse, len(content))
	return append(pdu, content...)
}

func fakeChannelJoinConfirm(request []byte) []byte {
	confirm := []byte{0x3e, 0x00, 0x03, 0xea, 0x00, 0x00}
	if len(request) >= 5 {
		copy(confirm[4:], request[3:5])
	}
	return confirm
}

func gatherEndpoint(t *testing.T, srv *fakeServer) (GatherResult, error) {
	t.Helper()
	host, port := srv.addr()
	return Gather(context.Background(), model.Endpoint{Address: host, Port: port}, Options{
		Timeout:       2 * time.Second,
		ProbeBlueKeep: true,
		ProbeTimeout:  400 * time.Millisecond,
	})
}

func TestGatherDetectsVulnerableServer(t *testing.T) {
	srv := newFakeServer(t, "vulnerable")
	result, err := gatherEndpoint(t, srv)
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	if result.Service.NegotiatedProtocol != ProtocolRDP {
		t.Fatalf("negotiated protocol = %#x", result.Service.NegotiatedProtocol)
	}
	if result.Service.ServerVersion != 0x00080004 {
		t.Fatalf("server version = %#x", result.Service.ServerVersion)
	}
	if result.Service.EncryptionLevel != "none" {
		t.Fatalf("encryption level = %q", result.Service.EncryptionLevel)
	}
	if result.BlueKeep == nil || !result.BlueKeep.Attempted || !result.BlueKeep.Triggered {
		t.Fatalf("bluekeep result = %+v", result.BlueKeep)
	}
	if !srv.sawCheck() {
		t.Fatal("fake server did not receive the MS_T120 check messages")
	}
}

func TestGatherPatchedServerIsSilent(t *testing.T) {
	srv := newFakeServer(t, "patched")
	result, err := gatherEndpoint(t, srv)
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	if result.BlueKeep == nil || !result.BlueKeep.Attempted {
		t.Fatalf("bluekeep result = %+v", result.BlueKeep)
	}
	if result.BlueKeep.Triggered {
		t.Fatalf("patched server must not trigger the probe: %+v", result.BlueKeep)
	}
	if !strings.Contains(result.BlueKeep.Reason, "no MS_T120 response") {
		t.Fatalf("unexpected reason: %q", result.BlueKeep.Reason)
	}
}

func TestGatherNLARequired(t *testing.T) {
	srv := newFakeServer(t, "nla")
	result, err := gatherEndpoint(t, srv)
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	if !result.Service.NLARequired {
		t.Fatalf("expected NLA to be required: %+v", result.Service)
	}
	if result.Service.NegotiationFailureCode == nil ||
		*result.Service.NegotiationFailureCode != FailureHybridRequiredByServer {
		t.Fatalf("failure code = %v", result.Service.NegotiationFailureCode)
	}
	if result.BlueKeep != nil {
		t.Fatal("probe must not run when NLA is enforced")
	}
}

func TestGatherLegacyEncryptionSkipsProbe(t *testing.T) {
	srv := newFakeServer(t, "legacy-encryption")
	result, err := gatherEndpoint(t, srv)
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	if result.Service.EncryptionLevel != "high" {
		t.Fatalf("encryption level = %q", result.Service.EncryptionLevel)
	}
	if result.BlueKeep != nil && result.BlueKeep.Attempted {
		t.Fatal("probe must not run over legacy RDP encryption")
	}
	if srv.sawCheck() {
		t.Fatal("no channel data may be sent when legacy encryption is required")
	}
}

func TestGatherRejectsNonRDPService(t *testing.T) {
	srv := newFakeServer(t, "notrdp")
	_, err := gatherEndpoint(t, srv)
	if err == nil || !errors.Is(err, ErrNotRDP) {
		t.Fatalf("err = %v, want ErrNotRDP", err)
	}
}

func TestGatherConnectionRefused(t *testing.T) {
	// Port 1 on localhost is expected to be closed.
	_, err := Gather(context.Background(), model.Endpoint{Address: "127.0.0.1", Port: 1},
		Options{Timeout: time.Second})
	if err == nil {
		t.Fatal("expected an error for a closed port")
	}
	if !errors.Is(err, ErrNetwork) && !errors.Is(err, ErrTimeout) {
		t.Fatalf("unexpected error classification: %v", err)
	}
}
