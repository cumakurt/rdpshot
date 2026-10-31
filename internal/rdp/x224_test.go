package rdp

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestBuildConnectionRequestNoCookie(t *testing.T) {
	got := BuildConnectionRequest("", ProtocolSSL|ProtocolHybrid|ProtocolHybridEx)
	want := "03000013" + "0ee00000000000" + "010008000b000000"
	if hex.EncodeToString(got) != want {
		t.Fatalf("connection request mismatch:\n got %s\nwant %s", hex.EncodeToString(got), want)
	}
}

func TestBuildConnectionRequestWithCookie(t *testing.T) {
	got := BuildConnectionRequest("test", ProtocolRDP)
	want := "0300002a" + "25e00000000000" + "436f6f6b69653a206d737473686173683d746573740d0a" + "0100080000000000"
	if hex.EncodeToString(got) != want {
		t.Fatalf("connection request mismatch:\n got %s\nwant %s", hex.EncodeToString(got), want)
	}
}

func TestParseConnectionConfirmResponse(t *testing.T) {
	tpdu := append([]byte{0x0e, x224ConnectionConfirm, 0, 0, 0, 0, 0},
		0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00)
	res, err := ParseConnectionConfirm(tpdu)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if res.SelectedProtocol != ProtocolHybrid {
		t.Fatalf("selected protocol = %#x, want HYBRID", res.SelectedProtocol)
	}
	if !res.NLARequired() {
		t.Fatal("expected NLA to be required")
	}
	if res.Failed() {
		t.Fatal("unexpected failure result")
	}
}

func TestParseConnectionConfirmFailure(t *testing.T) {
	tpdu := append([]byte{0x0e, x224ConnectionConfirm, 0, 0, 0, 0, 0},
		0x03, 0x00, 0x08, 0x00, 0x05, 0x00, 0x00, 0x00)
	res, err := ParseConnectionConfirm(tpdu)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !res.Failed() {
		t.Fatal("expected failure result")
	}
	if res.FailureCode == nil || *res.FailureCode != FailureHybridRequiredByServer {
		t.Fatalf("failure code = %v, want HYBRID_REQUIRED_BY_SERVER", res.FailureCode)
	}
	if res.NLARequired() {
		t.Fatal("failed negotiation must not report NLA as negotiated")
	}
}

func TestParseConnectionConfirmLegacy(t *testing.T) {
	tpdu := []byte{0x06, x224ConnectionConfirm, 0, 0, 0, 0, 0}
	res, err := ParseConnectionConfirm(tpdu)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if res.SelectedProtocol != ProtocolRDP {
		t.Fatalf("selected protocol = %#x, want RDP", res.SelectedProtocol)
	}
}

func TestParseConnectionConfirmWithCookie(t *testing.T) {
	tpdu := []byte{0x24, x224ConnectionConfirm, 0, 0, 0, 0, 0}
	tpdu = append(tpdu, []byte("Cookie: mstshash=abc\r\n")...)
	tpdu = append(tpdu, 0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00)
	res, err := ParseConnectionConfirm(tpdu)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if res.SelectedProtocol != ProtocolSSL {
		t.Fatalf("selected protocol = %#x, want SSL", res.SelectedProtocol)
	}
}

func TestParseConnectionConfirmRejectsMalformed(t *testing.T) {
	cases := [][]byte{
		nil,
		{0x0e},                        // too short
		{0xff, x224ConnectionConfirm}, // length indicator beyond payload
		{0x06, 0xE0, 0, 0, 0, 0, 0},   // wrong TPDU type
		{0x0e, x224ConnectionConfirm, 0, 0, 0, 0, 0, 0x7f, 0, 8, 0, 1, 0, 0, 0}, // unknown neg type
	}
	for i, in := range cases {
		if _, err := ParseConnectionConfirm(in); err == nil {
			t.Fatalf("case %d: expected error for malformed input %x", i, in)
		}
	}
}

func TestTPKTRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte{0x06, 0xd0, 0, 0, 0, 0, 0}
	if err := WriteTPKT(&buf, payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := ReadTPKT(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("round trip mismatch: %x != %x", got, payload)
	}
}

func TestTPKTRejectsMalformed(t *testing.T) {
	cases := [][]byte{
		{0x02, 0x00, 0x00, 0x08, 0, 0, 0, 0}, // bad version
		{0x03, 0x01, 0x00, 0x08, 0, 0, 0, 0}, // reserved byte set
		{0x03, 0x00, 0x00, 0x02},             // length smaller than header
		{0x03, 0x00, 0x00, 0x10, 0x01},       // truncated payload
	}
	for i, in := range cases {
		if _, err := ReadTPKT(bytes.NewReader(in)); err == nil {
			t.Fatalf("case %d: expected error for malformed TPKT %x", i, in)
		}
	}
}

func TestReadConnectionConfirmEndToEnd(t *testing.T) {
	frame := BuildConnectionRequest("", RequestedProtocols())
	// The request itself must be a valid TPKT frame.
	if _, err := ReadTPKT(bytes.NewReader(frame)); err != nil {
		t.Fatalf("request frame invalid: %v", err)
	}
	cc := append([]byte{0x0e, x224ConnectionConfirm, 0, 0, 0, 0, 0},
		0x02, 0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00)
	var buf bytes.Buffer
	if err := WriteTPKT(&buf, cc); err != nil {
		t.Fatalf("write: %v", err)
	}
	res, err := ReadConnectionConfirm(&buf)
	if err != nil {
		t.Fatalf("read confirm: %v", err)
	}
	if res.SelectedProtocol != ProtocolHybridEx {
		t.Fatalf("selected = %#x, want HYBRID_EX", res.SelectedProtocol)
	}
}

func TestReadEarlyUserAuthorizationResult(t *testing.T) {
	t.Parallel()
	if err := ReadEarlyUserAuthorizationResult(bytes.NewReader([]byte{0, 0, 0, 0})); err != nil {
		t.Fatalf("success: %v", err)
	}
	err := ReadEarlyUserAuthorizationResult(bytes.NewReader([]byte{5, 0, 0, 0}))
	if !errors.Is(err, ErrEarlyUserAccessDenied) {
		t.Fatalf("denied: %v", err)
	}
	if err := ReadEarlyUserAuthorizationResult(bytes.NewReader([]byte{1, 0, 0, 0})); err == nil {
		t.Fatal("expected unexpected-code error")
	}
	if err := ReadEarlyUserAuthorizationResult(bytes.NewReader([]byte{0, 0})); err == nil {
		t.Fatal("expected short-read error")
	}
}
