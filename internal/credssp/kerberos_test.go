package credssp

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func buildSampleCCache(t *testing.T) []byte {
	var buf bytes.Buffer
	// Version 0x0504
	_ = binary.Write(&buf, binary.BigEndian, uint16(0x0504))
	// Header length: 0
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))

	// Default principal: user@DOMAIN.LOCAL
	_ = binary.Write(&buf, binary.BigEndian, uint32(1)) // KRB5_NT_PRINCIPAL
	_ = binary.Write(&buf, binary.BigEndian, uint32(1)) // 1 component
	writeCountedString(&buf, "DOMAIN.LOCAL")
	writeCountedString(&buf, "user")

	// Credential entry:
	// Client: user@DOMAIN.LOCAL
	_ = binary.Write(&buf, binary.BigEndian, uint32(1))
	_ = binary.Write(&buf, binary.BigEndian, uint32(1))
	writeCountedString(&buf, "DOMAIN.LOCAL")
	writeCountedString(&buf, "user")

	// Server: termsrv/rdp-host.domain.local@DOMAIN.LOCAL
	_ = binary.Write(&buf, binary.BigEndian, uint32(2)) // KRB5_NT_SRV_INST
	_ = binary.Write(&buf, binary.BigEndian, uint32(2)) // 2 components
	writeCountedString(&buf, "DOMAIN.LOCAL")
	writeCountedString(&buf, "termsrv")
	writeCountedString(&buf, "rdp-host.domain.local")

	// Keyblock: enctype 18 (AES-256), keylen 32, key
	_ = binary.Write(&buf, binary.BigEndian, uint16(18))
	_ = binary.Write(&buf, binary.BigEndian, uint16(32))
	buf.Write(make([]byte, 32))

	// Times: authtime, start, end, renew
	now := uint32(time.Now().Unix())
	_ = binary.Write(&buf, binary.BigEndian, now)
	_ = binary.Write(&buf, binary.BigEndian, now)
	_ = binary.Write(&buf, binary.BigEndian, now+3600) // valid for 1 hour
	_ = binary.Write(&buf, binary.BigEndian, now+86400)

	// is_skey (0), flags (0)
	buf.WriteByte(0)
	_ = binary.Write(&buf, binary.BigEndian, uint32(0))

	// addresses (0)
	_ = binary.Write(&buf, binary.BigEndian, uint32(0))
	// authdata (0)
	_ = binary.Write(&buf, binary.BigEndian, uint32(0))

	// Ticket (40 bytes dummy ticket)
	dummyTicket := []byte{0x61, 0x26, 0x30, 0x24, 0xa0, 0x03, 0x02, 0x01, 0x05}
	dummyTicket = append(dummyTicket, make([]byte, 31)...)
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(dummyTicket)))
	buf.Write(dummyTicket)

	// Second ticket (0)
	_ = binary.Write(&buf, binary.BigEndian, uint32(0))

	return buf.Bytes()
}

func writeCountedString(buf *bytes.Buffer, s string) {
	_ = binary.Write(buf, binary.BigEndian, uint32(len(s)))
	buf.WriteString(s)
}

func TestReadCCache(t *testing.T) {
	data := buildSampleCCache(t)
	cc, err := ReadCCache(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ReadCCache failed: %v", err)
	}
	if cc.Version != 0x0504 {
		t.Errorf("version = 0x%04x, want 0x0504", cc.Version)
	}
	if cc.DefaultPrincipal.String() != "user@DOMAIN.LOCAL" {
		t.Errorf("default principal = %q, want user@DOMAIN.LOCAL", cc.DefaultPrincipal.String())
	}
	if len(cc.Credentials) != 1 {
		t.Fatalf("credentials count = %d, want 1", len(cc.Credentials))
	}
	cred := cc.Credentials[0]
	if cred.Server.String() != "termsrv/rdp-host.domain.local@DOMAIN.LOCAL" {
		t.Errorf("server principal = %q", cred.Server.String())
	}
	if cred.IsExpired() {
		t.Error("newly minted ticket should not be expired")
	}

	// Test FindTicket
	found, err := cc.FindTicket("rdp-host.domain.local")
	if err != nil {
		t.Fatalf("FindTicket failed: %v", err)
	}
	if len(found.Ticket) == 0 {
		t.Errorf("ticket length = 0")
	}

	// Test BuildKerberosAPReqWrap
	token, err := BuildKerberosAPReqWrap(found.Ticket)
	if err != nil {
		t.Fatalf("BuildKerberosAPReqWrap failed: %v", err)
	}
	if len(token) == 0 {
		t.Errorf("token empty")
	}
}
