package ntlm

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestAVPairsRoundTrip(t *testing.T) {
	pairs := []AVPair{
		{ID: MsvAvNbComputerName, Data: encodeUTF16LE("SERVER")},
		{ID: MsvAvNbDomainName, Data: encodeUTF16LE("DOMAIN")},
		{ID: MsvAvDnsComputerName, Data: encodeUTF16LE("server.example.com")},
		{ID: MsvAvTimestamp, Data: make([]byte, 8)},
		{ID: MsvAvFlags, Data: []byte{2, 0, 0, 0}},
	}
	raw := MarshalAVPairs(pairs)
	got, err := ParseAVPairs(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != len(pairs) {
		t.Fatalf("pair count = %d, want %d", len(got), len(pairs))
	}
	for i := range pairs {
		if got[i].ID != pairs[i].ID || !bytes.Equal(got[i].Data, pairs[i].Data) {
			t.Fatalf("pair %d mismatch: %+v vs %+v", i, got[i], pairs[i])
		}
	}
	// Marshal must be idempotent: re-marshaling the parsed pairs yields the
	// same bytes (the EOL terminator is not duplicated).
	again := MarshalAVPairs(got)
	if !bytes.Equal(raw, again) {
		t.Fatalf("re-marshal differs:\n%x\n%x", raw, again)
	}
}

func TestMarshalAVPairsAddsEOL(t *testing.T) {
	raw := MarshalAVPairs(nil)
	if !bytes.Equal(raw, []byte{0, 0, 0, 0}) {
		t.Fatalf("empty list must encode as the EOL terminator, got %x", raw)
	}
	raw = MarshalAVPairs([]AVPair{{ID: MsvAvEOL}})
	if !bytes.Equal(raw, []byte{0, 0, 0, 0}) {
		t.Fatalf("explicit EOL must not be duplicated, got %x", raw)
	}
}

func TestParseAVPairsMalformed(t *testing.T) {
	cases := map[string][]byte{
		"truncated-header": {0x01},
		"length-overrun":   {0x01, 0x00, 0x10, 0x00, 0x41},
		"eol-with-data":    {0x00, 0x00, 0x01, 0x00, 0x41},
	}
	for name, b := range cases {
		if _, err := ParseAVPairs(b); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	// Missing EOL is tolerated (Windows leniency) but trailing garbage is not.
	if _, err := ParseAVPairs([]byte{0x01, 0x00, 0x02, 0x00, 0x41, 0x00}); err != nil {
		t.Fatalf("EOL-less list must parse: %v", err)
	}
}

func TestWithTargetName(t *testing.T) {
	pairs := WithTargetName([]AVPair{{ID: MsvAvNbDomainName, Data: []byte{1}}}, "TERMSRV/host")
	if len(pairs) != 2 || pairs[1].ID != MsvAvTargetName {
		t.Fatalf("unexpected pairs: %+v", pairs)
	}
	if !bytes.Equal(pairs[1].Data, encodeUTF16LE("TERMSRV/host")) {
		t.Fatalf("target name data = %x", pairs[1].Data)
	}
	// Replacing an existing target name must not duplicate it.
	pairs = WithTargetName(pairs, "TERMSRV/other")
	count := 0
	for _, p := range pairs {
		if p.ID == MsvAvTargetName {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("target name count = %d, want 1", count)
	}
}

func TestEnrichTargetInfoForCredSSP(t *testing.T) {
	base := MarshalAVPairs([]AVPair{
		{ID: MsvAvNbComputerName, Data: encodeUTF16LE("HOST")},
		{ID: MsvAvTimestamp, Data: make([]byte, 8)},
	})
	got, err := EnrichTargetInfoForCredSSP(base, "TERMSRV/HOST")
	if err != nil {
		t.Fatal(err)
	}
	pairs, err := ParseAVPairs(got)
	if err != nil {
		t.Fatal(err)
	}
	var sawCB, sawTarget, sawFlags bool
	for _, p := range pairs {
		switch p.ID {
		case MsvAvChannelBindings:
			sawCB = true
			if len(p.Data) != 16 {
				t.Fatalf("channel bindings len=%d", len(p.Data))
			}
		case MsvAvTargetName:
			sawTarget = true
			if !bytes.Equal(p.Data, encodeUTF16LE("TERMSRV/HOST")) {
				t.Fatalf("target=%x", p.Data)
			}
		case MsvAvFlags:
			sawFlags = true
			if len(p.Data) != 4 || binary.LittleEndian.Uint32(p.Data) != MsvAvFlagsMIC {
				t.Fatalf("av flags = %x", p.Data)
			}
		}
	}
	if !sawCB || !sawTarget || !sawFlags {
		t.Fatalf("missing AV pairs: cb=%v target=%v flags=%v pairs=%+v", sawCB, sawTarget, sawFlags, pairs)
	}
}
