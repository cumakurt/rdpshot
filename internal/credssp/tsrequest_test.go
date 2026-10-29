package credssp

import (
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"math/rand"
	"testing"
)

func TestTSRequestRoundTrip(t *testing.T) {
	code := uint32(0xC000006A)
	cases := []TSRequest{
		{Version: 6},
		{Version: 2, NegoTokens: [][]byte{{0x60, 0x01, 0x02}, {}}},
		{
			Version:     6,
			NegoTokens:  [][]byte{bytes.Repeat([]byte{0xAA}, 300)},
			AuthInfo:    []byte{1, 2, 3},
			PubKeyAuth:  bytes.Repeat([]byte{0x55}, 40),
			ErrorCode:   &code,
			ClientNonce: bytes.Repeat([]byte{0x11}, 32),
		},
		{Version: 5, NegoTokens: [][]byte{{0x30, 0x00}}},
		{Version: 3, PubKeyAuth: []byte{9}},
	}
	for i, want := range cases {
		der, err := want.Marshal()
		if err != nil {
			t.Fatalf("case %d marshal: %v", i, err)
		}
		got, err := ParseTSRequest(der)
		if err != nil {
			t.Fatalf("case %d parse: %v", i, err)
		}
		if got.Version != want.Version {
			t.Fatalf("case %d version = %d, want %d", i, got.Version, want.Version)
		}
		if (got.ErrorCode == nil) != (want.ErrorCode == nil) {
			t.Fatalf("case %d errorCode presence mismatch", i)
		}
		if got.ErrorCode != nil && *got.ErrorCode != *want.ErrorCode {
			t.Fatalf("case %d errorCode = 0x%08x, want 0x%08x", i, *got.ErrorCode, *want.ErrorCode)
		}
		if (got.NegoTokens == nil) != (want.NegoTokens == nil) || len(got.NegoTokens) != len(want.NegoTokens) {
			t.Fatalf("case %d negoTokens mismatch: %v vs %v", i, got.NegoTokens, want.NegoTokens)
		}
		for j := range want.NegoTokens {
			if !bytes.Equal(got.NegoTokens[j], want.NegoTokens[j]) {
				t.Fatalf("case %d token %d differs", i, j)
			}
		}
		if !bytes.Equal(got.AuthInfo, want.AuthInfo) ||
			!bytes.Equal(got.PubKeyAuth, want.PubKeyAuth) ||
			!bytes.Equal(got.ClientNonce, want.ClientNonce) {
			t.Fatalf("case %d octet fields differ:\n got %+v\nwant %+v", i, got, want)
		}
		again, err := got.Marshal()
		if err != nil {
			t.Fatalf("case %d re-marshal: %v", i, err)
		}
		if !bytes.Equal(der, again) {
			t.Fatalf("case %d re-marshal differs", i)
		}
	}
}

// TestTSRequestManualDER decodes a hand-written DER sample matching the
// MS-CSSP 2.2.1.1 layout: version [0], negoTokens [1] with one token.
func TestTSRequestManualDER(t *testing.T) {
	// Layout: [0] version = 6, [1] negoTokens = one token "NTLMSSP".
	der, err := hex.DecodeString(
		"3016" + // TSRequest SEQUENCE (22 content bytes)
			"a003020106" + // [0] version = 6
			"a10f" + // [1] negoTokens (15 content bytes)
			"300d" + // SEQUENCE OF (13 content bytes)
			"300b" + // item SEQUENCE (11 content bytes)
			"a009" + // [0] negoToken (9 content bytes)
			"0407" + // OCTET STRING, 7 bytes
			"4e544c4d535350") // "NTLMSSP"
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseTSRequest(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Version != 6 {
		t.Fatalf("version = %d, want 6", got.Version)
	}
	if len(got.NegoTokens) != 1 || string(got.NegoTokens[0]) != "NTLMSSP" {
		t.Fatalf("negoTokens = %q", got.NegoTokens)
	}
	if got.AuthInfo != nil || got.PubKeyAuth != nil || got.ErrorCode != nil || got.ClientNonce != nil {
		t.Fatalf("optional fields must be absent: %+v", got)
	}
}

func TestTSRequestMalformed(t *testing.T) {
	good, err := TSRequest{Version: 6, AuthInfo: []byte{1, 2, 3}}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	version, err := asn1.Marshal(6)
	if err != nil {
		t.Fatal(err)
	}
	dupBody := append(derExplicit(0, version), derExplicit(0, version)...)
	duplicate := derSequence(dupBody)

	cases := map[string][]byte{
		"empty":         {},
		"truncated":     good[:len(good)-1],
		"not-der":       {0x31, 0x00},
		"junk":          {0xff, 0xff, 0xff, 0xff},
		"trailing":      append(append([]byte(nil), good...), 0x00),
		"duplicate-tag": duplicate,
		"missing-ver":   {0x30, 0x00},
	}
	for name, b := range cases {
		if _, err := ParseTSRequest(b); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

// TestParseTSRequestNeverPanicsOnRandomInput feeds deterministic
// pseudo-random buffers to the parser; it must always return cleanly.
func TestParseTSRequestNeverPanicsOnRandomInput(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	buf := make([]byte, 256)
	for i := 0; i < 20000; i++ {
		n := rng.Intn(len(buf))
		b := buf[:n]
		for j := range b {
			b[j] = byte(rng.Intn(256))
		}
		if rng.Intn(2) == 0 && n >= 2 {
			b[0] = 0x30 // bias toward a SEQUENCE header
		}
		_, _ = ParseTSRequest(b)
	}
}

// TestTSRequestErrorCodeUnsigned pins the NTSTATUS encoding: large values
// survive both as unsigned and as two's-complement signed INTEGERs.
func TestTSRequestErrorCodeUnsigned(t *testing.T) {
	code := uint32(0xC000006A)
	der, err := TSRequest{Version: 6, ErrorCode: &code}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseTSRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	if got.ErrorCode == nil || *got.ErrorCode != code {
		t.Fatalf("errorCode = %v, want 0x%08x", got.ErrorCode, code)
	}

	// The same bit pattern encoded as a negative INTEGER (int32 view).
	neg, err := asn1.Marshal(-1073741718)
	if err != nil {
		t.Fatal(err)
	}
	version, err := asn1.Marshal(6)
	if err != nil {
		t.Fatal(err)
	}
	body := append(derExplicit(0, version), derExplicit(4, neg)...)
	got, err = ParseTSRequest(derSequence(body))
	if err != nil {
		t.Fatal(err)
	}
	if got.ErrorCode == nil || *got.ErrorCode != code {
		t.Fatalf("signed errorCode = %v, want 0x%08x", got.ErrorCode, code)
	}
}
