package ntlm

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"testing"
)

func sampleVersion() *[8]byte {
	v := [8]byte{0x0A, 0x00, 0x61, 0x4A, 0x00, 0x00, 0x00, 0x0F}
	return &v
}

func TestNegotiateRoundTrip(t *testing.T) {
	cases := []NegotiateMessage{
		{Flags: DefaultNegotiateFlags, Domain: "DOMAIN", Workstation: "WORKSTATION", Version: sampleVersion()},
		{Flags: NEGOTIATE_UNICODE | NEGOTIATE_NTLM, Domain: "", Workstation: ""},
		{Flags: DefaultNegotiateFlags | NEGOTIATE_VERSION, Domain: "Ünïcödé-домен", Workstation: "日本語", Version: sampleVersion()},
	}
	for i, want := range cases {
		b, err := want.Marshal()
		if err != nil {
			t.Fatalf("case %d marshal: %v", i, err)
		}
		got, err := ParseNegotiate(b)
		if err != nil {
			t.Fatalf("case %d parse: %v", i, err)
		}
		if got.Flags != want.Flags {
			t.Fatalf("case %d flags = 0x%08x, want 0x%08x", i, got.Flags, want.Flags)
		}
		if got.Domain != want.Domain || got.Workstation != want.Workstation {
			t.Fatalf("case %d strings = %q/%q, want %q/%q", i, got.Domain, got.Workstation, want.Domain, want.Workstation)
		}
		if (got.Version == nil) != (want.Version == nil) {
			t.Fatalf("case %d version presence = %v, want %v", i, got.Version != nil, want.Version != nil)
		}
		if got.Version != nil && *got.Version != *want.Version {
			t.Fatalf("case %d version = %v, want %v", i, got.Version, want.Version)
		}
		// Stable re-encoding proves the parse consumed a canonical layout.
		again, err := got.Marshal()
		if err != nil {
			t.Fatalf("case %d re-marshal: %v", i, err)
		}
		if !bytes.Equal(b, again) {
			t.Fatalf("case %d re-marshal differs", i)
		}
	}
}

func TestChallengeRoundTrip(t *testing.T) {
	info := MarshalAVPairs([]AVPair{
		{ID: MsvAvNbDomainName, Data: encodeUTF16LE("Domain")},
		{ID: MsvAvTimestamp, Data: make([]byte, 8)},
	})
	challenge := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	cases := []ChallengeMessage{
		{Flags: DefaultNegotiateFlags, ServerChallenge: challenge, TargetName: "TERMSRV/host", TargetInfo: info, Version: sampleVersion()},
		{Flags: NEGOTIATE_UNICODE | NEGOTIATE_VERSION, ServerChallenge: challenge, TargetName: "Ünïcödé", TargetInfo: nil, Version: sampleVersion()},
	}
	for i, want := range cases {
		b, err := want.Marshal()
		if err != nil {
			t.Fatalf("case %d marshal: %v", i, err)
		}
		got, err := ParseChallenge(b)
		if err != nil {
			t.Fatalf("case %d parse: %v", i, err)
		}
		if got.Flags != want.Flags || got.ServerChallenge != want.ServerChallenge ||
			got.TargetName != want.TargetName || !bytes.Equal(got.TargetInfo, want.TargetInfo) {
			t.Fatalf("case %d round trip mismatch: %+v vs %+v", i, got, want)
		}
		if (got.Version == nil) != (want.Version == nil) {
			t.Fatalf("case %d version presence mismatch", i)
		}
	}
}

func TestAuthenticateRoundTrip(t *testing.T) {
	mic := [16]byte{1, 2, 3}
	cases := []AuthenticateMessage{
		{
			Flags:               DefaultNegotiateFlags,
			Domain:              "Domain",
			User:                "User",
			Workstation:         "WORKSTATION",
			NTChallengeResponse: bytes.Repeat([]byte{0xAB}, 48),
			LMChallengeResponse: bytes.Repeat([]byte{0xCD}, 24),
			Version:             sampleVersion(),
		},
		{
			Flags:                     DefaultNegotiateFlags | NEGOTIATE_VERSION,
			Domain:                    "Ünïcödé-домен",
			User:                      "ユーザー",
			Workstation:               "W",
			NTChallengeResponse:       []byte{1},
			EncryptedRandomSessionKey: []byte{9, 9, 9},
			Version:                   sampleVersion(),
			MIC:                       &mic,
		},
		{
			Flags: NEGOTIATE_UNICODE | NEGOTIATE_NTLM,
			User:  "u",
		},
	}
	for i, want := range cases {
		b, err := want.Marshal()
		if err != nil {
			t.Fatalf("case %d marshal: %v", i, err)
		}
		got, err := ParseAuthenticate(b)
		if err != nil {
			t.Fatalf("case %d parse: %v", i, err)
		}
		if got.Flags != want.Flags || got.Domain != want.Domain || got.User != want.User ||
			got.Workstation != want.Workstation ||
			!bytes.Equal(got.NTChallengeResponse, want.NTChallengeResponse) ||
			!bytes.Equal(got.LMChallengeResponse, want.LMChallengeResponse) ||
			!bytes.Equal(got.EncryptedRandomSessionKey, want.EncryptedRandomSessionKey) {
			t.Fatalf("case %d round trip mismatch:\n got %+v\nwant %+v", i, got, want)
		}
		if (got.MIC == nil) != (want.MIC == nil) {
			t.Fatalf("case %d MIC presence = %v, want %v", i, got.MIC != nil, want.MIC != nil)
		}
		if got.MIC != nil && *got.MIC != *want.MIC {
			t.Fatalf("case %d MIC mismatch", i)
		}
		if (got.Version == nil) != (want.Version == nil) {
			t.Fatalf("case %d version presence mismatch", i)
		}
		again, err := got.Marshal()
		if err != nil {
			t.Fatalf("case %d re-marshal: %v", i, err)
		}
		if !bytes.Equal(b, again) {
			t.Fatalf("case %d re-marshal differs", i)
		}
	}
}

// TestAuthenticateMICDetection checks the header-length heuristic against
// messages with and without the optional MIC field.
func TestAuthenticateMICDetection(t *testing.T) {
	base := AuthenticateMessage{Flags: NEGOTIATE_UNICODE, User: "u", NTChallengeResponse: []byte{1, 2, 3}}
	withoutMIC, err := base.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseAuthenticate(withoutMIC)
	if err != nil {
		t.Fatal(err)
	}
	if got.MIC != nil {
		t.Fatal("MIC must not be detected when absent")
	}
	mic := [16]byte{7}
	withMIC := base
	withMIC.MIC = &mic
	b, err := withMIC.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err = ParseAuthenticate(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.MIC == nil || *got.MIC != mic {
		t.Fatal("MIC must round trip")
	}
}

// TestMalformedNegotiate feeds truncated and corrupted NEGOTIATE messages to
// the parser and requires errors instead of panics.
func TestMalformedNegotiate(t *testing.T) {
	good, err := NegotiateMessage{Flags: DefaultNegotiateFlags, Domain: "DOM", Workstation: "WS"}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"empty":        {},
		"short":        good[:10],
		"no-signature": append([]byte("XXXXXXXX"), good[8:]...),
		"wrong-type":   withU32(good, 8, 0x00000042),
		"buf-overrun":  withU16(good, 16, 0xFFFF),
		"buf-offset":   withU32(good, 20, 0xFFFFFF00),
		"bad-utf16":    withU16(good, 24, 1), // odd-length Unicode payload
	}
	for name, b := range cases {
		if _, err := ParseNegotiate(b); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestMalformedChallenge(t *testing.T) {
	good, err := ChallengeMessage{Flags: DefaultNegotiateFlags, TargetName: "T", TargetInfo: []byte{0, 0, 0, 0}}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"empty":        {},
		"short":        good[:30],
		"wrong-type":   withU32(good, 8, 1),
		"buf-overrun":  withU16(good, 12, 0xFFFF),
		"buf-offset":   withU32(good, 16, 0x7FFFFFF0),
		"info-overrun": withU16(good, 40, 0x4000),
	}
	for name, b := range cases {
		if _, err := ParseChallenge(b); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestMalformedAuthenticate(t *testing.T) {
	good, err := AuthenticateMessage{
		Flags: NEGOTIATE_UNICODE, User: "u", Domain: "d", Workstation: "w",
		NTChallengeResponse: []byte{1, 2, 3}, LMChallengeResponse: []byte{4, 5, 6},
	}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"empty":       {},
		"short":       good[:40],
		"wrong-type":  withU32(good, 8, 2),
		"buf-overrun": withU16(good, 20, 0xFFFF),
		"buf-offset":  withU32(good, 24, 0xFFFFFF00),
		"header-cut":  good[:63],
	}
	for name, b := range cases {
		if _, err := ParseAuthenticate(b); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

// TestParseNeverPanicsOnRandomInput fuzzes the parsers with deterministic
// pseudo-random buffers; they must return errors or values, never panic.
func TestParseNeverPanicsOnRandomInput(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	buf := make([]byte, 256)
	for i := 0; i < 20000; i++ {
		n := rng.Intn(len(buf))
		b := buf[:n]
		for j := range b {
			b[j] = byte(rng.Intn(256))
		}
		if rng.Intn(2) == 0 {
			// Bias some samples toward a valid signature so field parsing runs.
			copy(b, signature[:])
		}
		_, _ = ParseNegotiate(b)
		_, _ = ParseChallenge(b)
		_, _ = ParseAuthenticate(b)
	}
}

func withU16(b []byte, off int, v uint16) []byte {
	out := append([]byte(nil), b...)
	binary.LittleEndian.PutUint16(out[off:], v)
	return out
}

func withU32(b []byte, off int, v uint32) []byte {
	out := append([]byte(nil), b...)
	binary.LittleEndian.PutUint32(out[off:], v)
	return out
}
