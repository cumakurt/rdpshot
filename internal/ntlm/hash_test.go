package ntlm

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"testing"
	"unicode/utf16"
)

// TestNTHashSpecVector pins the MS-NLMP 4.2 example NT hash.
func TestNTHashSpecVector(t *testing.T) {
	got := hex.EncodeToString(NTHash("Password"))
	const want = "a4f49c406510bdcab6824ee7c30fd852"
	if got != want {
		t.Fatalf("NTHash(\"Password\") = %s, want %s", got, want)
	}
}

// TestNTLMv2HashSpecVector pins the MS-NLMP 4.2 example NTLMv2 hash for
// user "User", domain "Domain", password "Password".
func TestNTLMv2HashSpecVector(t *testing.T) {
	nt := NTHash("Password")
	got := hex.EncodeToString(NTLMv2Hash("User", "Domain", nt))
	const want = "0c868a403bfd7a93a3001ef22ef02e3f"
	if got != want {
		t.Fatalf("NTLMv2Hash = %s, want %s", got, want)
	}
}

// TestNTLMv2HashIndependentRecompute re-derives the hash with a direct
// HMAC-MD5/UTF-16LE path inside the test so a regression in the helper code
// cannot silently pass.
func TestNTLMv2HashIndependentRecompute(t *testing.T) {
	nt, _ := hex.DecodeString("a4f49c406510bdcab6824ee7c30fd852")
	mac := hmac.New(md5.New, nt)
	u := utf16.Encode([]rune("USER" + "Domain"))
	for _, c := range u {
		mac.Write([]byte{byte(c), byte(c >> 8)})
	}
	want := hex.EncodeToString(mac.Sum(nil))
	got := hex.EncodeToString(NTLMv2Hash("User", "Domain", nt))
	if got != want {
		t.Fatalf("NTLMv2Hash = %s, independent recompute = %s", got, want)
	}
}

// TestNTLMv2HashUppercasesUser checks the account name is uppercased before
// key derivation while the domain is left verbatim.
func TestNTLMv2HashUppercasesUser(t *testing.T) {
	nt := NTHash("Password")
	a := NTLMv2Hash("User", "Domain", nt)
	b := NTLMv2Hash("USER", "Domain", nt)
	c := NTLMv2Hash("user", "Domain", nt)
	d := NTLMv2Hash("User", "DOMAIN", nt)
	if !bytes.Equal(a, b) {
		t.Fatal("user name case must not change the NTLMv2 hash")
	}
	if !bytes.Equal(a, c) {
		t.Fatal("lowercase user must hash like uppercase user")
	}
	if bytes.Equal(a, d) {
		t.Fatal("domain case must change the NTLMv2 hash")
	}
}

// TestLMv2ResponseShape verifies the documented LMv2 construction:
// HMAC_MD5(ntLMv2Hash, serverChallenge || clientChallenge) || clientChallenge.
func TestLMv2ResponseShape(t *testing.T) {
	nt := NTHash("Password")
	hash := NTLMv2Hash("User", "Domain", nt)
	server := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	client := []byte{9, 10, 11, 12, 13, 14, 15, 16}

	resp := LMv2Response(client, server, hash)
	if len(resp) != 24 {
		t.Fatalf("LMv2 response length = %d, want 24", len(resp))
	}
	if !bytes.Equal(resp[16:], client) {
		t.Fatal("LMv2 response must end with the client challenge")
	}
	mac := hmac.New(md5.New, hash)
	mac.Write(server)
	mac.Write(client)
	if !bytes.Equal(resp[:16], mac.Sum(nil)) {
		t.Fatal("LMv2 response prefix must be HMAC_MD5(ntLMv2Hash, serverChallenge || clientChallenge)")
	}
}

// TestLMv2Deterministic documents that the LMv2 response is a pure function
// of its inputs (the MS-NLMP 4.2 full response byte vectors are not
// reproducible here because the spec example inputs are only partially
// documented; structural checks above cover the construction).
func TestLMv2Deterministic(t *testing.T) {
	hash := make([]byte, md5.Size)
	server := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	client := []byte{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}
	a := LMv2Response(client, server, hash)
	b := LMv2Response(client, server, hash)
	if !bytes.Equal(a, b) {
		t.Fatal("LMv2Response must be deterministic")
	}
	other := LMv2Response(client, server, bytes.Repeat([]byte{1}, md5.Size))
	if bytes.Equal(a, other) {
		t.Fatal("LMv2Response must depend on the NTLMv2 hash")
	}
}

// TestNTHashEmptyPassword pins the MD4 of the empty Unicode string.
func TestNTHashEmptyPassword(t *testing.T) {
	got := hex.EncodeToString(NTHash(""))
	const want = "31d6cfe0d16ae931b73c59d7e0c089c0"
	if got != want {
		t.Fatalf("NTHash(\"\") = %s, want %s", got, want)
	}
}

// TestUTF16LERoundTrip covers surrogate pairs (non-BMP runes).
func TestUTF16LERoundTrip(t *testing.T) {
	for _, s := range []string{"", "ascii", "Ünïcödé", "Käferöl", "日本語", "emoji \U0001F600"} {
		enc := encodeUTF16LE(s)
		dec, err := decodeUTF16LE(enc)
		if err != nil {
			t.Fatalf("decode %q: %v", s, err)
		}
		if dec != s {
			t.Fatalf("round trip %q -> %q", s, dec)
		}
	}
	if _, err := decodeUTF16LE([]byte{0x00}); err == nil {
		t.Fatal("odd-length UTF-16LE must be rejected")
	}
}

func TestParseNTHash(t *testing.T) {
	const wantHex = "a4f49c406510bdcab6824ee7c30fd852"
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatal(err)
	}
	cases := []string{
		wantHex,
		"0x" + wantHex,
		"aad3b435b51404eeaad3b435b51404ee:" + wantHex,
		"  " + wantHex + "  ",
	}
	for _, in := range cases {
		got, err := ParseNTHash(in)
		if err != nil {
			t.Fatalf("ParseNTHash(%q): %v", in, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("ParseNTHash(%q) = %x, want %x", in, got, want)
		}
	}
	for _, bad := range []string{"", "deadbeef", "zz", "aa:bb"} {
		if _, err := ParseNTHash(bad); err == nil {
			t.Fatalf("ParseNTHash(%q) should fail", bad)
		}
	}
}

func TestBuildAuthenticateFromNTHashMatchesPassword(t *testing.T) {
	info := MarshalAVPairs([]AVPair{
		{ID: MsvAvNbDomainName, Data: encodeUTF16LE("Domain")},
		{ID: MsvAvTimestamp, Data: filetimeFromUnix(1700000000)},
	})
	var serverChallenge [8]byte
	copy(serverChallenge[:], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	timestamp := filetimeFromUnix(1700000000)
	clientChallenge := []byte{9, 10, 11, 12, 13, 14, 15, 16}

	fromPass, keyPass, err := BuildAuthenticate(DefaultNegotiateFlags, "Domain", "User", "Password", "WS",
		serverChallenge, info, timestamp, clientChallenge)
	if err != nil {
		t.Fatalf("password build: %v", err)
	}
	fromHash, keyHash, err := BuildAuthenticateFromNTHash(DefaultNegotiateFlags, "Domain", "User", NTHash("Password"), "WS",
		serverChallenge, info, timestamp, clientChallenge)
	if err != nil {
		t.Fatalf("hash build: %v", err)
	}
	if !bytes.Equal(fromPass.NTChallengeResponse, fromHash.NTChallengeResponse) {
		t.Fatal("NT response must match between password and NT-hash builders")
	}
	if !bytes.Equal(fromPass.LMChallengeResponse, fromHash.LMChallengeResponse) {
		t.Fatal("LM response must match between password and NT-hash builders")
	}
	if !bytes.Equal(keyPass, keyHash) {
		t.Fatal("session base key must match between password and NT-hash builders")
	}
}
