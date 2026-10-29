package ntlm

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestRC4KnownVectors pins the RC4 implementation against the well-known
// Wikipedia test vectors.
func TestRC4KnownVectors(t *testing.T) {
	cases := []struct{ key, plain, cipher string }{
		{"Key", "Plaintext", "bbf316e8d940af0ad3"},
		{"Wiki", "pedia", "1021bf0420"},
		{"Secret", "Attack at dawn", "45a01f645fc35b383552544b9bf5"},
	}
	for _, c := range cases {
		want, err := hex.DecodeString(c.cipher)
		if err != nil {
			t.Fatal(err)
		}
		enc := newRC4([]byte(c.key))
		got := make([]byte, len(c.plain))
		enc.xorKeyStream(got, []byte(c.plain))
		if !bytes.Equal(got, want) {
			t.Errorf("RC4(%q, %q) = %x, want %s", c.key, c.plain, got, c.cipher)
		}
		dec := newRC4([]byte(c.key))
		back := make([]byte, len(got))
		dec.xorKeyStream(back, got)
		if string(back) != c.plain {
			t.Errorf("RC4 decrypt(%q) = %q, want %q", c.key, back, c.plain)
		}
	}
}

func newPair(t *testing.T, key []byte) (*SessionSecurity, *SessionSecurity) {
	t.Helper()
	client := NewSessionSecurity(key, DefaultNegotiateFlags, true)
	server := NewSessionSecurity(key, DefaultNegotiateFlags, false)
	return client, server
}

// TestSealUnsealRoundTrip checks Unseal(Seal(p)) == p for several inputs
// across a client/server session pair and over consecutive messages.
func TestSealUnsealRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x5A}, 16)
	client, server := newPair(t, key)

	inputs := [][]byte{
		{},
		{0x00},
		[]byte("public key material"),
		bytes.Repeat([]byte{0xFF}, 1024),
		[]byte("Ünïcödé payload 日本語"),
	}
	for i, p := range inputs {
		sealed := client.Seal(p)
		if len(sealed) != SignatureLen+len(p) {
			t.Fatalf("input %d: sealed length = %d, want %d", i, len(sealed), SignatureLen+len(p))
		}
		got, err := server.Unseal(sealed)
		if err != nil {
			t.Fatalf("input %d: unseal: %v", i, err)
		}
		if !bytes.Equal(got, p) {
			t.Fatalf("input %d: round trip mismatch: %x vs %x", i, got, p)
		}
	}

	// Server to client direction uses the other key pair.
	for i, p := range inputs {
		sealed := server.Seal(p)
		got, err := client.Unseal(sealed)
		if err != nil {
			t.Fatalf("reverse input %d: unseal: %v", i, err)
		}
		if !bytes.Equal(got, p) {
			t.Fatalf("reverse input %d: round trip mismatch", i)
		}
	}
}

// TestSealUnsealOppositeDirectionsUseDifferentKeys ensures the two
// directions are cryptographically independent.
func TestSealUnsealOppositeDirectionsUseDifferentKeys(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 16)
	client, server := newPair(t, key)
	sealed := client.Seal([]byte("msg"))
	if _, err := client.Unseal(sealed); err == nil {
		t.Fatal("client must not unseal its own send stream with the recv key")
	}
	if _, err := server.Unseal(server.Seal([]byte("x"))); err == nil {
		t.Fatal("server must not unseal its own send stream with the recv key")
	}
}

// TestUnsealDetectsTamper flips a ciphertext byte and requires an error.
func TestUnsealDetectsTamper(t *testing.T) {
	key := bytes.Repeat([]byte{0x22}, 16)
	client, server := newPair(t, key)
	sealed := client.Seal([]byte("important public key"))

	tampered := append([]byte(nil), sealed...)
	tampered[SignatureLen+3] ^= 0x01
	if _, err := server.Unseal(tampered); err == nil {
		t.Fatal("tampered plaintext must be rejected")
	}

	tampered = append([]byte(nil), sealed...)
	tampered[5] ^= 0x01 // inside the checksum
	if _, err := server.Unseal(tampered); err == nil {
		t.Fatal("tampered checksum must be rejected")
	}

	if _, err := server.Unseal(sealed[:10]); err == nil {
		t.Fatal("truncated sealed message must be rejected")
	}
}

// TestUnsealRejectsOutOfOrderMessages pins the lockstep sequence numbers.
// The RC4 handle is persistent per direction (MS-NLMP handle semantics), so a
// rejected message desynchronizes the stream: the errors below prove the
// checks fire, and callers must abort the session after any of them.
func TestUnsealRejectsOutOfOrderMessages(t *testing.T) {
	key := bytes.Repeat([]byte{0x33}, 16)

	// Out-of-order delivery must fail.
	client, server := newPair(t, key)
	first := client.Seal([]byte("first"))
	second := client.Seal([]byte("second"))
	if _, err := server.Unseal(second); err == nil {
		t.Fatal("out-of-order message must be rejected")
	}

	// Replay of an already-seen message must fail.
	client, server = newPair(t, key)
	first = client.Seal([]byte("first"))
	if _, err := server.Unseal(first); err != nil {
		t.Fatalf("fresh message rejected: %v", err)
	}
	if _, err := server.Unseal(first); err == nil {
		t.Fatal("replayed message must be rejected")
	}

	// In-order continuation keeps working across many messages.
	client, server = newPair(t, key)
	for i := 0; i < 8; i++ {
		msg := []byte{byte(i)}
		if _, err := server.Unseal(client.Seal(msg)); err != nil {
			t.Fatalf("message %d rejected: %v", i, err)
		}
	}
}

// TestSignBlock checks the signature block layout: version 1 first.
func TestSignBlock(t *testing.T) {
	key := bytes.Repeat([]byte{0x44}, 16)
	client, _ := newPair(t, key)
	sig := client.Sign([]byte("message"))
	if len(sig) != SignatureLen {
		t.Fatalf("signature length = %d, want %d", len(sig), SignatureLen)
	}
	if sig[0] != 0x01 || sig[1] != 0x00 || sig[2] != 0x00 || sig[3] != 0x00 {
		t.Fatalf("signature must start with version 1, got %x", sig[:4])
	}
	// Sequence number zero in the first block.
	if sig[12] != 0 || sig[13] != 0 || sig[14] != 0 || sig[15] != 0 {
		t.Fatalf("first signature must carry sequence number 0, got %x", sig[12:])
	}
	sig2 := client.Sign([]byte("message"))
	if sig2[12] != 1 {
		t.Fatalf("second signature must carry sequence number 1, got %x", sig2[12:])
	}
	if bytes.Equal(sig[4:12], sig2[4:12]) {
		t.Fatal("checksums must differ with the sequence number")
	}
}

// TestExportedSessionKey pins the no-key-exchange derivation: the exported
// session key is the session base key.
func TestExportedSessionKey(t *testing.T) {
	base := bytes.Repeat([]byte{0x77}, 16)
	got := ExportedSessionKey(base)
	if !bytes.Equal(got, base) {
		t.Fatal("exported session key must equal the session base key")
	}
	got[0] ^= 0xFF
	if base[0] == got[0] {
		t.Fatal("ExportedSessionKey must return a copy")
	}
}
