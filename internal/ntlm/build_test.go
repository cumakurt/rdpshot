package ntlm

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"testing"
)

func TestBuildAuthenticateConsistency(t *testing.T) {
	info := MarshalAVPairs([]AVPair{
		{ID: MsvAvNbDomainName, Data: encodeUTF16LE("Domain")},
		{ID: MsvAvTimestamp, Data: filetimeFromUnix(1700000000)},
	})
	var serverChallenge [8]byte
	copy(serverChallenge[:], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	timestamp := filetimeFromUnix(1700000000)
	clientChallenge := []byte{9, 10, 11, 12, 13, 14, 15, 16}

	msg, baseKey, err := BuildAuthenticate(DefaultNegotiateFlags, "Domain", "User", "Password", "WS",
		serverChallenge, info, timestamp, clientChallenge)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if msg.User != "User" || msg.Domain != "Domain" || msg.Workstation != "WS" {
		t.Fatalf("identity fields wrong: %+v", msg)
	}
	if len(msg.NTChallengeResponse) < 16 {
		t.Fatalf("NT response too short: %d", len(msg.NTChallengeResponse))
	}

	// Independent recomputation of NTProofStr and the blob per MS-NLMP 3.3.
	ntLMv2Hash := NTLMv2Hash("User", "Domain", NTHash("Password"))
	blob := msg.NTChallengeResponse[16:]
	proof := hmacMD5(ntLMv2Hash, serverChallenge[:], blob)
	if !bytes.Equal(msg.NTChallengeResponse[:16], proof) {
		t.Fatal("NTProofStr mismatch against independent HMAC_MD5 computation")
	}
	if len(baseKey) != md5.Size {
		t.Fatalf("session base key length = %d, want %d", len(baseKey), md5.Size)
	}
	wantKey := hmac.New(md5.New, ntLMv2Hash)
	wantKey.Write(proof)
	if !bytes.Equal(baseKey, wantKey.Sum(nil)) {
		t.Fatal("session base key must be HMAC_MD5(NTLMv2Hash, NTProofStr)")
	}

	// Blob structure: fixed header, timestamp, client challenge, reserved,
	// target info, reserved tail.
	if blob[0] != 0x01 || blob[1] != 0x01 {
		t.Fatalf("blob response type wrong: %x", blob[:2])
	}
	if !bytes.Equal(blob[8:16], timestamp) {
		t.Fatal("blob timestamp mismatch")
	}
	if !bytes.Equal(blob[16:24], clientChallenge) {
		t.Fatal("blob client challenge mismatch")
	}
	if !bytes.Equal(blob[24:28], []byte{0, 0, 0, 0}) {
		t.Fatal("blob reserved3 must be zero")
	}
	if !bytes.Equal(blob[28:28+len(info)], info) {
		t.Fatal("blob must replay the server target info verbatim")
	}
	if !bytes.Equal(blob[len(blob)-4:], []byte{0, 0, 0, 0}) {
		t.Fatal("blob reserved4 must be zero")
	}

	// LMv2 response shape.
	if len(msg.LMChallengeResponse) != 24 ||
		!bytes.Equal(msg.LMChallengeResponse[16:], clientChallenge) {
		t.Fatalf("LMv2 response malformed: %x", msg.LMChallengeResponse)
	}
}

func TestBuildAuthenticateAddsEOLEOLWhenMissing(t *testing.T) {
	var serverChallenge [8]byte
	msg, _, err := BuildAuthenticate(DefaultNegotiateFlags, "", "u", "p", "",
		serverChallenge, []byte{0x02, 0x00, 0x02, 0x00, 0x41, 0x00}, make([]byte, 8), make([]byte, 8))
	if err != nil {
		t.Fatal(err)
	}
	blob := msg.NTChallengeResponse[16:]
	// AV pair data + EOL terminator + reserved4.
	if !bytes.Equal(blob[len(blob)-8:], make([]byte, 8)) {
		t.Fatalf("blob must end with EOL terminator and reserved4, got %x", blob[len(blob)-8:])
	}
}

func TestBuildAuthenticateInputValidation(t *testing.T) {
	var serverChallenge [8]byte
	if _, _, err := BuildAuthenticate(DefaultNegotiateFlags, "", "u", "p", "",
		serverChallenge, nil, []byte{1}, make([]byte, 8)); err == nil {
		t.Fatal("short timestamp must be rejected")
	}
	if _, _, err := BuildAuthenticate(DefaultNegotiateFlags, "", "u", "p", "",
		serverChallenge, nil, make([]byte, 8), []byte{1}); err == nil {
		t.Fatal("short client challenge must be rejected")
	}
}

// TestBuildAuthenticateMarshals checks the built message survives wire
// encoding and that the version field appears with the NEGOTIATE_VERSION flag.
func TestBuildAuthenticateMarshals(t *testing.T) {
	var serverChallenge [8]byte
	msg, _, err := BuildAuthenticate(DefaultNegotiateFlags, "Domain", "User", "Password", "WS",
		serverChallenge, nil, make([]byte, 8), make([]byte, 8))
	if err != nil {
		t.Fatal(err)
	}
	b, err := msg.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseAuthenticate(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.User != "User" || got.Version == nil {
		t.Fatalf("parsed message incomplete: %+v", got)
	}
	if !bytes.Equal(got.NTChallengeResponse, msg.NTChallengeResponse) {
		t.Fatal("NT response lost in round trip")
	}
}
