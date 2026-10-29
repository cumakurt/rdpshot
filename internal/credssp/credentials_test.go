package credssp

import (
	"encoding/asn1"
	"testing"
)

func TestBuildPasswordCredentialsRoundTrip(t *testing.T) {
	der, err := BuildPasswordCredentials("DOMAIN", "alice", "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil || len(rest) != 0 {
		t.Fatalf("outer: err=%v rest=%d", err, len(rest))
	}
	if outer.Tag != asn1.TagSequence {
		t.Fatalf("tag=%d", outer.Tag)
	}
	if len(der) < 20 {
		t.Fatalf("credentials der too short: %d", len(der))
	}
}

func TestUTF16LE(t *testing.T) {
	got := utf16LE("AB")
	want := []byte{'A', 0, 'B', 0}
	if string(got) != string(want) {
		t.Fatalf("got %v want %v", got, want)
	}
}
