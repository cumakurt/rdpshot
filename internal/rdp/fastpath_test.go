package rdp

import (
	"bytes"
	"testing"
)

func TestParseFastPathLength(t *testing.T) {
	total, header, err := parseFastPathLength([]byte{0x00, 0x05})
	if err != nil || total != 5 || header != 2 {
		t.Fatalf("short length: total=%d header=%d err=%v", total, header, err)
	}
	total, header, err = parseFastPathLength([]byte{0x00, 0x80, 0x10})
	if err != nil || total != 0x10 || header != 3 {
		t.Fatalf("long length: total=%d header=%d err=%v", total, header, err)
	}
}

func TestApplyFastPathBitmap(t *testing.T) {
	fb := NewFramebuffer(64, 64)
	// Minimal fast-path update: bitmap code with empty body (skipped safely).
	payload := []byte{0x01, 0x00}
	b, o, err := fb.applyFastPathUpdates(payload, newBitmapCache())
	if err != nil {
		t.Fatal(err)
	}
	if b != 0 || o != 0 {
		t.Fatalf("empty bitmap update: bitmaps=%d orders=%d", b, o)
	}
}

func TestIsFastPathHeader(t *testing.T) {
	if isFastPathHeader([]byte{0x03, 0x00}) {
		t.Fatal("TPKT must not look like fast-path")
	}
	if !isFastPathHeader([]byte{0x00, 0x04}) {
		t.Fatal("expected fast-path header")
	}
}

func TestReadFastPathPayload(t *testing.T) {
	frame := []byte{0x00, 0x05, 0xaa, 0xbb, 0xcc}
	body, err := readFastPathPayload(frame)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, []byte{0xaa, 0xbb, 0xcc}) {
		t.Fatalf("body = %x", body)
	}
}
