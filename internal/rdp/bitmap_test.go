package rdp

import (
	"encoding/binary"
	"testing"
)

func TestApplyUncompressedBitmap16(t *testing.T) {
	fb := NewFramebuffer(32, 32)
	// One 2x2 16-bpp uncompressed rectangle at (1,1).
	width, height, bpp := 2, 2, 16
	stride := (width*bpp/8 + 3) &^ 3
	raw := make([]byte, stride*height)
	// Bottom-up: row0 (bottom) blue-ish, row1 (top) red-ish.
	binary.LittleEndian.PutUint16(raw[0:2], 0x001F) // blue
	binary.LittleEndian.PutUint16(raw[2:4], 0x001F)
	binary.LittleEndian.PutUint16(raw[stride:stride+2], 0xF800) // red
	binary.LittleEndian.PutUint16(raw[stride+2:stride+4], 0xF800)

	payload := make([]byte, 0, 20+len(raw))
	payload = binary.LittleEndian.AppendUint16(payload, 1) // nRect
	payload = binary.LittleEndian.AppendUint16(payload, 1) // left
	payload = binary.LittleEndian.AppendUint16(payload, 1) // top
	payload = binary.LittleEndian.AppendUint16(payload, 2) // right
	payload = binary.LittleEndian.AppendUint16(payload, 2) // bottom
	payload = binary.LittleEndian.AppendUint16(payload, uint16(width))
	payload = binary.LittleEndian.AppendUint16(payload, uint16(height))
	payload = binary.LittleEndian.AppendUint16(payload, uint16(bpp))
	payload = binary.LittleEndian.AppendUint16(payload, 0) // flags uncompressed
	payload = binary.LittleEndian.AppendUint16(payload, uint16(len(raw)))
	payload = append(payload, raw...)

	n, err := fb.ApplyBitmapUpdate(payload)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("applied=%d", n)
	}
	r, g, b, a := fb.Img.At(1, 1).RGBA()
	if a>>8 != 255 || r>>8 < 200 || b>>8 > 50 {
		t.Fatalf("pixel(1,1)=#%02x%02x%02x want red-ish", r>>8, g>>8, b>>8)
	}
	if fb.PaintedFraction() <= 0 {
		t.Fatal("expected painted pixels")
	}
}

func TestDecompressRLESolid(t *testing.T) {
	// 4 pixels of 16-bpp solid colour via RLE runs of count=2 twice.
	color := []byte{0x1F, 0x00} // blue 565
	src := []byte{0x02, color[0], color[1], 0x02, color[0], color[1]}
	raw, err := decompressRLE(2, 2, 16, src)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 8 {
		t.Fatalf("len=%d", len(raw))
	}
}
