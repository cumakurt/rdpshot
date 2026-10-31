package rdp

import (
	"encoding/binary"
	"image/color"
	"testing"
)

func TestBuildCapsAdvertiseAndParseConfirm(t *testing.T) {
	adv := BuildCapsAdvertise(CapsSet{Version: CapsVersion107, Flags: 0x01})
	if len(adv) < 8 {
		t.Fatalf("advertisement too short: %d", len(adv))
	}
	cmdID := binary.LittleEndian.Uint16(adv[0:2])
	if cmdID != CmdIDCapsAdvertise {
		t.Errorf("cmdID = 0x%04x, want 0x%04x", cmdID, CmdIDCapsAdvertise)
	}

	// Fake server confirm PDU
	confirmPDU := make([]byte, 20)
	binary.LittleEndian.PutUint16(confirmPDU[0:2], CmdIDCapsConfirm)
	binary.LittleEndian.PutUint16(confirmPDU[2:4], 0)
	binary.LittleEndian.PutUint32(confirmPDU[4:8], 20)
	binary.LittleEndian.PutUint32(confirmPDU[8:12], CapsVersion107)
	binary.LittleEndian.PutUint32(confirmPDU[12:16], 4)
	binary.LittleEndian.PutUint32(confirmPDU[16:20], 0x01)

	caps, err := ParseCapsConfirm(confirmPDU)
	if err != nil {
		t.Fatalf("ParseCapsConfirm error: %v", err)
	}
	if caps.Version != CapsVersion107 {
		t.Errorf("caps version = 0x%08x, want 0x%08x", caps.Version, CapsVersion107)
	}
	if caps.Flags != 0x01 {
		t.Errorf("caps flags = 0x%08x, want 0x01", caps.Flags)
	}
}

func TestDVCFraming(t *testing.T) {
	// DVC Create Request for graphics channel
	name := DVCGraphicsChannelName + "\x00"
	req := append([]byte{(dvcCmdCreateRequest << 4) | 0x01, 0x05, 0x00}, []byte(name)...)

	chID, chName, err := ParseDVCCreateRequest(req)
	if err != nil {
		t.Fatalf("ParseDVCCreateRequest error: %v", err)
	}
	if chID != 5 {
		t.Errorf("chID = %d, want 5", chID)
	}
	if chName != DVCGraphicsChannelName {
		t.Errorf("chName = %q, want %q", chName, DVCGraphicsChannelName)
	}

	rsp := BuildDVCCreateResponse(5, 0)
	if len(rsp) != 9 {
		t.Fatalf("rsp len = %d, want 9", len(rsp))
	}

	dataPDU := BuildDVCData(5, []byte("hello graphics"))
	parsedID, parsedData, err := ParseDVCData(dataPDU)
	if err != nil {
		t.Fatalf("ParseDVCData error: %v", err)
	}
	if parsedID != 5 {
		t.Errorf("parsedID = %d, want 5", parsedID)
	}
	if string(parsedData) != "hello graphics" {
		t.Errorf("parsedData = %q, want 'hello graphics'", string(parsedData))
	}
}

func TestGFXDecoderSurfacesAndFills(t *testing.T) {
	fb := NewFramebuffer(640, 480)
	dec := NewGFXDecoder(fb)

	// 1. Create Surface 1 (320x240)
	createPDU := make([]byte, 15)
	binary.LittleEndian.PutUint16(createPDU[0:2], CmdIDCreateSurface)
	binary.LittleEndian.PutUint32(createPDU[4:8], 15)
	binary.LittleEndian.PutUint16(createPDU[8:10], 1)    // surfaceId 1
	binary.LittleEndian.PutUint16(createPDU[10:12], 320) // width
	binary.LittleEndian.PutUint16(createPDU[12:14], 240) // height
	createPDU[14] = PixelFormatXRGB8888

	n, err := dec.DecodePDU(createPDU)
	if err != nil || n != 1 {
		t.Fatalf("CreateSurface decode error: %v (n=%d)", err, n)
	}
	if len(dec.Surfaces) != 1 || dec.Surfaces[1] == nil {
		t.Fatalf("surface 1 not created")
	}

	// 2. Map Surface 1 to Output (0,0)
	mapPDU := make([]byte, 20)
	binary.LittleEndian.PutUint16(mapPDU[0:2], CmdIDMapSurfaceToOutput)
	binary.LittleEndian.PutUint32(mapPDU[4:8], 20)
	binary.LittleEndian.PutUint16(mapPDU[8:10], 1)
	binary.LittleEndian.PutUint32(mapPDU[12:16], 0) // originX
	binary.LittleEndian.PutUint32(mapPDU[16:20], 0) // originY

	n, err = dec.DecodePDU(mapPDU)
	if err != nil || n != 1 {
		t.Fatalf("MapSurface decode error: %v (n=%d)", err, n)
	}
	if !dec.Surfaces[1].Mapped {
		t.Errorf("surface 1 should be mapped")
	}

	// 3. Solid Fill (Rect: 0, 0, 100, 100 with Red)
	fillPDU := make([]byte, 24)
	binary.LittleEndian.PutUint16(fillPDU[0:2], CmdIDSolidFill)
	binary.LittleEndian.PutUint32(fillPDU[4:8], 24)
	binary.LittleEndian.PutUint16(fillPDU[8:10], 1)
	fillPDU[10] = 0x00                                 // B
	fillPDU[11] = 0x00                                 // G
	fillPDU[12] = 0xFF                                 // R
	fillPDU[13] = 0xFF                                 // A
	binary.LittleEndian.PutUint16(fillPDU[14:16], 1)   // 1 rect
	binary.LittleEndian.PutUint16(fillPDU[16:18], 0)   // left
	binary.LittleEndian.PutUint16(fillPDU[18:20], 0)   // top
	binary.LittleEndian.PutUint16(fillPDU[20:22], 100) // right
	binary.LittleEndian.PutUint16(fillPDU[22:24], 100) // bottom

	n, err = dec.DecodePDU(fillPDU)
	if err != nil || n != 1 {
		t.Fatalf("SolidFill decode error: %v (n=%d)", err, n)
	}

	// Verify surface pixel
	c := dec.Surfaces[1].Img.At(50, 50).(color.RGBA)
	if c.R != 0xFF || c.G != 0x00 || c.B != 0x00 {
		t.Errorf("surface pixel color = %+v, want Red", c)
	}

	// Verify target FB pixel
	fc := fb.Img.At(50, 50).(color.RGBA)
	if fc.R != 0xFF || fc.G != 0x00 || fc.B != 0x00 {
		t.Errorf("framebuffer pixel color = %+v, want Red", fc)
	}

	if fb.PaintedFraction() <= 0 {
		t.Errorf("fb PaintedFraction should be > 0, got %f", fb.PaintedFraction())
	}

	// 4. EndFrame
	endPDU := make([]byte, 12)
	binary.LittleEndian.PutUint16(endPDU[0:2], CmdIDEndFrame)
	binary.LittleEndian.PutUint32(endPDU[4:8], 12)
	binary.LittleEndian.PutUint32(endPDU[8:12], 1) // frameId 1

	n, err = dec.DecodePDU(endPDU)
	if err != nil || n != 1 {
		t.Fatalf("EndFrame decode error: %v", err)
	}
	if dec.FramesDecoded < 1 {
		t.Errorf("FramesDecoded = %d, want >= 1", dec.FramesDecoded)
	}
}

func TestGFXDecoderWireToSurfaceUncompressed(t *testing.T) {
	fb := NewFramebuffer(320, 240)
	dec := NewGFXDecoder(fb)

	// Create surface 1
	createPDU := make([]byte, 15)
	binary.LittleEndian.PutUint16(createPDU[0:2], CmdIDCreateSurface)
	binary.LittleEndian.PutUint32(createPDU[4:8], 15)
	binary.LittleEndian.PutUint16(createPDU[8:10], 1)
	binary.LittleEndian.PutUint16(createPDU[10:12], 320)
	binary.LittleEndian.PutUint16(createPDU[12:14], 240)
	createPDU[14] = PixelFormatXRGB8888
	_, _ = dec.DecodePDU(createPDU)

	// Map surface 1
	mapPDU := make([]byte, 20)
	binary.LittleEndian.PutUint16(mapPDU[0:2], CmdIDMapSurfaceToOutput)
	binary.LittleEndian.PutUint32(mapPDU[4:8], 20)
	binary.LittleEndian.PutUint16(mapPDU[8:10], 1)
	_, _ = dec.DecodePDU(mapPDU)

	// WireToSurface1: 2x2 uncompressed bitmap at (10, 10, 12, 12)
	// 4 pixels * 4 bytes = 16 bytes: Blue, Green, Red, Yellow
	pixels := []byte{
		0xFF, 0x00, 0x00, 0xFF, // Blue (BGRA)
		0x00, 0xFF, 0x00, 0xFF, // Green
		0x00, 0x00, 0xFF, 0xFF, // Red
		0x00, 0xFF, 0xFF, 0xFF, // Yellow (R+G)
	}

	pduLen := 25 + len(pixels)
	wirePDU := make([]byte, pduLen)
	binary.LittleEndian.PutUint16(wirePDU[0:2], CmdIDWireToSurface1)
	binary.LittleEndian.PutUint32(wirePDU[4:8], uint32(pduLen))
	binary.LittleEndian.PutUint16(wirePDU[8:10], 1) // surfaceId
	binary.LittleEndian.PutUint16(wirePDU[10:12], CodecIDUncompressed)
	wirePDU[12] = PixelFormatARGB8888
	binary.LittleEndian.PutUint16(wirePDU[13:15], 10) // destLeft
	binary.LittleEndian.PutUint16(wirePDU[15:17], 10) // destTop
	binary.LittleEndian.PutUint16(wirePDU[17:19], 12) // destRight
	binary.LittleEndian.PutUint16(wirePDU[19:21], 12) // destBottom
	binary.LittleEndian.PutUint32(wirePDU[21:25], uint32(len(pixels)))
	copy(wirePDU[25:], pixels)

	n, err := dec.DecodePDU(wirePDU)
	if err != nil || n != 1 {
		t.Fatalf("WireToSurface1 decode error: %v", err)
	}

	// Verify Blue pixel at (10, 10)
	c := fb.Img.At(10, 10).(color.RGBA)
	if c.B != 0xFF || c.R != 0x00 {
		t.Errorf("pixel at (10,10) = %+v, want Blue", c)
	}
	// Verify Yellow pixel at (11, 11)
	yc := fb.Img.At(11, 11).(color.RGBA)
	if yc.R != 0xFF || yc.G != 0xFF || yc.B != 0x00 {
		t.Errorf("pixel at (11,11) = %+v, want Yellow", yc)
	}
}
