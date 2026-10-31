package rdp

import (
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"strings"
)

// Dynamic Virtual Channel name for RDP Graphics Pipeline Extension.
const DVCGraphicsChannelName = "Microsoft::Windows::RDS::Graphics"

// DVC Command codes (MS-RDPEDYC 2.2.1).
const (
	dvcCmdCreateRequest  byte = 0x01
	dvcCmdCreateResponse byte = 0x02
	dvcCmdData           byte = 0x03
	dvcCmdDataFirst      byte = 0x04
	dvcCmdClose          byte = 0x05
)

// RDPGFX Command IDs (MS-RDPEGFX 2.2.1).
const (
	CmdIDWireToSurface1        uint16 = 0x0001
	CmdIDWireToSurface2        uint16 = 0x0002
	CmdIDDeleteEncodingContext uint16 = 0x0003
	CmdIDSolidFill             uint16 = 0x0004
	CmdIDSurfaceToSurface      uint16 = 0x0005
	CmdIDSurfaceToCache        uint16 = 0x0006
	CmdIDCacheToSurface        uint16 = 0x0007
	CmdIDEvictCacheEntry       uint16 = 0x0008
	CmdIDCreateSurface         uint16 = 0x0009
	CmdIDDeleteSurface         uint16 = 0x000A
	CmdIDStartFrame            uint16 = 0x000B
	CmdIDEndFrame              uint16 = 0x000C
	CmdIDResetGraphics         uint16 = 0x000E
	CmdIDMapSurfaceToOutput    uint16 = 0x000F
	CmdIDCacheImportSurface    uint16 = 0x0010
	CmdIDCapsAdvertise         uint16 = 0x0012
	CmdIDCapsConfirm           uint16 = 0x0013
	CmdIDFrameMarker           uint16 = 0x0014
)

// RDPGFX Codec IDs (MS-RDPEGFX 2.2.2.1).
const (
	CodecIDUncompressed  uint16 = 0x0000
	CodecIDCAVideo       uint16 = 0x0002
	CodecIDClearCodec    uint16 = 0x0008
	CodecIDPlanar        uint16 = 0x000A
	CodecIDAVC420        uint16 = 0x000B
	CodecIDAlpha         uint16 = 0x000C
	CodecIDCAProgressive uint16 = 0x0009
)

// RDPGFX Pixel Formats.
const (
	PixelFormatXRGB8888 byte = 0x20
	PixelFormatARGB8888 byte = 0x21
)

// RDPGFX Capability Versions.
const (
	CapsVersion8   uint32 = 0x00080004
	CapsVersion81  uint32 = 0x00080105
	CapsVersion10  uint32 = 0x000A0002
	CapsVersion101 uint32 = 0x000A0100
	CapsVersion102 uint32 = 0x000A0200
	CapsVersion107 uint32 = 0x000A0701
)

// CapsSet represents one capability set in CapsAdvertise / CapsConfirm.
type CapsSet struct {
	Version uint32
	Flags   uint32
}

// BuildCapsAdvertise encodes an RDPGFX_CAPS_ADVERTISE_PDU.
func BuildCapsAdvertise(caps ...CapsSet) []byte {
	if len(caps) == 0 {
		caps = []CapsSet{
			{Version: CapsVersion107, Flags: 0},
			{Version: CapsVersion102, Flags: 0},
			{Version: CapsVersion101, Flags: 0},
			{Version: CapsVersion81, Flags: 0},
			{Version: CapsVersion8, Flags: 0},
		}
	}

	bodyLen := 2 + len(caps)*(4+4+4) // capsSetCount(2) + N * (version(4) + length(4) + flags(4))
	totalLen := 8 + bodyLen

	out := make([]byte, totalLen)
	binary.LittleEndian.PutUint16(out[0:2], CmdIDCapsAdvertise)
	binary.LittleEndian.PutUint16(out[2:4], 0) // flags
	binary.LittleEndian.PutUint32(out[4:8], uint32(totalLen))

	binary.LittleEndian.PutUint16(out[8:10], uint16(len(caps)))
	off := 10
	for _, c := range caps {
		binary.LittleEndian.PutUint32(out[off:off+4], c.Version)
		binary.LittleEndian.PutUint32(out[off+4:off+8], 4) // capsDataLength (flags is 4 bytes)
		binary.LittleEndian.PutUint32(out[off+8:off+12], c.Flags)
		off += 12
	}
	return out
}

// ParseCapsConfirm decodes an RDPGFX_CAPS_CONFIRM_PDU.
func ParseCapsConfirm(payload []byte) (CapsSet, error) {
	if len(payload) < 8 {
		return CapsSet{}, fmt.Errorf("rdpgfx: short caps confirm PDU")
	}
	cmdID := binary.LittleEndian.Uint16(payload[0:2])
	if cmdID != CmdIDCapsConfirm {
		return CapsSet{}, fmt.Errorf("rdpgfx: expected CapsConfirm (0x0013), got 0x%04x", cmdID)
	}
	if len(payload) < 8+8 {
		return CapsSet{}, fmt.Errorf("rdpgfx: truncated caps confirm body")
	}
	// Body starts at offset 8: version (4), capsDataLength (4), capsData...
	ver := binary.LittleEndian.Uint32(payload[8:12])
	dataLen := binary.LittleEndian.Uint32(payload[12:16])
	var flags uint32
	if dataLen >= 4 && len(payload) >= 20 {
		flags = binary.LittleEndian.Uint32(payload[16:20])
	}
	return CapsSet{Version: ver, Flags: flags}, nil
}

// ParseDVCCreateRequest extracts ChannelID and ChannelName from a DVC_CREATE_REQ PDU.
func ParseDVCCreateRequest(payload []byte) (uint32, string, error) {
	if len(payload) < 2 {
		return 0, "", fmt.Errorf("dvc: short create request")
	}
	cmd := payload[0] >> 4
	if cmd != dvcCmdCreateRequest {
		return 0, "", fmt.Errorf("dvc: not a create request (cmd=%d)", cmd)
	}
	cbID := payload[0] & 0x03
	var channelID uint32
	off := 1

	switch cbID {
	case 0:
		channelID = uint32(payload[off])
		off += 1
	case 1:
		if len(payload) < off+2 {
			return 0, "", fmt.Errorf("dvc: truncated 16-bit channel id")
		}
		channelID = uint32(binary.LittleEndian.Uint16(payload[off : off+2]))
		off += 2
	case 2:
		if len(payload) < off+4 {
			return 0, "", fmt.Errorf("dvc: truncated 32-bit channel id")
		}
		channelID = binary.LittleEndian.Uint32(payload[off : off+4])
		off += 4
	default:
		return 0, "", fmt.Errorf("dvc: invalid cbId %d", cbID)
	}

	name := strings.TrimRight(string(payload[off:]), "\x00")
	return channelID, name, nil
}

// BuildDVCCreateResponse creates a DVC_CREATE_RSP PDU acknowledging channel creation.
func BuildDVCCreateResponse(channelID uint32, status int32) []byte {
	out := make([]byte, 1+4+4)
	out[0] = (dvcCmdCreateResponse << 4) | 0x02 // 32-bit channel id
	binary.LittleEndian.PutUint32(out[1:5], channelID)
	binary.LittleEndian.PutUint32(out[5:9], uint32(status))
	return out
}

// BuildDVCData encodes user data into a DVC_DATA PDU.
func BuildDVCData(channelID uint32, data []byte) []byte {
	hdr := make([]byte, 1+4)
	hdr[0] = (dvcCmdData << 4) | 0x02 // 32-bit channel id
	binary.LittleEndian.PutUint32(hdr[1:5], channelID)
	return append(hdr, data...)
}

// ParseDVCData extracts channel ID and data payload from a DVC Data PDU.
func ParseDVCData(payload []byte) (uint32, []byte, error) {
	if len(payload) < 2 {
		return 0, nil, fmt.Errorf("dvc: short data PDU")
	}
	cmd := payload[0] >> 4
	if cmd != dvcCmdData && cmd != dvcCmdDataFirst {
		return 0, nil, fmt.Errorf("dvc: not a data PDU (cmd=%d)", cmd)
	}
	cbID := payload[0] & 0x03
	var channelID uint32
	off := 1

	switch cbID {
	case 0:
		channelID = uint32(payload[off])
		off += 1
	case 1:
		if len(payload) < off+2 {
			return 0, nil, fmt.Errorf("dvc: truncated 16-bit channel id")
		}
		channelID = uint32(binary.LittleEndian.Uint16(payload[off : off+2]))
		off += 2
	case 2:
		if len(payload) < off+4 {
			return 0, nil, fmt.Errorf("dvc: truncated 32-bit channel id")
		}
		channelID = binary.LittleEndian.Uint32(payload[off : off+4])
		off += 4
	default:
		return 0, nil, fmt.Errorf("dvc: invalid cbId %d", cbID)
	}

	if cmd == dvcCmdDataFirst {
		// DataFirst carries total length (1-4 bytes)
		if len(payload) < off+4 {
			return 0, nil, fmt.Errorf("dvc: truncated data first length")
		}
		off += 4
	}

	return channelID, payload[off:], nil
}

// Surface represents an allocated graphics surface.
type Surface struct {
	ID      uint16
	Width   int
	Height  int
	Format  byte
	OriginX int
	OriginY int
	Mapped  bool
	Img     *image.RGBA
}

// GFXDecoder manages RDPGFX surfaces and decodes incoming graphics commands.
type GFXDecoder struct {
	Surfaces        map[uint16]*Surface
	TargetFB        *Framebuffer
	CapsConfirmed   bool
	ConfirmedCaps   CapsSet
	FramesDecoded   int
	GraphicsChannel uint32
	Active          bool
}

// NewGFXDecoder initializes a decoder that writes into the target Framebuffer.
func NewGFXDecoder(targetFB *Framebuffer) *GFXDecoder {
	return &GFXDecoder{
		Surfaces: make(map[uint16]*Surface),
		TargetFB: targetFB,
	}
}

// DecodePDU processes a single or concatenated stream of RDPGFX PDUs.
func (d *GFXDecoder) DecodePDU(data []byte) (int, error) {
	applied := 0
	off := 0

	for off+8 <= len(data) {
		cmdID := binary.LittleEndian.Uint16(data[off : off+2])
		pduLen := int(binary.LittleEndian.Uint32(data[off+4 : off+8]))

		if pduLen < 8 || off+pduLen > len(data) {
			break
		}
		pdu := data[off : off+pduLen]
		off += pduLen

		if err := d.dispatchCommand(cmdID, pdu); err == nil {
			applied++
		}
	}
	return applied, nil
}

func (d *GFXDecoder) dispatchCommand(cmdID uint16, pdu []byte) error {
	switch cmdID {
	case CmdIDCapsConfirm:
		caps, err := ParseCapsConfirm(pdu)
		if err == nil {
			d.CapsConfirmed = true
			d.ConfirmedCaps = caps
		}
		return err

	case CmdIDCreateSurface:
		return d.onCreateSurface(pdu)

	case CmdIDDeleteSurface:
		return d.onDeleteSurface(pdu)

	case CmdIDMapSurfaceToOutput:
		return d.onMapSurfaceToOutput(pdu)

	case CmdIDSolidFill:
		return d.onSolidFill(pdu)

	case CmdIDWireToSurface1:
		return d.onWireToSurface1(pdu)

	case CmdIDEndFrame:
		d.FramesDecoded++
		d.blitAllMappedToTarget()
		return nil

	case CmdIDResetGraphics:
		// Reset Graphics reconfigures display monitors; clear surfaces
		d.Surfaces = make(map[uint16]*Surface)
		return nil
	}
	return nil
}

func (d *GFXDecoder) onCreateSurface(pdu []byte) error {
	if len(pdu) < 15 {
		return fmt.Errorf("rdpgfx: short create surface")
	}
	sID := binary.LittleEndian.Uint16(pdu[8:10])
	w := int(binary.LittleEndian.Uint16(pdu[10:12]))
	h := int(binary.LittleEndian.Uint16(pdu[12:14]))
	fmtByte := pdu[14]

	if w <= 0 || h <= 0 {
		return fmt.Errorf("rdpgfx: invalid surface dimensions %dx%d", w, h)
	}

	d.Surfaces[sID] = &Surface{
		ID:     sID,
		Width:  w,
		Height: h,
		Format: fmtByte,
		Img:    image.NewRGBA(image.Rect(0, 0, w, h)),
	}
	return nil
}

func (d *GFXDecoder) onDeleteSurface(pdu []byte) error {
	if len(pdu) < 10 {
		return fmt.Errorf("rdpgfx: short delete surface")
	}
	sID := binary.LittleEndian.Uint16(pdu[8:10])
	delete(d.Surfaces, sID)
	return nil
}

func (d *GFXDecoder) onMapSurfaceToOutput(pdu []byte) error {
	if len(pdu) < 20 {
		return fmt.Errorf("rdpgfx: short map surface")
	}
	sID := binary.LittleEndian.Uint16(pdu[8:10])
	originX := int(binary.LittleEndian.Uint32(pdu[12:16]))
	originY := int(binary.LittleEndian.Uint32(pdu[16:20]))

	surf, ok := d.Surfaces[sID]
	if !ok {
		return fmt.Errorf("rdpgfx: surface %d not found", sID)
	}
	surf.Mapped = true
	surf.OriginX = originX
	surf.OriginY = originY

	d.blitSurfaceToTarget(surf)
	return nil
}

func (d *GFXDecoder) onSolidFill(pdu []byte) error {
	if len(pdu) < 16 {
		return fmt.Errorf("rdpgfx: short solid fill")
	}
	sID := binary.LittleEndian.Uint16(pdu[8:10])
	b := pdu[10]
	g := pdu[11]
	r := pdu[12]
	a := pdu[13]
	if a == 0 {
		a = 0xFF
	}
	fillColor := color.RGBA{R: r, G: g, B: b, A: a}

	surf, ok := d.Surfaces[sID]
	if !ok {
		return fmt.Errorf("rdpgfx: surface %d not found", sID)
	}

	qtyRects := int(binary.LittleEndian.Uint16(pdu[14:16]))
	off := 16
	for i := 0; i < qtyRects; i++ {
		if off+8 > len(pdu) {
			break
		}
		left := int(binary.LittleEndian.Uint16(pdu[off : off+2]))
		top := int(binary.LittleEndian.Uint16(pdu[off+2 : off+4]))
		right := int(binary.LittleEndian.Uint16(pdu[off+4 : off+6]))
		bottom := int(binary.LittleEndian.Uint16(pdu[off+6 : off+8]))
		off += 8

		rect := image.Rect(left, top, right, bottom).Intersect(surf.Img.Bounds())
		draw.Draw(surf.Img, rect, &image.Uniform{fillColor}, image.Point{}, draw.Src)
	}

	if surf.Mapped {
		d.blitSurfaceToTarget(surf)
	}
	d.FramesDecoded++
	return nil
}

func (d *GFXDecoder) onWireToSurface1(pdu []byte) error {
	if len(pdu) < 25 {
		return fmt.Errorf("rdpgfx: short wire to surface 1")
	}
	sID := binary.LittleEndian.Uint16(pdu[8:10])
	codecID := binary.LittleEndian.Uint16(pdu[10:12])
	// pixelFormat := pdu[12]
	destLeft := int(binary.LittleEndian.Uint16(pdu[13:15]))
	destTop := int(binary.LittleEndian.Uint16(pdu[15:17]))
	destRight := int(binary.LittleEndian.Uint16(pdu[17:19]))
	destBottom := int(binary.LittleEndian.Uint16(pdu[19:21]))
	dataLen := int(binary.LittleEndian.Uint32(pdu[21:25]))

	if 25+dataLen > len(pdu) {
		return fmt.Errorf("rdpgfx: wire to surface data truncated")
	}
	raw := pdu[25 : 25+dataLen]

	surf, ok := d.Surfaces[sID]
	if !ok {
		return fmt.Errorf("rdpgfx: surface %d not found", sID)
	}

	w := destRight - destLeft
	h := destBottom - destTop
	if w <= 0 || h <= 0 {
		return nil
	}

	switch codecID {
	case CodecIDUncompressed:
		decodeUncompressedSurface(surf.Img, destLeft, destTop, w, h, raw)
	case CodecIDPlanar:
		decodePlanarSurface(surf.Img, destLeft, destTop, w, h, raw)
	default:
		// Attempt fallback raw decode for arbitrary rectangular payloads
		decodeUncompressedSurface(surf.Img, destLeft, destTop, w, h, raw)
	}

	if surf.Mapped {
		d.blitSurfaceToTarget(surf)
	}
	d.FramesDecoded++
	return nil
}

func decodeUncompressedSurface(dst *image.RGBA, destLeft, destTop, w, h int, raw []byte) {
	stride := w * 4
	si := 0
	for y := 0; y < h; y++ {
		dy := destTop + y
		if dy < 0 || dy >= dst.Bounds().Dy() {
			si += stride
			continue
		}
		for x := 0; x < w; x++ {
			dx := destLeft + x
			if dx < 0 || dx >= dst.Bounds().Dx() || si+3 >= len(raw) {
				si += 4
				continue
			}
			b := raw[si]
			g := raw[si+1]
			r := raw[si+2]
			a := raw[si+3]
			if a == 0 {
				a = 0xFF
			}
			si += 4
			dst.SetRGBA(dx, dy, color.RGBA{R: r, G: g, B: b, A: a})
		}
	}
}

func decodePlanarSurface(dst *image.RGBA, destLeft, destTop, w, h int, raw []byte) {
	planeSize := w * h
	if len(raw) < planeSize*3 {
		// If uncompressed planar layout is shorter than 3 planes, fallback to RLE
		return
	}
	// MS-RDPRFX planar format (R, G, B planes)
	rPlane := raw[0:planeSize]
	gPlane := raw[planeSize : planeSize*2]
	bPlane := raw[planeSize*2 : planeSize*3]

	pi := 0
	for y := 0; y < h; y++ {
		dy := destTop + y
		if dy < 0 || dy >= dst.Bounds().Dy() {
			pi += w
			continue
		}
		for x := 0; x < w; x++ {
			dx := destLeft + x
			if dx >= 0 && dx < dst.Bounds().Dx() && pi < planeSize {
				dst.SetRGBA(dx, dy, color.RGBA{
					R: rPlane[pi],
					G: gPlane[pi],
					B: bPlane[pi],
					A: 0xFF,
				})
			}
			pi++
		}
	}
}

func (d *GFXDecoder) blitSurfaceToTarget(surf *Surface) {
	if d.TargetFB == nil || d.TargetFB.Img == nil || surf.Img == nil {
		return
	}
	targetBounds := d.TargetFB.Img.Bounds()
	destRect := image.Rect(surf.OriginX, surf.OriginY,
		surf.OriginX+surf.Width, surf.OriginY+surf.Height).Intersect(targetBounds)

	srcPt := image.Point{
		X: destRect.Min.X - surf.OriginX,
		Y: destRect.Min.Y - surf.OriginY,
	}
	draw.Draw(d.TargetFB.Img, destRect, surf.Img, srcPt, draw.Src)
}

func (d *GFXDecoder) blitAllMappedToTarget() {
	for _, surf := range d.Surfaces {
		if surf.Mapped {
			d.blitSurfaceToTarget(surf)
		}
	}
}
