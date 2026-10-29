package rdp

import (
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
)

// BITMAP_DATA flags (MS-RDPBCGR 2.2.9.1.1.3.1.2.1).
const (
	bitmapCompression       uint16 = 0x0001
	bitmapNoCompressionHDR  uint16 = 0x0400
)

// Framebuffer is a mutable RGBA desktop surface filled by bitmap updates.
type Framebuffer struct {
	Img *image.RGBA
}

// NewFramebuffer allocates a desktop surface.
func NewFramebuffer(width, height int) *Framebuffer {
	if width <= 0 {
		width = 1024
	}
	if height <= 0 {
		height = 768
	}
	return &Framebuffer{Img: image.NewRGBA(image.Rect(0, 0, width, height))}
}

// ApplyBitmapUpdate parses a slow-path Bitmap Update PDU payload (after the
// updateType field) and blits every rectangle onto the framebuffer.
func (fb *Framebuffer) ApplyBitmapUpdate(payload []byte) (int, error) {
	if len(payload) < 2 {
		return 0, fmt.Errorf("rdp: short bitmap update")
	}
	nRect := int(binary.LittleEndian.Uint16(payload[0:2]))
	off := 2
	applied := 0
	for i := 0; i < nRect; i++ {
		if off+18 > len(payload) {
			return applied, fmt.Errorf("rdp: truncated bitmap rectangle header")
		}
		destLeft := int(binary.LittleEndian.Uint16(payload[off : off+2]))
		destTop := int(binary.LittleEndian.Uint16(payload[off+2 : off+4]))
		destRight := int(binary.LittleEndian.Uint16(payload[off+4 : off+6]))
		destBottom := int(binary.LittleEndian.Uint16(payload[off+6 : off+8]))
		width := int(binary.LittleEndian.Uint16(payload[off+8 : off+10]))
		height := int(binary.LittleEndian.Uint16(payload[off+10 : off+12]))
		bpp := int(binary.LittleEndian.Uint16(payload[off+12 : off+14]))
		flags := binary.LittleEndian.Uint16(payload[off+14 : off+16])
		bitmapLen := int(binary.LittleEndian.Uint16(payload[off+16 : off+18]))
		off += 18

		if bitmapLen < 0 || off+bitmapLen > len(payload) {
			return applied, fmt.Errorf("rdp: bitmap data length %d out of range", bitmapLen)
		}
		data := payload[off : off+bitmapLen]
		off += bitmapLen

		pixels, err := decodeBitmapPixels(width, height, bpp, flags, data)
		if err != nil {
			continue
		}
		fb.blit(destLeft, destTop, destRight, destBottom, width, height, pixels)
		applied++
	}
	return applied, nil
}

func decodeBitmapPixels(width, height, bpp int, flags uint16, data []byte) ([]byte, error) {
	if width <= 0 || height <= 0 {
		return nil, fmt.Errorf("rdp: invalid bitmap size %dx%d", width, height)
	}
	compressed := flags&bitmapCompression != 0
	if !compressed {
		return expandRawBitmap(width, height, bpp, data)
	}
	body := data
	if flags&bitmapNoCompressionHDR == 0 {
		if len(data) < 8 {
			return nil, fmt.Errorf("rdp: missing compressed bitmap header")
		}
		// TS_CD_HEADER: cbCompMainBodySize(2) cbScanWidth(2) cbUncompressedSize(2) + pad
		body = data[8:]
	}
	raw, err := decompressRLE(width, height, bpp, body)
	if err != nil {
		return nil, err
	}
	return expandRawBitmap(width, height, bpp, raw)
}

func expandRawBitmap(width, height, bpp int, data []byte) ([]byte, error) {
	stride := (width*bpp + 7) / 8
	// RDP bitmaps are bottom-up; rows are often 4-byte aligned.
	align := (stride + 3) &^ 3
	need := align * height
	if len(data) < need {
		if len(data) < stride*height {
			return nil, fmt.Errorf("rdp: raw bitmap truncated: have %d want %d", len(data), need)
		}
		align = stride
		need = stride * height
	}
	out := make([]byte, width*height*4)
	for y := 0; y < height; y++ {
		srcY := height - 1 - y // flip to top-down
		row := data[srcY*align : srcY*align+stride]
		for x := 0; x < width; x++ {
			r, g, b, a := samplePixel(row, x, bpp)
			i := (y*width + x) * 4
			out[i], out[i+1], out[i+2], out[i+3] = r, g, b, a
		}
	}
	return out, nil
}

func samplePixel(row []byte, x, bpp int) (r, g, b, a byte) {
	a = 255
	switch bpp {
	case 32:
		off := x * 4
		if off+3 >= len(row) {
			return
		}
		b, g, r = row[off], row[off+1], row[off+2]
	case 24:
		off := x * 3
		if off+2 >= len(row) {
			return
		}
		b, g, r = row[off], row[off+1], row[off+2]
	case 16, 15:
		off := x * 2
		if off+1 >= len(row) {
			return
		}
		v := binary.LittleEndian.Uint16(row[off : off+2])
		if bpp == 15 {
			r = byte((v>>7)&0xF8 | (v>>12)&0x07)
			g = byte((v>>2)&0xF8 | (v>>7)&0x07)
			b = byte((v<<3)&0xF8 | (v>>2)&0x07)
		} else {
			r = byte((v>>8)&0xF8 | (v>>13)&0x07)
			g = byte((v>>3)&0xFC | (v>>9)&0x03)
			b = byte((v<<3)&0xF8 | (v>>2)&0x07)
		}
	case 8:
		if x >= len(row) {
			return
		}
		// Without a palette, treat as grayscale.
		r, g, b = row[x], row[x], row[x]
	default:
		return 0, 0, 0, 255
	}
	return
}

func (fb *Framebuffer) blit(left, top, right, bottom, width, height int, pixels []byte) {
	if fb == nil || fb.Img == nil || len(pixels) == 0 {
		return
	}
	bounds := fb.Img.Bounds()
	w := width
	if right > left {
		w = right - left + 1
	}
	h := height
	if bottom > top {
		h = bottom - top + 1
	}
	if w > width {
		w = width
	}
	if h > height {
		h = height
	}
	for y := 0; y < h; y++ {
		dy := top + y
		if dy < bounds.Min.Y || dy >= bounds.Max.Y {
			continue
		}
		for x := 0; x < w; x++ {
			dx := left + x
			if dx < bounds.Min.X || dx >= bounds.Max.X {
				continue
			}
			i := (y*width + x) * 4
			if i+3 >= len(pixels) {
				continue
			}
			fb.Img.SetRGBA(dx, dy, color.RGBA{
				R: pixels[i], G: pixels[i+1], B: pixels[i+2], A: pixels[i+3],
			})
		}
	}
}

// PaintedFraction estimates how much of the surface is non-zero.
func (fb *Framebuffer) PaintedFraction() float64 {
	if fb == nil || fb.Img == nil {
		return 0
	}
	pix := fb.Img.Pix
	if len(pix) == 0 {
		return 0
	}
	painted := 0
	for i := 0; i+3 < len(pix); i += 4 {
		if pix[i] != 0 || pix[i+1] != 0 || pix[i+2] != 0 {
			painted++
		}
	}
	return float64(painted) / float64(len(pix)/4)
}

// decompressRLE implements a practical subset of MS-RDPBCGR interleaved RLE
// (codes sufficient for solid fills and short runs used by classic bitmaps).
func decompressRLE(width, height, bpp int, src []byte) ([]byte, error) {
	bytesPerPixel := (bpp + 7) / 8
	if bytesPerPixel < 1 {
		bytesPerPixel = 1
	}
	if bytesPerPixel > 4 {
		bytesPerPixel = 4
	}
	dst := make([]byte, width*height*bytesPerPixel)
	if len(src) == 0 {
		return dst, nil
	}
	di := 0
	si := 0
	for si < len(src) && di < len(dst) {
		code := src[si]
		si++
		if code == 0x00 {
			// Escape / absolute / end-of-line / end-of-bitmap.
			if si >= len(src) {
				break
			}
			n := int(src[si])
			si++
			switch n {
			case 0: // end of line — pad to next row
				row := width * bytesPerPixel
				if row == 0 {
					break
				}
				mod := di % row
				if mod != 0 {
					di += row - mod
				}
			case 1: // end of bitmap
				return dst, nil
			case 2: // delta — skip x/y
				if si+1 >= len(src) {
					return dst, fmt.Errorf("rdp: truncated RLE delta")
				}
				si += 2
			default: // absolute copy of n pixels
				need := n * bytesPerPixel
				if si+need > len(src) {
					return dst, fmt.Errorf("rdp: truncated RLE absolute")
				}
				copy(dst[di:di+need], src[si:si+need])
				di += need
				si += need
				if need&1 != 0 && si < len(src) {
					si++ // word align
				}
			}
			continue
		}
		// Encoded run: count = code, colour follows.
		count := int(code)
		if si+bytesPerPixel > len(src) {
			return dst, fmt.Errorf("rdp: truncated RLE run colour")
		}
		color := src[si : si+bytesPerPixel]
		si += bytesPerPixel
		for i := 0; i < count && di+bytesPerPixel <= len(dst); i++ {
			copy(dst[di:di+bytesPerPixel], color)
			di += bytesPerPixel
		}
	}
	return dst, nil
}
