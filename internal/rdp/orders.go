package rdp

import (
	"encoding/binary"
	"image"
	"image/color"
	"image/draw"
)

// Primary drawing order types used by this MVP (MS-RDPBCGR 2.2.9.1.1.3.1.1).
const (
	orderPatBlt  byte = 0x01
	orderScrBlt  byte = 0x02
	orderMemBlt  byte = 0x0D
)

type bitmapCache struct {
	entries map[uint16]*image.RGBA
}

func newBitmapCache() *bitmapCache {
	return &bitmapCache{entries: map[uint16]*image.RGBA{}}
}

// applyOrders decodes a subset of primary drawing orders into the framebuffer.
func applyOrders(fb *Framebuffer, data []byte, cache *bitmapCache) int {
	if fb == nil || fb.Img == nil || len(data) == 0 {
		return 0
	}
	if cache == nil {
		cache = newBitmapCache()
	}
	applied := 0
	off := 0
	for off < len(data) {
		control := data[off]
		off++
		if control&0x01 == 0 {
			// Secondary / alternate orders — skip remainder conservatively.
			break
		}
		orderType := byte(0)
		if control&0x02 != 0 {
			if off >= len(data) {
				break
			}
			orderType = data[off]
			off++
		}
		fieldBytes := 1
		if control&0x40 != 0 {
			fieldBytes = 2
		}
		if control&0x80 != 0 {
			fieldBytes = 3
		}
		if off+fieldBytes > len(data) {
			break
		}
		fields := uint32(0)
		for i := 0; i < fieldBytes; i++ {
			fields |= uint32(data[off]) << (8 * i)
			off++
		}
		bounds := fb.Img.Bounds()
		switch orderType {
		case orderPatBlt:
			n, next := decodePatBlt(fb, data[off:], fields, bounds)
			off += next
			applied += n
		case orderScrBlt:
			n, next := decodeScrBlt(fb, data[off:], fields, bounds)
			off += next
			applied += n
		case orderMemBlt:
			n, next := decodeMemBlt(fb, data[off:], fields, bounds, cache)
			off += next
			applied += n
		default:
			// Unknown primary order — abort the rest of this PDU safely.
			return applied
		}
	}
	return applied
}

func decodePatBlt(fb *Framebuffer, data []byte, fields uint32, bounds image.Rectangle) (int, int) {
	// Minimal coordinate stream: left, top, width, height, then brush colour.
	coords, used := readCoords(data, fields, 4)
	if len(coords) < 4 || used+3 > len(data) {
		return 0, used
	}
	left, top, width, height := coords[0], coords[1], coords[2], coords[3]
	// Last 3 bytes treated as BGR brush colour when present.
	b, g, r := data[used], byte(0), byte(0)
	if used+2 < len(data) {
		b, g, r = data[used], data[used+1], data[used+2]
		used += 3
	}
	fillRect(fb, left, top, width, height, color.RGBA{R: r, G: g, B: b, A: 255}, bounds)
	return 1, used
}

func decodeScrBlt(fb *Framebuffer, data []byte, fields uint32, bounds image.Rectangle) (int, int) {
	coords, used := readCoords(data, fields, 7)
	if len(coords) < 7 {
		return 0, used
	}
	left, top, width, height := coords[0], coords[1], coords[2], coords[3]
	srcX, srcY := coords[5], coords[6]
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			dx, dy := left+x, top+y
			sx, sy := srcX+x, srcY+y
			if !ptIn(bounds, dx, dy) || !ptIn(bounds, sx, sy) {
				continue
			}
			fb.Img.Set(dx, dy, fb.Img.At(sx, sy))
		}
	}
	return 1, used
}

func decodeMemBlt(fb *Framebuffer, data []byte, fields uint32, bounds image.Rectangle, cache *bitmapCache) (int, int) {
	coords, used := readCoords(data, fields, 7)
	if len(coords) < 7 || used+2 > len(data) {
		return 0, used
	}
	left, top, width, height := coords[0], coords[1], coords[2], coords[3]
	cacheIdx := binary.LittleEndian.Uint16(data[used : used+2])
	used += 2
	src, ok := cache.entries[cacheIdx]
	if !ok || src == nil {
		return 0, used
	}
	r := image.Rect(left, top, left+width, top+height)
	draw.Draw(fb.Img, r.Intersect(bounds), src, image.Pt(coords[5], coords[6]), draw.Src)
	return 1, used
}

func readCoords(data []byte, fields uint32, n int) ([]int, int) {
	out := make([]int, 0, n)
	off := 0
	for i := 0; i < n; i++ {
		if fields&(1<<uint(i)) == 0 {
			out = append(out, 0)
			continue
		}
		if off+2 > len(data) {
			return out, off
		}
		out = append(out, int(int16(binary.LittleEndian.Uint16(data[off:off+2]))))
		off += 2
	}
	return out, off
}

func fillRect(fb *Framebuffer, left, top, width, height int, c color.RGBA, bounds image.Rectangle) {
	for y := top; y < top+height; y++ {
		for x := left; x < left+width; x++ {
			if ptIn(bounds, x, y) {
				fb.Img.SetRGBA(x, y, c)
			}
		}
	}
}

func ptIn(b image.Rectangle, x, y int) bool {
	return x >= b.Min.X && x < b.Max.X && y >= b.Min.Y && y < b.Max.Y
}
