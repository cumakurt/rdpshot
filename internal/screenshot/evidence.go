package screenshot

import (
	"context"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"os"
	"path/filepath"
	"time"

	"rdpshot/internal/model"
)

const (
	evidenceWidth  = 1024
	evidenceHeight = 768
	// OpenHostLabel marks synthetic open-host detection cards. These are no
	// longer persisted by the scanner; the constant remains for filtering
	// legacy gallery rows and unit tests of GrabOpenHost.
	OpenHostLabel = "rdp-open"
)

// EvidenceGrabber is a pure-Go grabber that writes labelled PNG evidence cards.
// It is the post-login fallback when FreeRDP/framebuffer cannot produce a live
// desktop frame after a verified credential.
type EvidenceGrabber struct {
	OutputDir string
}

// NewEvidenceGrabber builds a pure-Go evidence-card grabber.
func NewEvidenceGrabber(outputDir string) *EvidenceGrabber {
	return &EvidenceGrabber{OutputDir: outputDir}
}

// Available always succeeds: the grabber only needs the Go standard library.
func (g *EvidenceGrabber) Available() error {
	return nil
}

// Grab writes a session-evidence PNG for the verified credential.
func (g *EvidenceGrabber) Grab(ctx context.Context, ep model.Endpoint, cred model.Credential) (model.Screenshot, error) {
	return g.writeCard(ctx, ep, cred.Username, func(at time.Time) image.Image {
		return renderVerifiedEvidenceCard(ep, cred, at)
	})
}

// GrabOpenHost writes a detection evidence PNG for an open RDP endpoint.
// Retained for tests and tooling; the scanner no longer calls this path so the
// gallery only shows real Winlogon / desktop frames.
func (g *EvidenceGrabber) GrabOpenHost(ctx context.Context, ep model.Endpoint, svc *model.ServiceInfo) (model.Screenshot, error) {
	return g.writeCard(ctx, ep, OpenHostLabel, func(at time.Time) image.Image {
		return renderOpenHostEvidenceCard(ep, svc, at)
	})
}

func (g *EvidenceGrabber) writeCard(ctx context.Context, ep model.Endpoint, label string, render func(time.Time) image.Image) (model.Screenshot, error) {
	var shot model.Screenshot
	if err := ctx.Err(); err != nil {
		return shot, err
	}
	if err := os.MkdirAll(g.OutputDir, 0o700); err != nil {
		return shot, fmt.Errorf("screenshot: create output directory: %w", err)
	}

	now := time.Now().UTC()
	name := FileName(ep, label, now)
	outPath := filepath.Join(g.OutputDir, name)

	img := render(now)
	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return shot, fmt.Errorf("screenshot: create evidence image: %w", err)
	}
	if err := png.Encode(f, img); err != nil {
		f.Close()
		os.Remove(outPath)
		return shot, fmt.Errorf("screenshot: encode evidence image: %w", err)
	}
	if err := f.Close(); err != nil {
		return shot, fmt.Errorf("screenshot: close evidence image: %w", err)
	}

	return model.Screenshot{
		Address:    ep.Address,
		Port:       ep.Port,
		Username:   label,
		FilePath:   outPath,
		Width:      evidenceWidth,
		Height:     evidenceHeight,
		CapturedAt: now,
	}, nil
}

func renderVerifiedEvidenceCard(ep model.Endpoint, cred model.Credential, at time.Time) image.Image {
	img, text, muted := newEvidenceCanvas(color.RGBA{R: 16, G: 185, B: 129, A: 255}) // emerald
	drawBitmap(img, 80, 120, "RDPShot session evidence", text, 3)
	drawBitmap(img, 80, 175, "Authentication verified - desktop capture tooling unavailable", muted, 2)
	drawBitmap(img, 80, 260, fmt.Sprintf("Host      %s:%d", ep.Address, ep.Port), text, 2)
	drawBitmap(img, 80, 310, fmt.Sprintf("User      %s", displayUser(cred)), text, 2)
	drawBitmap(img, 80, 360, fmt.Sprintf("Method    %s", fallback(cred.Method, "nla")), text, 2)
	drawBitmap(img, 80, 410, fmt.Sprintf("Captured  %s", at.Format(time.RFC3339)), text, 2)
	drawBitmap(img, 80, 500, "This image is a pure-Go evidence card, not a framebuffer dump.", muted, 2)
	drawBitmap(img, 80, 550, "Install FreeRDP + Xvfb + ImageMagick/ffmpeg for live screenshots.", muted, 2)
	return img
}

func renderOpenHostEvidenceCard(ep model.Endpoint, svc *model.ServiceInfo, at time.Time) image.Image {
	img, text, muted := newEvidenceCanvas(color.RGBA{R: 59, G: 130, B: 246, A: 255}) // blue
	drawBitmap(img, 80, 120, "RDPShot detection evidence", text, 3)
	nla := svc != nil && svc.NLARequired
	if nla {
		drawBitmap(img, 80, 175, "Pre-auth login UI blocked - server requires CredSSP/NLA", muted, 2)
	} else {
		drawBitmap(img, 80, 175, "RDP open - login-screen capture unavailable on this host", muted, 2)
	}
	drawBitmap(img, 80, 260, fmt.Sprintf("Host      %s:%d", ep.Address, ep.Port), text, 2)
	drawBitmap(img, 80, 310, fmt.Sprintf("NLA       %s", boolLabel(nla)), text, 2)
	drawBitmap(img, 80, 360, fmt.Sprintf("TLS       %s", openHostTLS(svc)), text, 2)
	drawBitmap(img, 80, 410, fmt.Sprintf("Cert      %s", openHostCert(svc)), text, 2)
	drawBitmap(img, 80, 460, fmt.Sprintf("OS guess  %s", openHostOS(svc)), text, 2)
	drawBitmap(img, 80, 510, fmt.Sprintf("Captured  %s", at.Format(time.RFC3339)), text, 2)
	if nla {
		drawBitmap(img, 80, 590, "HYBRID_REQUIRED: TLS-only clients cannot reach Winlogon.", muted, 2)
		drawBitmap(img, 80, 640, "Use a verified credential for a live desktop screenshot.", muted, 2)
	} else {
		drawBitmap(img, 80, 590, "Install FreeRDP + Xvfb + ImageMagick for login-screen grabs.", muted, 2)
		drawBitmap(img, 80, 640, "Live desktop screenshots still require a verified credential.", muted, 2)
	}
	return img
}

func newEvidenceCanvas(accent color.RGBA) (*image.RGBA, color.RGBA, color.RGBA) {
	img := image.NewRGBA(image.Rect(0, 0, evidenceWidth, evidenceHeight))
	bg := color.RGBA{R: 15, G: 23, B: 42, A: 255}
	panel := color.RGBA{R: 30, G: 41, B: 59, A: 255}
	text := color.RGBA{R: 226, G: 232, B: 240, A: 255}
	muted := color.RGBA{R: 148, G: 163, B: 184, A: 255}
	draw.Draw(img, img.Bounds(), &image.Uniform{C: bg}, image.Point{}, draw.Src)
	draw.Draw(img, image.Rect(64, 96, evidenceWidth-64, evidenceHeight-96), &image.Uniform{C: panel}, image.Point{}, draw.Src)
	draw.Draw(img, image.Rect(64, 96, 72, evidenceHeight-96), &image.Uniform{C: accent}, image.Point{}, draw.Src)
	return img, text, muted
}

func boolLabel(v bool) string {
	if v {
		return "required"
	}
	return "not required / unknown"
}

func openHostTLS(svc *model.ServiceInfo) string {
	if svc == nil || svc.TLSVersion == "" {
		return "n/a"
	}
	if svc.TLSCipherSuite != "" {
		return svc.TLSVersion + " / " + svc.TLSCipherSuite
	}
	return svc.TLSVersion
}

func openHostCert(svc *model.ServiceInfo) string {
	if svc == nil || svc.Certificate == nil {
		return "n/a"
	}
	sub := svc.Certificate.Subject
	if sub == "" {
		sub = "present"
	}
	if len(sub) > 48 {
		sub = sub[:45] + "..."
	}
	if svc.Certificate.SelfSigned {
		return sub + " (self-signed)"
	}
	return sub
}

func openHostOS(svc *model.ServiceInfo) string {
	if svc == nil || svc.OSGuess == "" {
		return "n/a"
	}
	return svc.OSGuess
}

func displayUser(cred model.Credential) string {
	if cred.Domain != "" {
		return cred.Domain + `\` + cred.Username
	}
	return cred.Username
}

func fallback(value, def string) string {
	if value == "" {
		return def
	}
	return value
}

// drawBitmap paints a tiny 5x7 bitmap font. It keeps the fallback grabber free
// of font-file dependencies while remaining readable at 1024x768.
func drawBitmap(img *image.RGBA, x, y int, text string, ink color.Color, scale int) {
	if scale < 1 {
		scale = 1
	}
	cx := x
	for _, r := range text {
		glyph, ok := bitmapFont[r]
		if !ok {
			glyph = bitmapFont['?']
		}
		for row := 0; row < 7; row++ {
			bits := glyph[row]
			for col := 0; col < 5; col++ {
				if bits&(1<<uint(4-col)) == 0 {
					continue
				}
				for dy := 0; dy < scale; dy++ {
					for dx := 0; dx < scale; dx++ {
						img.Set(cx+col*scale+dx, y+row*scale+dy, ink)
					}
				}
			}
		}
		cx += 6 * scale
	}
}

// bitmapFont is a minimal uppercase/digit glyph set used by the evidence card.
var bitmapFont = map[rune][7]uint8{
	' ': {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	'-': {0x00, 0x00, 0x00, 0x1F, 0x00, 0x00, 0x00},
	'.': {0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x0C},
	':': {0x00, 0x0C, 0x0C, 0x00, 0x0C, 0x0C, 0x00},
	'/': {0x01, 0x02, 0x04, 0x08, 0x10, 0x00, 0x00},
	'\\': {0x10, 0x08, 0x04, 0x02, 0x01, 0x00, 0x00},
	'+': {0x00, 0x04, 0x04, 0x1F, 0x04, 0x04, 0x00},
	'=': {0x00, 0x00, 0x1F, 0x00, 0x1F, 0x00, 0x00},
	'_': {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1F},
	',': {0x00, 0x00, 0x00, 0x00, 0x0C, 0x04, 0x08},
	'?': {0x0E, 0x11, 0x01, 0x02, 0x04, 0x00, 0x04},
	'0': {0x0E, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0E},
	'1': {0x04, 0x0C, 0x04, 0x04, 0x04, 0x04, 0x0E},
	'2': {0x0E, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1F},
	'3': {0x1F, 0x02, 0x04, 0x02, 0x01, 0x11, 0x0E},
	'4': {0x02, 0x06, 0x0A, 0x12, 0x1F, 0x02, 0x02},
	'5': {0x1F, 0x10, 0x1E, 0x01, 0x01, 0x11, 0x0E},
	'6': {0x06, 0x08, 0x10, 0x1E, 0x11, 0x11, 0x0E},
	'7': {0x1F, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08},
	'8': {0x0E, 0x11, 0x11, 0x0E, 0x11, 0x11, 0x0E},
	'9': {0x0E, 0x11, 0x11, 0x0F, 0x01, 0x02, 0x0C},
	'A': {0x0E, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11},
	'B': {0x1E, 0x11, 0x11, 0x1E, 0x11, 0x11, 0x1E},
	'C': {0x0E, 0x11, 0x10, 0x10, 0x10, 0x11, 0x0E},
	'D': {0x1E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x1E},
	'E': {0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x1F},
	'F': {0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x10},
	'G': {0x0E, 0x11, 0x10, 0x17, 0x11, 0x11, 0x0F},
	'H': {0x11, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11},
	'I': {0x0E, 0x04, 0x04, 0x04, 0x04, 0x04, 0x0E},
	'J': {0x01, 0x01, 0x01, 0x01, 0x11, 0x11, 0x0E},
	'K': {0x11, 0x12, 0x14, 0x18, 0x14, 0x12, 0x11},
	'L': {0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1F},
	'M': {0x11, 0x1B, 0x15, 0x15, 0x11, 0x11, 0x11},
	'N': {0x11, 0x19, 0x15, 0x13, 0x11, 0x11, 0x11},
	'O': {0x0E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E},
	'P': {0x1E, 0x11, 0x11, 0x1E, 0x10, 0x10, 0x10},
	'Q': {0x0E, 0x11, 0x11, 0x11, 0x15, 0x12, 0x0D},
	'R': {0x1E, 0x11, 0x11, 0x1E, 0x14, 0x12, 0x11},
	'S': {0x0F, 0x10, 0x10, 0x0E, 0x01, 0x01, 0x1E},
	'T': {0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04},
	'U': {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E},
	'V': {0x11, 0x11, 0x11, 0x11, 0x11, 0x0A, 0x04},
	'W': {0x11, 0x11, 0x11, 0x15, 0x15, 0x1B, 0x11},
	'X': {0x11, 0x11, 0x0A, 0x04, 0x0A, 0x11, 0x11},
	'Y': {0x11, 0x11, 0x0A, 0x04, 0x04, 0x04, 0x04},
	'Z': {0x1F, 0x01, 0x02, 0x04, 0x08, 0x10, 0x1F},
	'a': {0x00, 0x00, 0x0E, 0x01, 0x0F, 0x11, 0x0F},
	'b': {0x10, 0x10, 0x1E, 0x11, 0x11, 0x11, 0x1E},
	'c': {0x00, 0x00, 0x0E, 0x10, 0x10, 0x11, 0x0E},
	'd': {0x01, 0x01, 0x0F, 0x11, 0x11, 0x11, 0x0F},
	'e': {0x00, 0x00, 0x0E, 0x11, 0x1F, 0x10, 0x0E},
	'f': {0x06, 0x08, 0x08, 0x1E, 0x08, 0x08, 0x08},
	'g': {0x00, 0x00, 0x0F, 0x11, 0x0F, 0x01, 0x0E},
	'h': {0x10, 0x10, 0x1E, 0x11, 0x11, 0x11, 0x11},
	'i': {0x04, 0x00, 0x0C, 0x04, 0x04, 0x04, 0x0E},
	'j': {0x02, 0x00, 0x06, 0x02, 0x02, 0x12, 0x0C},
	'k': {0x10, 0x10, 0x12, 0x14, 0x18, 0x14, 0x12},
	'l': {0x0C, 0x04, 0x04, 0x04, 0x04, 0x04, 0x0E},
	'm': {0x00, 0x00, 0x1A, 0x15, 0x15, 0x15, 0x15},
	'n': {0x00, 0x00, 0x1E, 0x11, 0x11, 0x11, 0x11},
	'o': {0x00, 0x00, 0x0E, 0x11, 0x11, 0x11, 0x0E},
	'p': {0x00, 0x00, 0x1E, 0x11, 0x1E, 0x10, 0x10},
	'q': {0x00, 0x00, 0x0F, 0x11, 0x0F, 0x01, 0x01},
	'r': {0x00, 0x00, 0x16, 0x19, 0x10, 0x10, 0x10},
	's': {0x00, 0x00, 0x0F, 0x10, 0x0E, 0x01, 0x1E},
	't': {0x08, 0x08, 0x1E, 0x08, 0x08, 0x09, 0x06},
	'u': {0x00, 0x00, 0x11, 0x11, 0x11, 0x13, 0x0D},
	'v': {0x00, 0x00, 0x11, 0x11, 0x11, 0x0A, 0x04},
	'w': {0x00, 0x00, 0x11, 0x11, 0x15, 0x15, 0x0A},
	'x': {0x00, 0x00, 0x11, 0x0A, 0x04, 0x0A, 0x11},
	'y': {0x00, 0x00, 0x11, 0x11, 0x0F, 0x01, 0x0E},
	'z': {0x00, 0x00, 0x1F, 0x02, 0x04, 0x08, 0x1F},
}
