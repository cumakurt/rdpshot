package screenshot

import (
	"context"
	"fmt"
	"image/png"
	"os"
	"path/filepath"
	"time"

	"rdpshot/internal/model"
	"rdpshot/internal/rdp"
)

// FramebufferGrabber captures a remote desktop PNG via a pure-Go NLA RDP
// session that decodes slow-path Bitmap Update PDUs. Drawing Orders and
// RDPGFX are not implemented; when the server never sends classic bitmaps
// Grab returns an error so AutoGrabber can fall through to the evidence card.
type FramebufferGrabber struct {
	OutputDir string
	// Timeout bounds the full capture attempt. Zero selects the rdp default.
	Timeout time.Duration
}

// NewFramebufferGrabber builds the pure-Go framebuffer grabber.
func NewFramebufferGrabber(outputDir string) *FramebufferGrabber {
	return &FramebufferGrabber{OutputDir: outputDir}
}

// Available always succeeds: capture needs only the Go standard library plus
// the in-tree RDP stack (no FreeRDP/Xvfb).
func (g *FramebufferGrabber) Available() error {
	return nil
}

// Grab opens an authenticated RDP session and writes a PNG of the framebuffer.
func (g *FramebufferGrabber) Grab(ctx context.Context, ep model.Endpoint, cred model.Credential) (model.Screenshot, error) {
	var shot model.Screenshot
	if err := ctx.Err(); err != nil {
		return shot, err
	}
	if err := os.MkdirAll(g.OutputDir, 0o700); err != nil {
		return shot, fmt.Errorf("framebuffer: create output directory: %w", err)
	}

	img, err := rdp.Capture(ctx, ep, cred, rdp.CaptureOptions{Timeout: g.Timeout})
	if err != nil {
		return shot, fmt.Errorf("framebuffer: %w", err)
	}

	now := time.Now().UTC()
	name := "fb-" + FileName(ep, cred.Username, now)
	outPath := filepath.Join(g.OutputDir, name)
	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return shot, fmt.Errorf("framebuffer: create image: %w", err)
	}
	if err := png.Encode(f, img); err != nil {
		f.Close()
		os.Remove(outPath)
		return shot, fmt.Errorf("framebuffer: encode image: %w", err)
	}
	if err := f.Close(); err != nil {
		return shot, fmt.Errorf("framebuffer: close image: %w", err)
	}

	b := img.Bounds()
	return model.Screenshot{
		Address:    ep.Address,
		Port:       ep.Port,
		Username:   cred.Username,
		FilePath:   outPath,
		Width:      b.Dx(),
		Height:     b.Dy(),
		CapturedAt: now,
	}, nil
}
