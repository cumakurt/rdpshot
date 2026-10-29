package screenshot

import (
	"context"
	"fmt"
	"log/slog"

	"rdpshot/internal/model"
)

// AutoGrabber prefers a live FreeRDP capture when the host tooling is present,
// then the pure-Go authenticated framebuffer (bitmap updates), and finally the
// evidence card. Callers that only care about "some visual proof of a verified
// login" should use this.
type AutoGrabber struct {
	Primary   Grabber
	Secondary Grabber
	Fallback  Grabber
	Logger    *slog.Logger
}

// NewAutoGrabber builds the preferred capture chain writing into outputDir.
func NewAutoGrabber(outputDir string, logger *slog.Logger) *AutoGrabber {
	if logger == nil {
		logger = slog.Default()
	}
	return &AutoGrabber{
		Primary:   NewXFreeRDPGrabber(outputDir),
		Secondary: NewFramebufferGrabber(outputDir),
		Fallback:  NewEvidenceGrabber(outputDir),
		Logger:    logger,
	}
}

// Available reports whether at least one grabber can produce an image.
func (g *AutoGrabber) Available() error {
	if g.Primary != nil && g.Primary.Available() == nil {
		return nil
	}
	if g.Secondary != nil && g.Secondary.Available() == nil {
		return nil
	}
	if g.Fallback != nil {
		return g.Fallback.Available()
	}
	return ErrGrabberUnavailable
}

// Grab captures with FreeRDP when possible, otherwise Go framebuffer, otherwise evidence.
func (g *AutoGrabber) Grab(ctx context.Context, ep model.Endpoint, cred model.Credential) (model.Screenshot, error) {
	if g.Primary != nil && g.Primary.Available() == nil {
		shot, err := g.Primary.Grab(ctx, ep, cred)
		if err == nil {
			return shot, nil
		}
		g.Logger.Warn("live screenshot capture failed; trying Go framebuffer",
			"address", ep.Address, "port", ep.Port, "error", err.Error())
	}
	if g.Secondary != nil && g.Secondary.Available() == nil {
		shot, err := g.Secondary.Grab(ctx, ep, cred)
		if err == nil {
			return shot, nil
		}
		g.Logger.Warn("Go framebuffer capture failed; falling back to evidence card",
			"address", ep.Address, "port", ep.Port, "error", err.Error())
	}
	if g.Fallback == nil {
		return model.Screenshot{}, fmt.Errorf("%w: no fallback grabber configured", ErrGrabberUnavailable)
	}
	return g.Fallback.Grab(ctx, ep, cred)
}
