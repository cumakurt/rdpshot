package screenshot

import (
	"context"
	"fmt"
	"log/slog"

	"rdpshot/internal/model"
)

// AutoGrabber prefers a live FreeRDP capture when the host tooling is present
// and otherwise falls back to the pure-Go session evidence card. Callers that
// only care about "some visual proof of a verified login" should use this.
type AutoGrabber struct {
	Primary  Grabber
	Fallback Grabber
	Logger   *slog.Logger
}

// NewAutoGrabber builds the preferred capture chain writing into outputDir.
func NewAutoGrabber(outputDir string, logger *slog.Logger) *AutoGrabber {
	if logger == nil {
		logger = slog.Default()
	}
	return &AutoGrabber{
		Primary:  NewXFreeRDPGrabber(outputDir),
		Fallback: NewEvidenceGrabber(outputDir),
		Logger:   logger,
	}
}

// Available reports whether at least one grabber can produce an image.
func (g *AutoGrabber) Available() error {
	if g.Primary != nil && g.Primary.Available() == nil {
		return nil
	}
	if g.Fallback != nil {
		return g.Fallback.Available()
	}
	return ErrGrabberUnavailable
}

// Grab captures with FreeRDP when possible, otherwise with the evidence card.
func (g *AutoGrabber) Grab(ctx context.Context, ep model.Endpoint, cred model.Credential) (model.Screenshot, error) {
	if g.Primary != nil && g.Primary.Available() == nil {
		shot, err := g.Primary.Grab(ctx, ep, cred)
		if err == nil {
			return shot, nil
		}
		g.Logger.Warn("live screenshot capture failed; falling back to evidence card",
			"address", ep.Address, "port", ep.Port, "error", err.Error())
	}
	if g.Fallback == nil {
		return model.Screenshot{}, fmt.Errorf("%w: no fallback grabber configured", ErrGrabberUnavailable)
	}
	return g.Fallback.Grab(ctx, ep, cred)
}
