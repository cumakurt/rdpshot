package screenshot

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"rdpshot/internal/model"
)

// AutoGrabber prefers a live FreeRDP capture when the host tooling is present,
// then the pure-Go authenticated framebuffer (bitmap updates), and finally the
// evidence card — but only when FreeRDP tooling is missing. When tooling is
// present and both live paths fail, Grab returns an error instead of a
// misleading "tooling unavailable" card.
type AutoGrabber struct {
	Primary             Grabber
	Secondary           Grabber
	Fallback            Grabber
	PreferGoFramebuffer bool
	Logger              *slog.Logger
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

// Grab captures with FreeRDP when possible (password via /from-stdin, NT hash
// via /pth restricted-admin), otherwise the Go framebuffer, otherwise evidence.
func (g *AutoGrabber) Grab(ctx context.Context, ep model.Endpoint, cred model.Credential) (model.Screenshot, error) {
	if g.PreferGoFramebuffer && g.Secondary != nil && g.Secondary.Available() == nil {
		shot, err := g.Secondary.Grab(ctx, ep, cred)
		if err == nil {
			return shot, nil
		}
		g.Logger.Warn("preferred Go framebuffer capture failed; trying FreeRDP",
			"address", ep.Address, "port", ep.Port, "error", err.Error())
	}

	var primaryErr error
	freerdpAvailable := g.Primary != nil && g.Primary.Available() == nil
	if freerdpAvailable {
		shot, err := g.Primary.Grab(ctx, ep, cred)
		if err == nil {
			return shot, nil
		}
		primaryErr = err
		// Xvfb sometimes grabs before the desktop paints; one blank-frame retry
		// recovers most flaky hosts without falling through to the evidence card.
		if strings.Contains(err.Error(), "blank") {
			g.Logger.Warn("live screenshot blank; retrying once",
				"address", ep.Address, "port", ep.Port)
			shot, err = g.Primary.Grab(ctx, ep, cred)
			if err == nil {
				return shot, nil
			}
			primaryErr = err
		}
		g.Logger.Warn("live screenshot capture failed; trying Go framebuffer",
			"address", ep.Address, "port", ep.Port, "error", primaryErr.Error())
	}

	var secondaryErr error
	if g.Secondary != nil && g.Secondary.Available() == nil {
		shot, err := g.Secondary.Grab(ctx, ep, cred)
		if err == nil {
			return shot, nil
		}
		secondaryErr = err
		g.Logger.Warn("Go framebuffer capture failed",
			"address", ep.Address, "port", ep.Port, "error", err.Error())
	}

	// FreeRDP tooling on PATH: do not store a synthetic evidence card as a
	// desktop screenshot when live capture failed.
	if freerdpAvailable {
		switch {
		case primaryErr != nil && secondaryErr != nil:
			return model.Screenshot{}, fmt.Errorf("screenshot: freerdp: %v; framebuffer: %w", primaryErr, secondaryErr)
		case primaryErr != nil:
			return model.Screenshot{}, fmt.Errorf("screenshot: freerdp: %w", primaryErr)
		case secondaryErr != nil:
			return model.Screenshot{}, fmt.Errorf("screenshot: framebuffer: %w", secondaryErr)
		}
	}

	if g.Fallback == nil {
		return model.Screenshot{}, fmt.Errorf("%w: no fallback grabber configured", ErrGrabberUnavailable)
	}
	g.Logger.Warn("falling back to evidence card (FreeRDP tooling unavailable)",
		"address", ep.Address, "port", ep.Port)
	return g.Fallback.Grab(ctx, ep, cred)
}
