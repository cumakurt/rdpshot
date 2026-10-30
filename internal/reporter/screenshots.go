package reporter

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"os"
	"strings"

	"rdpshot/internal/model"
	"rdpshot/internal/screenshot"
)

// reportScreens returns gallery-worthy frames only (no synthetic detection cards).
func reportScreens(screens []model.Screenshot) []model.Screenshot {
	out := make([]model.Screenshot, 0, len(screens))
	for _, s := range screens {
		if s.Username == screenshot.OpenHostLabel {
			continue
		}
		out = append(out, s)
	}
	return out
}

// screenshotLabel turns the stored username token into a short report caption.
func screenshotLabel(username string) string {
	switch username {
	case screenshot.LoginScreenLabel:
		return "Login screen"
	case "":
		return "Session"
	default:
		return "User: " + username
	}
}

// screenshotMIME sniffs PNG/JPEG magic; unknown files are treated as PNG.
func screenshotMIME(data []byte) string {
	switch {
	case len(data) >= 8 && string(data[:8]) == "\x89PNG\r\n\x1a\n":
		return "image/png"
	case len(data) >= 3 && data[0] == 0xff && data[1] == 0xd8 && data[2] == 0xff:
		return "image/jpeg"
	default:
		return "image/png"
	}
}

// loadScreenshotDataURI reads a capture file into a data URI for self-contained HTML.
func loadScreenshotDataURI(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("empty screenshot path")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(data) == 0 {
		return "", fmt.Errorf("empty screenshot file")
	}
	mime := screenshotMIME(data)
	return "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(data), nil
}

// loadScreenshotBytes returns raw image bytes and fpdf image type ("PNG"/"JPG").
func loadScreenshotBytes(path string) (data []byte, imageType string, err error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, "", fmt.Errorf("empty screenshot path")
	}
	data, err = os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	if len(data) == 0 {
		return nil, "", fmt.Errorf("empty screenshot file")
	}
	if _, _, err := image.DecodeConfig(bytes.NewReader(data)); err != nil {
		return nil, "", fmt.Errorf("decode screenshot: %w", err)
	}
	switch screenshotMIME(data) {
	case "image/jpeg":
		return data, "JPG", nil
	default:
		return data, "PNG", nil
	}
}
