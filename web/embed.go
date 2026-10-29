// Package web embeds the UI templates and static assets so the server binary
// is self-contained.
package web

import "embed"

// FS exposes templates/*.html and static/... from the built binary.
//
//go:embed templates static
var FS embed.FS
