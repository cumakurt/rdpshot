package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

// TestInlineScriptHashesMatchRenderedPage guards the CSP policy against a
// subtle failure mode: html/template may rewrite script bodies, so the hashes
// pinned in the policy must be computed from the bytes that are actually
// served, not only from the template file.
func TestInlineScriptHashesMatchRenderedPage(t *testing.T) {
	env := newTestEnv(t, Config{})
	tpl := env.server.tpl

	var buf bytes.Buffer
	data := DashboardData{Title: "Dashboard", ActiveNav: "dashboard"}
	if err := tpl.ExecuteTemplate(&buf, "dashboard", data); err != nil {
		t.Fatalf("render dashboard: %v", err)
	}
	rendered := buf.String()

	served := inlineScriptBlocks(rendered)
	if len(served) == 0 {
		t.Fatal("rendered page has no inline scripts to pin")
	}
	policy := inlineScriptHashes()
	if policy == "" {
		t.Fatal("no CSP hashes computed")
	}
	for _, body := range served {
		sum := sha256.Sum256([]byte(body))
		want := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
		if !strings.Contains(policy, want) {
			t.Fatalf("rendered inline script is not pinned in the CSP policy:\n body=%q\n want=%s\n policy=%s",
				body, want, policy)
		}
	}
}

// TestEstatePageUsesExternalScriptOnly ensures the estate map fetch/render
// logic is not an inline <script> block. html/template strips JS comments,
// which breaks CSP hashes computed from template source and leaves the map
// stuck on "Loading…". Shared head scripts (theme/tailwind) are fine.
func TestEstatePageUsesExternalScriptOnly(t *testing.T) {
	env := newTestEnv(t, Config{})
	var buf bytes.Buffer
	if err := env.server.tpl.ExecuteTemplate(&buf, "estate", EstateData{
		Title: "Estate", ActiveNav: "estate",
	}); err != nil {
		t.Fatalf("render estate: %v", err)
	}
	body := buf.String()
	if strings.Contains(body, "/api/v1/estate") && !strings.Contains(body, `src="/static/js/app.js"`) {
		t.Fatal("estate API client must load via /static/js/app.js")
	}
	for _, block := range inlineScriptBlocks(body) {
		if strings.Contains(block, "/api/v1/estate") || strings.Contains(block, "estate-graph") {
			t.Fatalf("estate map logic must not be inline (CSP comment stripping):\n%s", block)
		}
	}
	if !strings.Contains(body, `id="estate-graph"`) {
		t.Fatal("estate page missing #estate-graph hook")
	}
}
