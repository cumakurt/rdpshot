package engagement

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"rdpshot/internal/model"
	"rdpshot/internal/screenshot"
)

// PackVersion is the evidence ZIP schema revision.
const PackVersion = "2"

// PackInput is everything AssemblePack needs to build a self-contained evidence ZIP.
type PackInput struct {
	Scan           model.Scan
	ToolVersion    string
	HardeningScore int
	HardeningGrade string
	Branding       model.ReportBranding
	Hosts          []model.Host
	Findings       []model.Finding
	Credentials    []model.Credential // must already be masked
	AuthAttempts   []model.AuthAttempt
	ReportHTML     []byte
	FindingsCSV    []byte
	ReportPDF      []byte
	// Screenshots maps archive-relative paths (screenshots/foo.png) to bytes.
	Screenshots map[string][]byte
}

// AssemblePack builds the named file map for an evidence ZIP (manifest excluded).
func AssemblePack(in PackInput) (map[string][]byte, error) {
	files := map[string][]byte{}

	meta, err := json.MarshalIndent(map[string]any{
		"pack_version": PackVersion,
		"scan":         in.Scan,
		"generated":    time.Now().UTC(),
		"branding":     in.Branding,
		"tool":         in.ToolVersion,
		"score":        in.HardeningScore,
		"grade":        in.HardeningGrade,
		"counts": map[string]int{
			"hosts":         len(in.Hosts),
			"findings":      len(in.Findings),
			"credentials":   len(in.Credentials),
			"auth_attempts": len(in.AuthAttempts),
			"screenshots":   len(in.Screenshots),
		},
	}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("engagement: encode meta: %w", err)
	}
	files["meta.json"] = meta

	if raw, err := json.MarshalIndent(in.Hosts, "", "  "); err == nil {
		files["hosts.json"] = raw
	}
	if raw, err := json.MarshalIndent(in.Findings, "", "  "); err == nil {
		files["findings.json"] = raw
	}
	if raw, err := json.MarshalIndent(in.Credentials, "", "  "); err == nil {
		files["credentials-masked.json"] = raw
	}
	if raw, err := json.MarshalIndent(in.AuthAttempts, "", "  "); err == nil {
		files["auth_attempts.json"] = raw
	}
	if raw, err := json.MarshalIndent(map[string]any{
		"score": in.HardeningScore,
		"grade": in.HardeningGrade,
	}, "", "  "); err == nil {
		files["score.json"] = raw
	}

	if len(in.ReportHTML) > 0 {
		files["report.html"] = in.ReportHTML
	}
	if len(in.FindingsCSV) > 0 {
		files["findings.csv"] = in.FindingsCSV
	}
	if len(in.ReportPDF) > 0 {
		files["report.pdf"] = in.ReportPDF
	}
	for name, body := range in.Screenshots {
		files[name] = body
	}

	files["PACK_README.txt"] = []byte(packReadme(in))
	return files, nil
}

// FilterPackScreenshots drops synthetic open-host detection cards.
func FilterPackScreenshots(shots []model.Screenshot) []model.Screenshot {
	out := make([]model.Screenshot, 0, len(shots))
	for _, sc := range shots {
		if sc.Username == screenshot.OpenHostLabel {
			continue
		}
		out = append(out, sc)
	}
	return out
}

func packReadme(in PackInput) string {
	var b strings.Builder
	b.WriteString("rdpshot evidence pack v" + PackVersion + "\n")
	b.WriteString("Scan: " + in.Scan.Name + " (" + in.Scan.ID + ")\n")
	if in.Scan.Engagement != "" {
		b.WriteString("Engagement: " + in.Scan.Engagement + "\n")
	}
	b.WriteString("Hardening score: " + fmt.Sprintf("%d (%s)\n", in.HardeningScore, in.HardeningGrade))
	b.WriteString("\nContents:\n")
	names := []string{
		"meta.json", "manifest.json", "hosts.json", "findings.json",
		"credentials-masked.json", "auth_attempts.json", "score.json",
		"report.html", "findings.csv", "report.pdf", "screenshots/",
	}
	sort.Strings(names)
	for _, n := range names {
		b.WriteString("  - " + n + "\n")
	}
	b.WriteString("\nSecrets are never included. credentials-masked.json redacts secrets.\n")
	b.WriteString("Verify integrity with manifest.json (SHA-256 per file + manifest_sha256).\n")
	return b.String()
}
