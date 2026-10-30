// Package reporter renders scan results into report formats: HTML for
// browsers, CSV for SIEM ingestion and PDF for management distribution.
package reporter

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"rdpshot/internal/about"
	"rdpshot/internal/model"
)

// toolName identifies the generator in report headers and footers.
const toolName = about.Product

// Data is everything a report needs; it is fully self-contained.
type Data struct {
	Scan           model.Scan
	Summary        model.Summary
	Hosts          []model.Host
	Findings       []model.Finding
	Credentials    []model.Credential // already masked by the caller; never print raw secrets
	Screens        []model.Screenshot
	CVEStats       []model.CVEStat
	GeneratedAt    time.Time
	ToolVersion    string
	Branding       model.ReportBranding
	HardeningScore int
	HardeningGrade string
}

// sortedFindings returns a copy of the findings ordered by severity rank
// (most severe first) and then by host so report rows are stable across runs.
func sortedFindings(findings []model.Finding) []model.Finding {
	sorted := make([]model.Finding, len(findings))
	copy(sorted, findings)
	sort.Slice(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if a.Address != b.Address {
			return a.Address < b.Address
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.CheckID < b.CheckID
	})
	return sorted
}

// severityBucket is one row of the severity distribution.
type severityBucket struct {
	Severity string
	Class    string
	Count    int64
}

// severityBuckets returns one bucket per known severity, most severe first.
// Counts come from the caller-provided summary; when the summary omits the
// per-severity buckets the findings are counted instead so the distribution
// never contradicts the findings table.
func severityBuckets(d Data) []severityBucket {
	fromFindings := len(d.Summary.BySeverity) == 0
	counts := make(map[model.Severity]int64)
	if fromFindings {
		for _, f := range d.Findings {
			counts[f.Severity]++
		}
	}
	severities := []model.Severity{
		model.SeverityCritical,
		model.SeverityHigh,
		model.SeverityMedium,
		model.SeverityLow,
		model.SeverityInfo,
	}
	buckets := make([]severityBucket, 0, len(severities))
	for _, sev := range severities {
		count := d.Summary.CountBySeverity(sev)
		if fromFindings {
			count = counts[sev]
		}
		buckets = append(buckets, severityBucket{
			Severity: string(sev),
			Class:    severityClass(sev),
			Count:    count,
		})
	}
	return buckets
}

// executiveExtras are one-pager counters beyond the base severity cards.
type executiveExtras struct {
	NLACoveragePct   int64
	HostsAudited     int64
	AuthSkippedNoNLA int64
	OpenVulnerable   int64
}

// computeExecutiveExtras derives NLA coverage and auth-audit outcomes.
func computeExecutiveExtras(d Data) executiveExtras {
	var open, nla, audited, skipped, openVuln int64
	for _, h := range d.Hosts {
		if h.State != "open" {
			continue
		}
		open++
		if h.Service == nil {
			continue
		}
		if h.Service.NLARequired {
			nla++
		}
		if h.Service.AuthStoppedReason != "" || h.Service.AuthAttempts > 0 {
			audited++
		}
		if h.Service.Evidence != nil && h.Service.Evidence["auth_path"] == "skipped_no_credssp" {
			skipped++
		}
	}
	for _, f := range d.Findings {
		if f.Status == model.FindingVulnerable || f.Status == model.FindingPotential {
			openVuln++
		}
	}
	var pct int64
	if open > 0 {
		pct = (nla * 100) / open
	}
	return executiveExtras{
		NLACoveragePct:   pct,
		HostsAudited:     audited,
		AuthSkippedNoNLA: skipped,
		OpenVulnerable:   openVuln,
	}
}

// severityClass maps a severity to a whitelisted CSS class suffix so arbitrary
// values can never leak into markup.
func severityClass(s model.Severity) string {
	if !s.Valid() {
		return "unknown"
	}
	return string(s)
}

// formatTime renders a timestamp as UTC RFC 3339; zero times render as empty.
func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// formatTimePtr renders an optional timestamp; nil renders as empty.
func formatTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return formatTime(*t)
}

// orDash renders empty display values as a placeholder.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// formatCVSS renders a score with one decimal; zero renders as empty because
// the model treats 0 as "not scored".
func formatCVSS(score float64) string {
	if score == 0 {
		return ""
	}
	return strconv.FormatFloat(score, 'f', 1, 64)
}

// singleLine collapses line breaks so the value stays within one CSV record
// field or one table row.
func singleLine(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}

// endpointText renders "address:port" for tables and records.
func endpointText(address string, port uint16) string {
	return address + ":" + strconv.FormatUint(uint64(port), 10)
}

// protocolName maps a negotiated RDP protocol code to its specification name.
func protocolName(protocol uint32) string {
	switch protocol {
	case 0:
		return "RDP"
	case 1:
		return "SSL"
	case 2:
		return "HYBRID"
	case 8:
		return "HYBRID_EX"
	default:
		return "unknown (" + strconv.FormatUint(uint64(protocol), 10) + ")"
	}
}

// scopeText lists the scan targets for the report header.
func scopeText(scan model.Scan) string {
	return strings.Join(scan.Options.Targets, ", ")
}
