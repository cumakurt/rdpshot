// Package sarif builds SARIF 2.1.0 output from rdpshot scan findings.
// The format is understood by GitHub Advanced Security, GitLab SAST, and any
// SARIF-aware CI/CD pipeline.
//
// Specification reference:
//
//	https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
package sarif

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"rdpshot/internal/model"
)

const (
	sarifVersion  = "2.1.0"
	sarifSchema   = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json"
	toolName      = "RDPShot"
	toolInfoURI   = "https://github.com/rdpshot/rdpshot"
)

// ─────────────────────────────────────────────────────────────────────────────
// SARIF 2.1.0 struct hierarchy (subset needed for security tool output)
// ─────────────────────────────────────────────────────────────────────────────

// Log is the top-level SARIF document.
type Log struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []Run  `json:"runs"`
}

// Run is one tool execution.
type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

// Tool identifies the scanning tool.
type Tool struct {
	Driver Driver `json:"driver"`
}

// Driver describes the tool that produced this run.
type Driver struct {
	Name            string `json:"name"`
	Version         string `json:"version,omitempty"`
	InformationURI  string `json:"informationUri,omitempty"`
	Rules           []Rule `json:"rules"`
}

// Rule describes one check (maps 1:1 to model.Finding.CheckID).
type Rule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	ShortDescription Message         `json:"shortDescription"`
	FullDescription  *Message        `json:"fullDescription,omitempty"`
	DefaultConfig    *RuleConfig     `json:"defaultConfiguration,omitempty"`
	Properties       *RuleProperties `json:"properties,omitempty"`
}

// RuleConfig sets the default severity level for a rule.
type RuleConfig struct {
	Level string `json:"level"` // "error" | "warning" | "note" | "none"
}

// RuleProperties carries additional metadata.
type RuleProperties struct {
	Tags     []string `json:"tags,omitempty"`
	CVE      string   `json:"cve,omitempty"`
	CVSS     float64  `json:"cvss,omitempty"`
	Severity string   `json:"severity,omitempty"` // rdpshot native severity
}

// Message wraps a SARIF message text.
type Message struct {
	Text string `json:"text"`
}

// Result is one finding instance.
type Result struct {
	RuleID    string     `json:"ruleId"`
	Level     string     `json:"level"`
	Message   Message    `json:"message"`
	Locations []Location `json:"locations,omitempty"`
	Properties *ResultProperties `json:"properties,omitempty"`
}

// Location pinpoints where the issue was observed.
type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

// PhysicalLocation points to the affected "file" (we use rdp://address:port URI).
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
}

// ArtifactLocation is the URI of the affected resource.
type ArtifactLocation struct {
	URI         string `json:"uri"`
	Description *Message `json:"description,omitempty"`
}

// ResultProperties carries extra metadata attached to a result.
type ResultProperties struct {
	DetectedAt  string `json:"detected_at,omitempty"`
	Evidence    string `json:"evidence,omitempty"`
	Remediation string `json:"remediation,omitempty"`
	TriageStatus string `json:"triage_status,omitempty"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Builder
// ─────────────────────────────────────────────────────────────────────────────

// BuildSARIF converts a scan's findings into a SARIF 2.1.0 Log.
func BuildSARIF(scan model.Scan, hosts []model.Host, findings []model.Finding) Log {
	// Collect unique rules from findings.
	ruleMap := map[string]Rule{}
	for _, f := range findings {
		if _, ok := ruleMap[f.CheckID]; ok {
			continue
		}
		ruleMap[f.CheckID] = buildRule(f)
	}
	rules := make([]Rule, 0, len(ruleMap))
	for _, r := range ruleMap {
		rules = append(rules, r)
	}
	sortRules(rules)

	// Build results.
	var results []Result
	for _, f := range findings {
		if f.Status == model.FindingNotVulnerable || f.Status == model.FindingInconclusive {
			continue
		}
		results = append(results, buildResult(f))
	}

	return Log{
		Version: sarifVersion,
		Schema:  sarifSchema,
		Runs: []Run{
			{
				Tool: Tool{
					Driver: Driver{
						Name:           toolName,
						Version:        scan.Options.AuthMode, // version injected by caller if needed
						InformationURI: toolInfoURI,
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}
}

// HasCritical reports whether the SARIF log contains any error-level results,
// used to implement the --fail-on-critical CI/CD gate.
func (l Log) HasCritical() bool {
	for _, run := range l.Runs {
		for _, r := range run.Results {
			if r.Level == "error" {
				return true
			}
		}
	}
	return false
}

// JSON serialises the SARIF log to indented JSON.
func (l Log) JSON() ([]byte, error) {
	return json.MarshalIndent(l, "", "  ")
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func buildRule(f model.Finding) Rule {
	r := Rule{
		ID:   f.CheckID,
		Name: camelCase(f.CheckID),
		ShortDescription: Message{Text: f.Title},
		DefaultConfig: &RuleConfig{Level: sarifLevel(f.Severity)},
		Properties: &RuleProperties{
			Severity: string(f.Severity),
		},
	}
	if f.CVE != "" {
		r.Properties.CVE = f.CVE
		r.Properties.CVSS = f.CVSS
		r.Properties.Tags = append(r.Properties.Tags, f.CVE)
	}
	r.Properties.Tags = append(r.Properties.Tags, "rdp", string(f.Severity))
	if f.Remediation != "" {
		r.FullDescription = &Message{Text: f.Remediation}
	}
	return r
}

func buildResult(f model.Finding) Result {
	uri := fmt.Sprintf("rdp://%s:%d", f.Address, f.Port)
	desc := fmt.Sprintf("[%s] %s on %s:%d", strings.ToUpper(string(f.Severity)), f.Title, f.Address, f.Port)
	if f.Evidence != "" {
		desc += " — " + f.Evidence
	}

	props := &ResultProperties{
		DetectedAt:   f.DetectedAt.Format(time.RFC3339),
		TriageStatus: string(f.TriageStatus),
	}
	if f.Evidence != "" {
		props.Evidence = f.Evidence
	}
	if f.Remediation != "" {
		props.Remediation = f.Remediation
	}

	return Result{
		RuleID: f.CheckID,
		Level:  sarifLevel(f.Severity),
		Message: Message{Text: desc},
		Locations: []Location{
			{
				PhysicalLocation: PhysicalLocation{
					ArtifactLocation: ArtifactLocation{
						URI: uri,
						Description: &Message{
							Text: fmt.Sprintf("RDP endpoint %s:%d", f.Address, f.Port),
						},
					},
				},
			},
		},
		Properties: props,
	}
}

// sarifLevel maps rdpshot severity to SARIF level.
func sarifLevel(sev model.Severity) string {
	switch sev {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// camelCase converts "nla-not-required" → "NlaNotRequired".
func camelCase(s string) string {
	parts := strings.Split(s, "-")
	for i, p := range parts {
		if len(p) > 0 {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, "")
}

func sortRules(rules []Rule) {
	// Simple insertion sort by ID for deterministic output.
	for i := 1; i < len(rules); i++ {
		key := rules[i]
		j := i - 1
		for j >= 0 && rules[j].ID > key.ID {
			rules[j+1] = rules[j]
			j--
		}
		rules[j+1] = key
	}
}
