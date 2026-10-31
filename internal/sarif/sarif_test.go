package sarif_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"rdpshot/internal/model"
	"rdpshot/internal/sarif"
)

func scan() model.Scan {
	return model.Scan{
		ID:   "scan-001",
		Name: "Test Scan",
	}
}

func findings() []model.Finding {
	return []model.Finding{
		{
			ID: 1, ScanID: "scan-001", Address: "10.0.0.1", Port: 3389,
			CheckID: "bluekeep-cve-2019-0708", Title: "BlueKeep RCE",
			Severity: model.SeverityCritical, Status: model.FindingVulnerable,
			CVE: "CVE-2019-0708", CVSS: 9.8,
			Evidence:    "MCS server version 0x0007001F",
			Remediation: "Apply Microsoft security update MS19-0708",
			DetectedAt:  time.Now(),
			TriageStatus: model.TriageOpen,
		},
		{
			ID: 2, ScanID: "scan-001", Address: "10.0.0.1", Port: 3389,
			CheckID: "nla-not-required", Title: "NLA Not Required",
			Severity: model.SeverityHigh, Status: model.FindingVulnerable,
			DetectedAt: time.Now(), TriageStatus: model.TriageOpen,
		},
		{
			ID: 3, ScanID: "scan-001", Address: "10.0.0.2", Port: 3389,
			CheckID: "weak-tls", Title: "Weak TLS Version",
			Severity: model.SeverityMedium, Status: model.FindingVulnerable,
			DetectedAt: time.Now(), TriageStatus: model.TriageOpen,
		},
		{
			// Not-vulnerable finding should be excluded.
			ID: 4, ScanID: "scan-001", Address: "10.0.0.3", Port: 3389,
			CheckID: "mfa-enforced", Title: "MFA Enforced",
			Severity: model.SeverityInfo, Status: model.FindingNotVulnerable,
			DetectedAt: time.Now(), TriageStatus: model.TriageOpen,
		},
	}
}

func TestBuildSARIF_Version(t *testing.T) {
	log := sarif.BuildSARIF(scan(), nil, findings())
	if log.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %q", log.Version)
	}
	if !strings.Contains(log.Schema, "sarif") {
		t.Errorf("unexpected schema: %q", log.Schema)
	}
}

func TestBuildSARIF_ResultCount(t *testing.T) {
	log := sarif.BuildSARIF(scan(), nil, findings())
	// Not-vulnerable findings are excluded.
	if len(log.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(log.Runs))
	}
	results := log.Runs[0].Results
	if len(results) != 3 {
		t.Errorf("expected 3 results (not_vulnerable excluded), got %d", len(results))
	}
}

func TestBuildSARIF_SeverityMapping(t *testing.T) {
	log := sarif.BuildSARIF(scan(), nil, findings())
	levelByRule := map[string]string{}
	for _, r := range log.Runs[0].Results {
		levelByRule[r.RuleID] = r.Level
	}
	if levelByRule["bluekeep-cve-2019-0708"] != "error" {
		t.Errorf("critical → error, got %q", levelByRule["bluekeep-cve-2019-0708"])
	}
	if levelByRule["nla-not-required"] != "error" {
		t.Errorf("high → error, got %q", levelByRule["nla-not-required"])
	}
	if levelByRule["weak-tls"] != "warning" {
		t.Errorf("medium → warning, got %q", levelByRule["weak-tls"])
	}
}

func TestBuildSARIF_LocationURI(t *testing.T) {
	log := sarif.BuildSARIF(scan(), nil, findings())
	for _, r := range log.Runs[0].Results {
		if len(r.Locations) == 0 {
			t.Errorf("result %q has no locations", r.RuleID)
			continue
		}
		uri := r.Locations[0].PhysicalLocation.ArtifactLocation.URI
		if !strings.HasPrefix(uri, "rdp://") {
			t.Errorf("expected rdp:// URI, got %q", uri)
		}
	}
}

func TestBuildSARIF_HasCritical(t *testing.T) {
	log := sarif.BuildSARIF(scan(), nil, findings())
	if !log.HasCritical() {
		t.Error("expected HasCritical() = true when critical finding present")
	}
}

func TestBuildSARIF_HasCriticalFalse(t *testing.T) {
	lowOnly := []model.Finding{
		{
			CheckID: "rdp-service-exposed", Severity: model.SeverityInfo,
			Status: model.FindingVulnerable, DetectedAt: time.Now(),
			TriageStatus: model.TriageOpen,
		},
	}
	log := sarif.BuildSARIF(scan(), nil, lowOnly)
	if log.HasCritical() {
		t.Error("expected HasCritical() = false for info-only findings")
	}
}

func TestBuildSARIF_JSONRoundTrip(t *testing.T) {
	log := sarif.BuildSARIF(scan(), nil, findings())
	b, err := log.JSON()
	if err != nil {
		t.Fatalf("JSON() error: %v", err)
	}
	var rt sarif.Log
	if err := json.Unmarshal(b, &rt); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if rt.Version != "2.1.0" {
		t.Error("round-trip version mismatch")
	}
}

func TestBuildSARIF_RulesDeduplication(t *testing.T) {
	// Same CheckID appears on two hosts — should produce only one rule.
	fs := []model.Finding{
		{
			CheckID: "nla-not-required", Title: "NLA", Severity: model.SeverityHigh,
			Address: "10.0.0.1", Port: 3389, Status: model.FindingVulnerable,
			DetectedAt: time.Now(), TriageStatus: model.TriageOpen,
		},
		{
			CheckID: "nla-not-required", Title: "NLA", Severity: model.SeverityHigh,
			Address: "10.0.0.2", Port: 3389, Status: model.FindingVulnerable,
			DetectedAt: time.Now(), TriageStatus: model.TriageOpen,
		},
	}
	log := sarif.BuildSARIF(scan(), nil, fs)
	rules := log.Runs[0].Tool.Driver.Rules
	if len(rules) != 1 {
		t.Errorf("expected 1 deduplicated rule, got %d", len(rules))
	}
	if len(log.Runs[0].Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(log.Runs[0].Results))
	}
}
