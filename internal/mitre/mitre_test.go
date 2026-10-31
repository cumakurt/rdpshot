package mitre_test

import (
	"testing"
	"time"

	"rdpshot/internal/mitre"
	"rdpshot/internal/model"
)

func findings(checkIDs ...string) []model.Finding {
	fs := make([]model.Finding, len(checkIDs))
	for i, id := range checkIDs {
		fs[i] = model.Finding{
			CheckID:  id,
			Severity: model.SeverityHigh,
			Status:   model.FindingVulnerable,
		}
	}
	return fs
}

func hosts(nla bool) []model.Host {
	return []model.Host{
		{
			Endpoint: model.Endpoint{Address: "10.0.0.1", Port: 3389},
			State:    "open",
			Service: &model.ServiceInfo{
				NLARequired: nla,
				TLSVersion:  "TLS 1.2",
			},
			UpdatedAt: time.Now(),
		},
	}
}

func TestBuildHeatmap_BlueKeepDetectedAsT1190(t *testing.T) {
	hm := mitre.BuildHeatmap("scan-1", "eng", hosts(true),
		findings("bluekeep-cve-2019-0708"), nil)

	found := false
	for _, tech := range hm.Techniques {
		if tech.ID == "T1190" {
			if tech.Status != mitre.StatusDetected {
				t.Errorf("T1190 should be detected when BlueKeep finding present, got %q", tech.Status)
			}
			found = true
		}
	}
	if !found {
		t.Error("T1190 technique not found in heatmap")
	}
	if hm.Detected == 0 {
		t.Error("expected at least one detected technique")
	}
}

func TestBuildHeatmap_ValidCredsDetectsT1078(t *testing.T) {
	creds := []model.Credential{
		{Username: "admin", Address: "10.0.0.1", Port: 3389, VerifiedAt: time.Now()},
	}
	hm := mitre.BuildHeatmap("scan-1", "eng", hosts(true), nil, creds)
	for _, tech := range hm.Techniques {
		if tech.ID == "T1078" {
			if tech.Status != mitre.StatusDetected {
				t.Errorf("T1078 should be detected when creds found, got %q", tech.Status)
			}
			return
		}
	}
	t.Error("T1078 not found")
}

func TestBuildHeatmap_MFAMitigatesSpray(t *testing.T) {
	h := []model.Host{
		{
			Endpoint: model.Endpoint{Address: "10.0.0.1", Port: 3389},
			State:    "open",
			Service:  &model.ServiceInfo{NLARequired: true, MFAEnforced: true},
			UpdatedAt: time.Now(),
		},
	}
	hm := mitre.BuildHeatmap("scan-1", "eng", h, nil, nil)
	for _, tech := range hm.Techniques {
		if tech.ID == "T1110.003" {
			if tech.Status != mitre.StatusMitigated {
				t.Errorf("T1110.003 should be mitigated when MFA enforced, got %q", tech.Status)
			}
			return
		}
	}
	t.Error("T1110.003 not found")
}

func TestBuildHeatmap_ShadowPolicyDetectsHijack(t *testing.T) {
	hm := mitre.BuildHeatmap("scan-1", "eng", hosts(true),
		findings("rdp-shadow-unprompted-exposed"), nil)
	for _, tech := range hm.Techniques {
		if tech.ID == "T1563.002" {
			if tech.Status != mitre.StatusDetected {
				t.Errorf("T1563.002 should be detected for shadow finding, got %q", tech.Status)
			}
			return
		}
	}
	t.Error("T1563.002 not found")
}

func TestBuildHeatmap_Counters(t *testing.T) {
	hm := mitre.BuildHeatmap("scan-1", "eng", hosts(false),
		findings("rdp-service-exposed", "nla-not-required", "bluekeep-cve-2019-0708"), nil)
	total := hm.Detected + hm.Mitigated + hm.Potential + hm.NotApplicable
	if total != len(hm.Techniques) {
		t.Errorf("counters sum %d != len(techniques) %d", total, len(hm.Techniques))
	}
}

func TestBuildHeatmap_EmptyInput(t *testing.T) {
	hm := mitre.BuildHeatmap("", "", nil, nil, nil)
	if len(hm.Techniques) == 0 {
		t.Error("expected catalog techniques even with empty input")
	}
}
