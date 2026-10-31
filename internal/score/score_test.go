package score

import (
	"testing"

	"rdpshot/internal/model"
)

func TestEvaluateHostNLAPass(t *testing.T) {
	h := model.Host{
		Endpoint: model.Endpoint{Address: "10.0.0.1", Port: 3389},
		State:    "open",
		Service:  &model.ServiceInfo{NLARequired: true, TLSVersion: "TLS 1.2", EncryptionLevel: "high"},
	}
	h.Service.Certificate = &model.CertificateInfo{SelfSigned: false}
	got := EvaluateHost(h, nil)
	if got.Score < 80 {
		t.Fatalf("score = %d, want >= 80 (%+v)", got.Score, got.Rules)
	}
	if got.Grade == "F" {
		t.Fatalf("unexpected grade F")
	}
}

func TestEvaluateScanEmpty(t *testing.T) {
	s := EvaluateScan("s1", nil, nil)
	if s.Score != 100 || s.HostsScored != 0 {
		t.Fatalf("empty scan score = %+v", s)
	}
}

func TestEvaluateCompliancePosture(t *testing.T) {
	// Clean scan -> 100% on all standards
	cp := EvaluateCompliancePosture("s1", nil, nil)
	if cp.OverallScore != 100 {
		t.Fatalf("overall score = %d, want 100", cp.OverallScore)
	}
	if len(cp.Standards) != 4 {
		t.Fatalf("standards count = %d, want 4", len(cp.Standards))
	}

	// Scan with NLA not required and BlueKeep
	hosts := []model.Host{
		{
			Endpoint: model.Endpoint{Address: "172.16.3.128", Port: 3389},
			State:    "open",
			Service:  &model.ServiceInfo{NLARequired: false},
		},
	}
	findings := []model.Finding{
		{
			Address:  "172.16.3.128",
			Port:     3389,
			CheckID:  "bluekeep-cve-2019-0708",
			Severity: "critical",
			Status:   model.FindingVulnerable,
		},
	}
	posture := EvaluateCompliancePosture("s2", hosts, findings)
	if posture.OverallScore >= 100 {
		t.Fatalf("expected degraded overall score, got %d", posture.OverallScore)
	}
	for _, std := range posture.Standards {
		if std.Standard == "PCI-DSS" {
			// PCI-DSS loses 30 (NLA) + 30 (BlueKeep) -> 40%
			if std.Score > 50 {
				t.Fatalf("PCI-DSS score = %d, want <= 50", std.Score)
			}
			if len(std.FailedCheckIDs) < 2 {
				t.Fatalf("PCI-DSS failed checks = %v, want >= 2", std.FailedCheckIDs)
			}
		}
	}
}
