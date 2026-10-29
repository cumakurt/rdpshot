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
