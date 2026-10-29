package vuln

import (
	"testing"

	"rdpshot/internal/model"
)

func TestCertHostnameMismatch(t *testing.T) {
	svc := &model.ServiceInfo{
		Certificate: &model.CertificateInfo{
			Subject:  "CN=other.example",
			DNSNames: []string{"other.example"},
		},
	}
	status, _ := evaluateCertHostname(Input{Service: svc, TargetHost: "rdp.example.com"})
	if status != model.FindingVulnerable {
		t.Fatalf("status=%q want vulnerable", status)
	}
	status, _ = evaluateCertHostname(Input{Service: svc, TargetHost: "other.example"})
	if status != model.FindingNotVulnerable {
		t.Fatalf("status=%q want not_vulnerable", status)
	}
}

func TestMatchWildcard(t *testing.T) {
	if !matchWildcard("*.example.com", "a.example.com") {
		t.Fatal("expected wildcard match")
	}
	if matchWildcard("*.example.com", "a.b.example.com") {
		t.Fatal("nested label must not match")
	}
}
