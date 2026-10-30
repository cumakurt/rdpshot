package vuln

import (
	"strings"
	"testing"
	"time"

	"rdpshot/internal/model"
	"rdpshot/internal/rdp"
)

func findingByID(t *testing.T, findings []model.Finding, id string) model.Finding {
	t.Helper()
	for _, f := range findings {
		if f.CheckID == id {
			return f
		}
	}
	t.Fatalf("finding %q not produced (got %d findings)", id, len(findings))
	return model.Finding{}
}

func findingMissing(t *testing.T, findings []model.Finding, id string) {
	t.Helper()
	for _, f := range findings {
		if f.CheckID == id {
			t.Fatalf("finding %q must not be reported: %+v", id, f)
		}
	}
}

func TestEvaluateInsecureEndpoint(t *testing.T) {
	svc := &model.ServiceInfo{
		NegotiatedProtocol: rdp.ProtocolRDP,
		NLARequired:        false,
		EncryptionLevel:    "low",
		TLSVersion:         "TLS 1.0",
		TLSCipherSuite:     "TLS_RSA_WITH_RC4_128_SHA",
	}
	findings := Evaluate(model.Endpoint{Address: "10.0.0.1", Port: 3389}, Input{
		Service: svc,
		BlueKeep: &rdp.BlueKeepResult{
			Attempted: true,
			Triggered: true,
			Reason:    "server answered the MS_T120 check with a Disconnect Provider Ultimatum",
			Evidence:  "MCS Disconnect Provider Ultimatum (reason 0x0)",
		},
	})

	bluekeep := findingByID(t, findings, "bluekeep-cve-2019-0708")
	if bluekeep.Status != model.FindingVulnerable || bluekeep.Severity != model.SeverityCritical {
		t.Fatalf("bluekeep finding = %+v", bluekeep)
	}
	if bluekeep.CVE != "CVE-2019-0708" || bluekeep.CVSS != 9.8 {
		t.Fatalf("bluekeep metadata = %+v", bluekeep)
	}

	if f := findingByID(t, findings, "nla-not-required"); f.Status != model.FindingVulnerable {
		t.Fatalf("nla finding = %+v", f)
	}
	if f := findingByID(t, findings, "weak-encryption"); f.Status != model.FindingVulnerable {
		t.Fatalf("encryption finding = %+v", f)
	}
	if f := findingByID(t, findings, "weak-tls"); f.Status != model.FindingVulnerable {
		t.Fatalf("tls finding = %+v", f)
	}
	if f := findingByID(t, findings, "rdp-security-without-tls"); f.Status != model.FindingVulnerable {
		t.Fatalf("legacy security finding = %+v", f)
	}
	findingMissing(t, findings, "dejablue-cve-2019-1181-1182")
	for _, f := range findings {
		if f.Address != "10.0.0.1" || f.Port != 3389 {
			t.Fatalf("endpoint not attached: %+v", f)
		}
		if f.Remediation == "" {
			t.Fatalf("finding without remediation: %+v", f)
		}
		if f.Status != model.FindingVulnerable && f.Status != model.FindingNotVulnerable {
			t.Fatalf("speculative status leaked: %+v", f)
		}
	}
}

func TestEvaluateHardenedEndpointOmitsSpeculativeBlueKeep(t *testing.T) {
	cert := &model.CertificateInfo{
		Subject:    "CN=rdp.example.com",
		Issuer:     "CN=Example CA",
		NotAfter:   time.Now().Add(365 * 24 * time.Hour),
		SelfSigned: false,
		DNSNames:   []string{"rdp.example.com"},
	}
	svc := &model.ServiceInfo{
		NegotiatedProtocol: rdp.ProtocolHybrid,
		NLARequired:        true,
		EncryptionLevel:    "high",
		TLSVersion:         "TLS 1.3",
		TLSCipherSuite:     "TLS_AES_256_GCM_SHA384",
		Certificate:        cert,
	}
	findings := Evaluate(model.Endpoint{Address: "10.0.0.2", Port: 3389}, Input{
		Service:    svc,
		TargetHost: "rdp.example.com",
	})

	for _, f := range findings {
		if f.Severity != model.SeverityInfo && f.Status == model.FindingVulnerable {
			t.Fatalf("hardened endpoint must have no vulnerable findings: %+v", f)
		}
	}
	// NLA blocks the pre-auth probe — do not invent Critical/potential noise.
	findingMissing(t, findings, "bluekeep-cve-2019-0708")
	findingMissing(t, findings, "dejablue-cve-2019-1181-1182")
}

func TestBlueKeepNotVulnerableIsReported(t *testing.T) {
	svc := &model.ServiceInfo{NegotiatedProtocol: rdp.ProtocolSSL, EncryptionLevel: "none"}
	findings := Evaluate(model.Endpoint{Address: "10.0.0.3", Port: 3389}, Input{
		Service: svc,
		BlueKeep: &rdp.BlueKeepResult{
			Attempted: true,
			Triggered: false,
			Reason:    "no MS_T120 response within 6s",
			Evidence:  "sent 10 MS_T120 check messages",
		},
	})
	bluekeep := findingByID(t, findings, "bluekeep-cve-2019-0708")
	if bluekeep.Status != model.FindingNotVulnerable {
		t.Fatalf("bluekeep finding = %+v", bluekeep)
	}
}

func TestBlueKeepSkippedWhenProbeNotAttempted(t *testing.T) {
	svc := &model.ServiceInfo{NegotiatedProtocol: rdp.ProtocolRDP, EncryptionLevel: "high"}
	findings := Evaluate(model.Endpoint{Address: "10.0.0.4", Port: 3389}, Input{
		Service: svc,
		BlueKeep: &rdp.BlueKeepResult{
			Attempted: false,
			Reason:    "virtual channel layer unavailable (NLA or legacy encryption)",
		},
	})
	findingMissing(t, findings, "bluekeep-cve-2019-0708")
}

func TestBlueKeepIgnoresUnconfirmedTrigger(t *testing.T) {
	svc := &model.ServiceInfo{NegotiatedProtocol: rdp.ProtocolRDP}
	findings := Evaluate(model.Endpoint{Address: "10.0.0.7", Port: 3389}, Input{
		Service: svc,
		BlueKeep: &rdp.BlueKeepResult{
			Attempted: true,
			Triggered: true,
			Reason:    "server closed the connection after the check messages",
			Evidence:  "sent 2 messages",
		},
	})
	findingMissing(t, findings, "bluekeep-cve-2019-0708")
}

func TestSelfSignedAndExpiredCertificates(t *testing.T) {
	svc := &model.ServiceInfo{
		NegotiatedProtocol: rdp.ProtocolSSL,
		Certificate: &model.CertificateInfo{
			Subject:    "CN=self",
			Issuer:     "CN=self",
			SelfSigned: true,
			NotAfter:   time.Now().Add(-24 * time.Hour),
		},
	}
	findings := Evaluate(model.Endpoint{Address: "10.0.0.5", Port: 3389}, Input{Service: svc})
	if f := findingByID(t, findings, "self-signed-cert"); f.Status != model.FindingVulnerable {
		t.Fatalf("self-signed finding = %+v", f)
	}
	if f := findingByID(t, findings, "expired-cert"); f.Status != model.FindingVulnerable {
		t.Fatalf("expired finding = %+v", f)
	}
}

func TestExpiringCertificateIsNotReported(t *testing.T) {
	svc := &model.ServiceInfo{
		NegotiatedProtocol: rdp.ProtocolSSL,
		Certificate: &model.CertificateInfo{
			Subject:  "CN=soon",
			Issuer:   "CN=CA",
			NotAfter: time.Now().Add(10 * 24 * time.Hour),
		},
	}
	findings := Evaluate(model.Endpoint{Address: "10.0.0.8", Port: 3389}, Input{Service: svc})
	findingMissing(t, findings, "expired-cert")
}

func TestFindingsCarryStableIdentifiers(t *testing.T) {
	svc := &model.ServiceInfo{NegotiatedProtocol: rdp.ProtocolSSL}
	findings := Evaluate(model.Endpoint{Address: "10.0.0.6", Port: 3389}, Input{Service: svc})
	seen := map[string]bool{}
	for _, f := range findings {
		if seen[f.CheckID] {
			t.Fatalf("duplicate check id %q", f.CheckID)
		}
		seen[f.CheckID] = true
		if strings.TrimSpace(f.Title) == "" {
			t.Fatalf("finding without title: %+v", f)
		}
	}
	if !seen["rdp-service-exposed"] {
		t.Fatal("expected the informational exposure finding")
	}
}
