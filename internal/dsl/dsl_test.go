package dsl_test

import (
	"testing"
	"time"

	"rdpshot/internal/dsl"
	"rdpshot/internal/model"
)

// ─────────────────────────────────────────────────────────────────────────────
// Parse tests
// ─────────────────────────────────────────────────────────────────────────────

func TestParse_EmptyQuery(t *testing.T) {
	f, err := dsl.Parse("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.NLA != nil || f.TLS != "" || f.Port != 0 {
		t.Error("empty query should produce zero Filter")
	}
}

func TestParse_NLA(t *testing.T) {
	f, err := dsl.Parse("nla:false")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.NLA == nil || *f.NLA != false {
		t.Errorf("expected nla=false, got %v", f.NLA)
	}
}

func TestParse_TLS(t *testing.T) {
	cases := []struct{ input, want string }{
		{"tls:1.0", "TLS 1.0"},
		{"tls:1.2", "TLS 1.2"},
		{"tls:1.3", "TLS 1.3"},
	}
	for _, tc := range cases {
		f, err := dsl.Parse(tc.input)
		if err != nil {
			t.Fatalf("Parse(%q) error: %v", tc.input, err)
		}
		if f.TLS != tc.want {
			t.Errorf("Parse(%q).TLS = %q, want %q", tc.input, f.TLS, tc.want)
		}
	}
}

func TestParse_Port(t *testing.T) {
	f, err := dsl.Parse("port:3389")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Port != 3389 {
		t.Errorf("expected port=3389, got %d", f.Port)
	}
}

func TestParse_State(t *testing.T) {
	f, err := dsl.Parse("state:open")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.State != "open" {
		t.Errorf("expected state=open, got %q", f.State)
	}
}

func TestParse_Severity(t *testing.T) {
	f, err := dsl.Parse("severity:critical")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Severity != "critical" {
		t.Errorf("expected severity=critical, got %q", f.Severity)
	}
}

func TestParse_CVE(t *testing.T) {
	f, err := dsl.Parse("cve:CVE-2019-0708")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.CVE != "CVE-2019-0708" {
		t.Errorf("expected CVE-2019-0708, got %q", f.CVE)
	}
}

func TestParse_MultipleTokens(t *testing.T) {
	f, err := dsl.Parse("nla:false tls:1.0 severity:critical")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.NLA == nil || *f.NLA != false {
		t.Error("nla not set")
	}
	if f.TLS != "TLS 1.0" {
		t.Errorf("tls not set correctly: %q", f.TLS)
	}
	if f.Severity != "critical" {
		t.Errorf("severity not set: %q", f.Severity)
	}
}

func TestParse_InvalidField(t *testing.T) {
	_, err := dsl.Parse("unknownfield:value")
	if err == nil {
		t.Error("expected error for unknown field")
	}
}

func TestParse_InvalidSeverity(t *testing.T) {
	_, err := dsl.Parse("severity:extreme")
	if err == nil {
		t.Error("expected error for invalid severity")
	}
}

func TestParse_InvalidBool(t *testing.T) {
	_, err := dsl.Parse("nla:maybe")
	if err == nil {
		t.Error("expected error for invalid bool")
	}
}

func TestParse_InvalidPort(t *testing.T) {
	_, err := dsl.Parse("port:notaport")
	if err == nil {
		t.Error("expected error for invalid port")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ApplyToHosts tests
// ─────────────────────────────────────────────────────────────────────────────

func makeHost(addr string, port uint16, state string, nla bool, tls string) model.Host {
	return model.Host{
		Endpoint:  model.Endpoint{Address: addr, Port: port},
		State:     state,
		Service:   &model.ServiceInfo{NLARequired: nla, TLSVersion: tls},
		UpdatedAt: time.Now(),
	}
}

func TestApplyToHosts_NLAFilter(t *testing.T) {
	hosts := []model.Host{
		makeHost("10.0.0.1", 3389, "open", false, "TLS 1.2"),
		makeHost("10.0.0.2", 3389, "open", true, "TLS 1.3"),
	}
	f, _ := dsl.Parse("nla:false")
	out := dsl.ApplyToHosts(f, hosts, nil, nil)
	if len(out) != 1 || out[0].Endpoint.Address != "10.0.0.1" {
		t.Errorf("expected 1 host without NLA, got %d", len(out))
	}
}

func TestApplyToHosts_TLSFilter(t *testing.T) {
	hosts := []model.Host{
		makeHost("10.0.0.1", 3389, "open", false, "TLS 1.0"),
		makeHost("10.0.0.2", 3389, "open", true, "TLS 1.2"),
	}
	f, _ := dsl.Parse("tls:1.0")
	out := dsl.ApplyToHosts(f, hosts, nil, nil)
	if len(out) != 1 || out[0].Endpoint.Address != "10.0.0.1" {
		t.Errorf("expected 1 legacy TLS host, got %d", len(out))
	}
}

func TestApplyToHosts_StateFilter(t *testing.T) {
	hosts := []model.Host{
		makeHost("10.0.0.1", 3389, "open", false, ""),
		makeHost("10.0.0.2", 3389, "closed", false, ""),
	}
	f, _ := dsl.Parse("state:open")
	out := dsl.ApplyToHosts(f, hosts, nil, nil)
	if len(out) != 1 {
		t.Errorf("expected 1 open host, got %d", len(out))
	}
}

func TestApplyToHosts_CredsFilter(t *testing.T) {
	hosts := []model.Host{
		makeHost("10.0.0.1", 3389, "open", false, ""),
		makeHost("10.0.0.2", 3389, "open", false, ""),
	}
	credAddrs := map[string]bool{"10.0.0.1:3389": true}
	f, _ := dsl.Parse("creds:true")
	out := dsl.ApplyToHosts(f, hosts, nil, credAddrs)
	if len(out) != 1 || out[0].Endpoint.Address != "10.0.0.1" {
		t.Errorf("expected 1 host with creds, got %d", len(out))
	}
}

func TestApplyToHosts_CVEFilter(t *testing.T) {
	hosts := []model.Host{
		makeHost("10.0.0.1", 3389, "open", false, ""),
		makeHost("10.0.0.2", 3389, "open", false, ""),
	}
	findings := []model.Finding{
		{
			Address: "10.0.0.1", Port: 3389,
			CVE: "CVE-2019-0708", Status: model.FindingVulnerable,
			Severity: model.SeverityCritical,
		},
	}
	f, _ := dsl.Parse("cve:CVE-2019-0708")
	out := dsl.ApplyToHosts(f, hosts, findings, nil)
	if len(out) != 1 || out[0].Endpoint.Address != "10.0.0.1" {
		t.Errorf("expected 1 host with BlueKeep CVE, got %d", len(out))
	}
}

func TestApplyToHosts_EmptyFilter(t *testing.T) {
	hosts := []model.Host{
		makeHost("10.0.0.1", 3389, "open", false, ""),
		makeHost("10.0.0.2", 3389, "open", true, ""),
	}
	f, _ := dsl.Parse("")
	out := dsl.ApplyToHosts(f, hosts, nil, nil)
	if len(out) != 2 {
		t.Errorf("empty filter should return all hosts, got %d", len(out))
	}
}
