package bloodhound_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"rdpshot/internal/bloodhound"
	"rdpshot/internal/model"
)

func sampleHosts() []model.Host {
	return []model.Host{
		{
			ID:     1,
			ScanID: "scan-001",
			Endpoint: model.Endpoint{Address: "10.0.0.1", Port: 3389},
			State: "open",
			Service: &model.ServiceInfo{
				NLARequired: false,
				TLSVersion:  "TLS 1.2",
				OSGuess:     "Windows Server 2019",
			},
			UpdatedAt: time.Now(),
		},
		{
			ID:     2,
			ScanID: "scan-001",
			Endpoint: model.Endpoint{Address: "10.0.0.2", Port: 3389},
			State: "open",
			Service: &model.ServiceInfo{
				NLARequired: true,
				TLSVersion:  "TLS 1.3",
			},
			UpdatedAt: time.Now(),
		},
		{
			ID:     3,
			ScanID: "scan-001",
			Endpoint: model.Endpoint{Address: "10.0.0.3", Port: 3389},
			State: "closed",
			UpdatedAt: time.Now(),
		},
	}
}

func sampleCreds() []model.Credential {
	return []model.Credential{
		{
			ID: 1, ScanID: "scan-001", HostID: 1,
			Address: "10.0.0.1", Port: 3389,
			Username: "administrator", Domain: "CORP",
			Method: "password", VerifiedAt: time.Now(),
		},
		{
			ID: 2, ScanID: "scan-001", HostID: 1,
			Address: "10.0.0.1", Port: 3389,
			Username: "jdoe", Domain: "CORP",
			Method: "nthash", VerifiedAt: time.Now(),
		},
	}
}

func sampleFindings() []model.Finding {
	return []model.Finding{
		{
			ID: 1, ScanID: "scan-001", HostID: 1,
			Address: "10.0.0.1", Port: 3389,
			CheckID: "bluekeep-cve-2019-0708",
			Title: "BlueKeep", Severity: model.SeverityCritical,
			Status: model.FindingVulnerable,
		},
		{
			ID: 2, ScanID: "scan-001", HostID: 2,
			Address: "10.0.0.2", Port: 3389,
			CheckID: "nla-not-required",
			Title: "NLA Not Required", Severity: model.SeverityHigh,
			Status: model.FindingVulnerable,
		},
	}
}

func TestBuildExport_NodeCount(t *testing.T) {
	hosts := sampleHosts()
	creds := sampleCreds()
	findings := sampleFindings()

	exp := bloodhound.BuildExport("CORP", hosts, creds, findings)

	// 2 open hosts → 2 computer nodes
	// 2 distinct users (administrator, jdoe) → 2 user nodes
	if exp.Meta.Count != len(exp.Data) {
		t.Errorf("meta.count %d != len(data) %d", exp.Meta.Count, len(exp.Data))
	}
	if exp.Meta.Version != 5 {
		t.Errorf("expected version 5, got %d", exp.Meta.Version)
	}
	if exp.Meta.Type != "mixed" {
		t.Errorf("expected type 'mixed', got %q", exp.Meta.Type)
	}
	if exp.Meta.Count == 0 {
		t.Error("expected at least one data entry")
	}
}

func TestBuildExport_SIDsAreDeterministic(t *testing.T) {
	hosts := sampleHosts()
	creds := sampleCreds()

	exp1 := bloodhound.BuildExport("CORP", hosts, creds, nil)
	exp2 := bloodhound.BuildExport("CORP", hosts, creds, nil)

	sids1 := make([]string, len(exp1.Data))
	for i, e := range exp1.Data {
		sids1[i] = e.ObjectIdentifier
	}
	for i, e := range exp2.Data {
		if e.ObjectIdentifier != sids1[i] {
			t.Errorf("SID not deterministic at index %d: %q vs %q", i, sids1[i], e.ObjectIdentifier)
		}
	}
}

func TestBuildExport_BlueKeepSetsUnconstrainedDelegation(t *testing.T) {
	hosts := sampleHosts()
	findings := sampleFindings()
	creds := sampleCreds()

	exp := bloodhound.BuildExport("CORP", hosts, creds, findings)

	for _, e := range exp.Data {
		addr, ok := e.Properties["rdpaddress"]
		if !ok {
			continue // user node
		}
		if addr == "10.0.0.1" {
			if e.Properties["rdpshot_bluekeep"] != true {
				t.Errorf("10.0.0.1 should have rdpshot_bluekeep=true")
			}
			if len(e.LocalAdmins) == 0 {
				t.Errorf("10.0.0.1 should have LocalAdmins (NLA missing + BlueKeep)")
			}
		}
	}
}

func TestBuildExport_ClosedHostExcluded(t *testing.T) {
	hosts := sampleHosts()
	exp := bloodhound.BuildExport("CORP", hosts, nil, nil)
	for _, e := range exp.Data {
		if addr, ok := e.Properties["rdpaddress"]; ok {
			if addr == "10.0.0.3" {
				t.Error("closed host 10.0.0.3 should not appear in export")
			}
		}
	}
}

func TestBuildExport_JSONRoundTrip(t *testing.T) {
	exp := bloodhound.BuildExport("test-eng", sampleHosts(), sampleCreds(), sampleFindings())
	b, err := exp.JSON()
	if err != nil {
		t.Fatalf("JSON() error: %v", err)
	}
	var roundTrip bloodhound.BHExport
	if err := json.Unmarshal(b, &roundTrip); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if roundTrip.Meta.Version != 5 {
		t.Errorf("round-trip version mismatch")
	}
	// SIDs must start with S-1-5-21-
	for _, e := range roundTrip.Data {
		if !strings.HasPrefix(e.ObjectIdentifier, "S-1-5-21-") {
			t.Errorf("unexpected SID format: %q", e.ObjectIdentifier)
		}
	}
}

func TestBuildExport_EmptyInput(t *testing.T) {
	exp := bloodhound.BuildExport("", nil, nil, nil)
	if exp.Meta.Count != 0 {
		t.Errorf("expected 0 entries for empty input, got %d", exp.Meta.Count)
	}
}
