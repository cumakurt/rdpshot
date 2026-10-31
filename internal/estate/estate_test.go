package estate

import (
	"testing"

	"rdpshot/internal/model"
)

func TestBuildOmitsClosedHosts(t *testing.T) {
	hosts := []model.Host{
		{Endpoint: model.Endpoint{Address: "10.0.0.1", Port: 3389}, State: "open"},
		{Endpoint: model.Endpoint{Address: "10.0.0.2", Port: 3389}, State: "closed"},
		{Endpoint: model.Endpoint{Address: "10.0.0.3", Port: 3389}, State: "filtered"},
	}
	g := Build("lab", hosts, nil)
	if len(g.Nodes) != 1 {
		t.Fatalf("nodes = %d, want 1 open host", len(g.Nodes))
	}
	if g.Nodes[0].ID != "10.0.0.1:3389" || !g.Nodes[0].Open {
		t.Fatalf("node = %+v", g.Nodes[0])
	}
}

func TestBuildPrefersOpenWhenDuplicateKey(t *testing.T) {
	hosts := []model.Host{
		{Endpoint: model.Endpoint{Address: "10.0.0.9", Port: 3389}, State: "closed"},
		{Endpoint: model.Endpoint{Address: "10.0.0.9", Port: 3389}, State: "open",
			Service: &model.ServiceInfo{TLSVersion: "TLS 1.2"}},
	}
	g := Build("", hosts, nil)
	if len(g.Nodes) != 1 {
		t.Fatalf("nodes = %d, want 1", len(g.Nodes))
	}
	if g.Nodes[0].TLSVersion != "TLS 1.2" {
		t.Fatalf("tls = %q, closed record must not win", g.Nodes[0].TLSVersion)
	}
}

func TestBuildBlastRadius(t *testing.T) {
	hosts := []model.Host{
		{
			Endpoint: model.Endpoint{Address: "172.16.3.128", Port: 3389},
			State:    "open",
			Service:  &model.ServiceInfo{NLARequired: true},
		},
		{
			Endpoint: model.Endpoint{Address: "172.16.3.130", Port: 3389},
			State:    "open",
			Service:  &model.ServiceInfo{NLARequired: false},
		},
	}
	creds := []model.Credential{
		{
			Address:  "172.16.3.128",
			Port:     3389,
			Username: "cmk",
			Domain:   "CORP",
			Method:   "nla",
		},
	}
	findings := []model.Finding{
		{
			Address:  "172.16.3.130",
			Port:     3389,
			CheckID:  "bluekeep-cve-2019-0708",
			Title:    "BlueKeep Vulnerability",
			Severity: model.SeverityCritical,
			Status:   model.FindingVulnerable,
		},
	}

	g := BuildBlastRadius("production", hosts, creds, findings)
	if len(g.Nodes) < 4 { // 2 hosts + 1 cred + 1 vuln
		t.Fatalf("expected at least 4 nodes, got %d", len(g.Nodes))
	}
	if g.TotalPivots < 2 {
		t.Fatalf("expected at least 2 edges/pivots, got %d", g.TotalPivots)
	}

	foundCred := false
	foundVuln := false
	for _, n := range g.Nodes {
		if n.Type == BlastNodeCredential && n.Label == `CORP\cmk` {
			foundCred = true
		}
		if n.Type == BlastNodeVuln && n.ID == "vuln:bluekeep-cve-2019-0708" {
			foundVuln = true
		}
	}
	if !foundCred {
		t.Error("credential node CORP\\cmk not found in blast radius")
	}
	if !foundVuln {
		t.Error("vuln node bluekeep not found in blast radius")
	}
}
