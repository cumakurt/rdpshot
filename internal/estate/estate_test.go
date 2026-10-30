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
