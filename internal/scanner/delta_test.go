package scanner

import (
	"testing"

	"rdpshot/internal/model"
)

func TestFilterDeltaEndpoints(t *testing.T) {
	all := []model.Endpoint{
		{Address: "10.0.0.1", Port: 3389},
		{Address: "10.0.0.2", Port: 3389},
		{Address: "10.0.0.3", Port: 3389},
	}
	baseHosts := []model.Host{
		{Endpoint: all[0], State: "open"},
		{Endpoint: all[1], State: "closed"},
	}
	baseFindings := []model.Finding{
		{Address: "10.0.0.1", Port: 3389, Status: model.FindingVulnerable, TriageStatus: model.TriageOpen},
	}
	got := FilterDeltaEndpoints(all, baseHosts, baseFindings)
	if len(got) != 3 {
		// .1 open triage, .2 previously closed, .3 new
		t.Fatalf("len=%d want 3 (%+v)", len(got), got)
	}
}

func TestPrioritizeEndpoints(t *testing.T) {
	eps := []model.Endpoint{
		{Address: "10.0.0.1", Port: 3389},
		{Address: "10.0.0.2", Port: 3389},
	}
	hosts := []model.Host{
		{Endpoint: eps[0], State: "open", Service: &model.ServiceInfo{NLARequired: true}},
		{Endpoint: eps[1], State: "open", Service: &model.ServiceInfo{NLARequired: false}},
	}
	PrioritizeEndpoints(eps, hosts, nil)
	if eps[0].Address != "10.0.0.2" {
		t.Fatalf("expected NLA-off host first, got %s", eps[0].Address)
	}
}
