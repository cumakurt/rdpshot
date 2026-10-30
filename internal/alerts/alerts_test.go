package alerts

import (
	"testing"

	"rdpshot/internal/model"
)

func TestEvaluateSLARules(t *testing.T) {
	rules := model.AlertRules{
		Enabled:              true,
		WebhookURL:           "https://hooks.example/x",
		OnHigh:               true,
		MinHardeningScore:    80,
		OnOpenTriageCritical: true,
	}
	in := Input{
		Scan: model.Scan{ID: "s1", Name: "demo", Status: model.ScanCompleted},
		Summary: model.Summary{BySeverity: []model.SeverityCount{
			{Severity: model.SeverityHigh, Count: 2},
		}},
		HardeningScore: 55,
		Findings: []model.Finding{
			{
				Severity: model.SeverityCritical, Status: model.FindingVulnerable,
				TriageStatus: model.TriageOpen,
			},
		},
	}
	got := Evaluate(rules, in)
	want := map[string]bool{
		"alert.high":                 false,
		"alert.hardening_sla":        false,
		"alert.open_triage_critical": false,
	}
	for _, p := range got {
		want[p.Event] = true
	}
	for event, ok := range want {
		if !ok {
			t.Fatalf("missing event %s in %#v", event, got)
		}
	}
}

func TestEvaluateDisabled(t *testing.T) {
	got := Evaluate(model.AlertRules{OnCritical: true}, Input{
		Summary: model.Summary{BySeverity: []model.SeverityCount{
			{Severity: model.SeverityCritical, Count: 1},
		}},
	})
	if got != nil {
		t.Fatalf("got %#v", got)
	}
}

func TestEvaluateNLARegression(t *testing.T) {
	rules := model.AlertRules{Enabled: true, WebhookURL: "https://hooks.example/x", OnNLARegressed: true}
	prior := []model.Host{{
		Endpoint: model.Endpoint{Address: "10.0.0.1", Port: 3389},
		State: "open", Service: &model.ServiceInfo{NLARequired: true},
	}}
	current := []model.Host{{
		Endpoint: model.Endpoint{Address: "10.0.0.1", Port: 3389},
		State: "open", Service: &model.ServiceInfo{NLARequired: false},
	}}
	got := Evaluate(rules, Input{Scan: model.Scan{ID: "s"}, Hosts: current, PriorHosts: prior})
	if len(got) != 1 || got[0].Event != "alert.nla_regressed" {
		t.Fatalf("got %#v", got)
	}
}
