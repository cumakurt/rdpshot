// Package policy evaluates scan results against a declarative hardening policy.
package policy

import (
	"fmt"
	"strings"

	"rdpshot/internal/model"
	"rdpshot/internal/score"
)

// Document is the operator-defined pass/fail policy.
type Document struct {
	FailOnSeverities []string `json:"fail_on"`
	Require          []string `json:"require"` // nla, tls12, trusted_cert, strong_crypto, no_critical
	MaxOpenTriage    *int     `json:"max_open_triage"`
	MinScore         *int     `json:"min_score"`
}

// Result is the evaluation outcome.
type Result struct {
	Passed   bool     `json:"passed"`
	Failures []string `json:"failures,omitempty"`
	Score    int      `json:"score"`
	Grade    string   `json:"grade"`
}

// Default returns a sensible audit gate.
func Default() Document {
	maxOpen := 0
	minScore := 70
	return Document{
		FailOnSeverities: []string{"critical"},
		Require:          []string{"nla", "tls12", "no_critical"},
		MaxOpenTriage:    &maxOpen,
		MinScore:         &minScore,
	}
}

// Evaluate checks a scan against the policy document.
func Evaluate(doc Document, hosts []model.Host, findings []model.Finding) Result {
	sc := score.EvaluateScan("", hosts, findings)
	res := Result{Passed: true, Score: sc.Score, Grade: sc.Grade}

	sevSet := map[string]bool{}
	for _, s := range doc.FailOnSeverities {
		sevSet[strings.ToLower(strings.TrimSpace(s))] = true
	}
	for _, f := range findings {
		if f.Status != model.FindingVulnerable {
			continue
		}
		if sevSet[string(f.Severity)] {
			res.Passed = false
			res.Failures = append(res.Failures,
				fmt.Sprintf("fail_on %s: %s on %s:%d", f.Severity, f.CheckID, f.Address, f.Port))
		}
	}

	summary := map[string]bool{}
	for _, r := range sc.Summary {
		summary[r.ID] = r.Passed
	}
	// Also derive from hosts if summary empty (no open hosts).
	if len(sc.Summary) == 0 && len(sc.Hosts) > 0 {
		for _, h := range sc.Hosts {
			for _, r := range h.Rules {
				if !r.Passed {
					summary[r.ID] = false
				} else if _, ok := summary[r.ID]; !ok {
					summary[r.ID] = true
				}
			}
		}
	}
	for _, req := range doc.Require {
		req = strings.TrimSpace(req)
		if req == "" {
			continue
		}
		passed, present := summary[req]
		if !present || !passed {
			res.Passed = false
			res.Failures = append(res.Failures, "require "+req+" failed")
		}
	}

	if doc.MaxOpenTriage != nil {
		open := 0
		for _, f := range findings {
			if f.TriageStatus == "" || f.TriageStatus == model.TriageOpen {
				if f.Status == model.FindingVulnerable || f.Status == model.FindingPotential {
					open++
				}
			}
		}
		if open > *doc.MaxOpenTriage {
			res.Passed = false
			res.Failures = append(res.Failures,
				fmt.Sprintf("open triage findings %d > max %d", open, *doc.MaxOpenTriage))
		}
	}
	if doc.MinScore != nil && sc.Score < *doc.MinScore {
		res.Passed = false
		res.Failures = append(res.Failures,
			fmt.Sprintf("hardening score %d < min %d", sc.Score, *doc.MinScore))
	}
	return res
}
