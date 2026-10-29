// Package estate builds a compact attack-surface graph for the portal.
package estate

import (
	"rdpshot/internal/model"
	"rdpshot/internal/score"
)

// Node is one host in the estate graph.
type Node struct {
	ID          string  `json:"id"`
	Address     string  `json:"address"`
	Port        uint16  `json:"port"`
	Open        bool    `json:"open"`
	RiskScore   float64 `json:"risk_score"`
	Hardening   int     `json:"hardening_score"`
	Grade       string  `json:"grade"`
	NLARequired bool    `json:"nla_required"`
	TLSVersion  string  `json:"tls_version,omitempty"`
	Findings    int     `json:"findings"`
	MaxSeverity string  `json:"max_severity,omitempty"`
}

// Edge links a host to a finding check.
type Edge struct {
	From     string `json:"from"`
	To       string `json:"to"`
	CheckID  string `json:"check_id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
}

// Graph is the estate map payload.
type Graph struct {
	Engagement string `json:"engagement,omitempty"`
	Nodes      []Node `json:"nodes"`
	Edges      []Edge `json:"edges"`
}

// Build constructs a graph from hosts and findings of one or more scans.
func Build(engagement string, hosts []model.Host, findings []model.Finding) Graph {
	g := Graph{Engagement: engagement}
	findingByHost := map[string][]model.Finding{}
	for _, f := range findings {
		key := f.Address + ":" + portStr(f.Port)
		findingByHost[key] = append(findingByHost[key], f)
	}
	seen := map[string]bool{}
	for _, h := range hosts {
		key := h.Endpoint.Address + ":" + portStr(h.Endpoint.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		hs := score.EvaluateHost(h, findingByHost[key])
		maxSev := ""
		risk := 0.0
		for _, f := range findingByHost[key] {
			if f.Status != model.FindingVulnerable && f.Status != model.FindingPotential {
				continue
			}
			if model.Severity(maxSev).Rank() < f.Severity.Rank() {
				maxSev = string(f.Severity)
			}
			risk += float64(f.Severity.Rank())
			g.Edges = append(g.Edges, Edge{
				From: key, To: f.CheckID, CheckID: f.CheckID,
				Severity: string(f.Severity), Title: f.Title,
			})
		}
		nla, tls := false, ""
		if h.Service != nil {
			nla = h.Service.NLARequired
			tls = h.Service.TLSVersion
		}
		g.Nodes = append(g.Nodes, Node{
			ID: key, Address: h.Endpoint.Address, Port: h.Endpoint.Port,
			Open: h.State == "open", RiskScore: risk, Hardening: hs.Score,
			Grade: hs.Grade, NLARequired: nla, TLSVersion: tls,
			Findings: len(findingByHost[key]), MaxSeverity: maxSev,
		})
	}
	return g
}

func portStr(p uint16) string {
	const digits = "0123456789"
	if p == 0 {
		return "0"
	}
	var b [5]byte
	i := len(b)
	for p > 0 {
		i--
		b[i] = digits[p%10]
		p /= 10
	}
	return string(b[i:])
}
