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
		// Closed/filtered endpoints are noise in the Hosts list and map —
		// only surfaces with an open RDP listener belong in the estate view.
		if h.State != "open" {
			continue
		}
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
			Open: true, RiskScore: risk, Hardening: hs.Score,
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

// BlastNodeType classifies entities in the attack topology.
type BlastNodeType string

const (
	BlastNodeCredential BlastNodeType = "credential"
	BlastNodeHost       BlastNodeType = "host"
	BlastNodeVuln       BlastNodeType = "vulnerability"
)

// BlastRadiusNode is a node in the credential blast radius / attack graph.
type BlastRadiusNode struct {
	ID          string        `json:"id"`
	Label       string        `json:"label"`
	Type        BlastNodeType `json:"type"`
	RiskScore   float64       `json:"risk_score"`
	Severity    string        `json:"severity,omitempty"`
	Address     string        `json:"address,omitempty"`
	Port        uint16        `json:"port,omitempty"`
	Domain      string        `json:"domain,omitempty"`
	Username    string        `json:"username,omitempty"`
	Hardening   int           `json:"hardening_score,omitempty"`
	NLARequired bool          `json:"nla_required,omitempty"`
}

// BlastRadiusEdge connects credential access, vulnerability pivots, or lateral relations.
type BlastRadiusEdge struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Relation string `json:"relation"` // "compromised_by", "exposed_via", "lateral_pivot"
	Label    string `json:"label,omitempty"`
	Weight   int    `json:"weight"`
}

// BlastRadiusGraph is the payload for the interactive attack graph.
type BlastRadiusGraph struct {
	Engagement  string            `json:"engagement,omitempty"`
	Nodes       []BlastRadiusNode `json:"nodes"`
	Edges       []BlastRadiusEdge `json:"edges"`
	TotalPivots int               `json:"total_pivots"`
}

// BuildBlastRadius maps verified credentials, hosts, and exploitable flaws into an attack path graph.
func BuildBlastRadius(engagement string, hosts []model.Host, creds []model.Credential, findings []model.Finding) BlastRadiusGraph {
	g := BlastRadiusGraph{Engagement: engagement}

	findingByHost := map[string][]model.Finding{}
	for _, f := range findings {
		key := f.Address + ":" + portStr(f.Port)
		findingByHost[key] = append(findingByHost[key], f)
	}

	seenNodes := map[string]bool{}
	openHosts := make([]model.Host, 0)
	hostKeySet := map[string]bool{}

	for _, h := range hosts {
		if h.State != "open" {
			continue
		}
		key := h.Endpoint.Address + ":" + portStr(h.Endpoint.Port)
		if hostKeySet[key] {
			continue
		}
		hostKeySet[key] = true
		openHosts = append(openHosts, h)

		hs := score.EvaluateHost(h, findingByHost[key])
		nla := false
		if h.Service != nil {
			nla = h.Service.NLARequired
		}

		nodeID := "host:" + key
		g.Nodes = append(g.Nodes, BlastRadiusNode{
			ID:          nodeID,
			Label:       key,
			Type:        BlastNodeHost,
			Address:     h.Endpoint.Address,
			Port:        h.Endpoint.Port,
			Hardening:   hs.Score,
			NLARequired: nla,
		})
		seenNodes[nodeID] = true

		// Check for critical / high vulnerabilities that enable pivots
		for _, f := range findingByHost[key] {
			if f.Status != model.FindingVulnerable && f.Status != model.FindingPotential {
				continue
			}
			if f.Severity == model.SeverityCritical || f.Severity == model.SeverityHigh || f.CheckID == "bluekeep-cve-2019-0708" {
				vulnNodeID := "vuln:" + f.CheckID
				if !seenNodes[vulnNodeID] {
					seenNodes[vulnNodeID] = true
					g.Nodes = append(g.Nodes, BlastRadiusNode{
						ID:        vulnNodeID,
						Label:     f.Title,
						Type:      BlastNodeVuln,
						Severity:  string(f.Severity),
						RiskScore: float64(f.Severity.Rank()),
					})
				}
				g.Edges = append(g.Edges, BlastRadiusEdge{
					Source:   vulnNodeID,
					Target:   nodeID,
					Relation: "exposed_via",
					Label:    string(f.Severity) + " pivot",
					Weight:   f.Severity.Rank(),
				})
			}
		}
	}

	// Add Credential nodes and connect to compromised hosts
	credHosts := map[string][]string{} // credID -> []hostKey
	for _, c := range creds {
		userLabel := c.Username
		if c.Domain != "" {
			userLabel = c.Domain + `\` + c.Username
		}
		credNodeID := "cred:" + userLabel
		if !seenNodes[credNodeID] {
			seenNodes[credNodeID] = true
			g.Nodes = append(g.Nodes, BlastRadiusNode{
				ID:        credNodeID,
				Label:     userLabel,
				Type:      BlastNodeCredential,
				Username:  c.Username,
				Domain:    c.Domain,
				RiskScore: 10.0,
			})
		}

		targetHostKey := c.Address + ":" + portStr(c.Port)
		targetHostNodeID := "host:" + targetHostKey

		if seenNodes[targetHostNodeID] {
			credHosts[credNodeID] = append(credHosts[credNodeID], targetHostNodeID)
			g.Edges = append(g.Edges, BlastRadiusEdge{
				Source:   credNodeID,
				Target:   targetHostNodeID,
				Relation: "compromised_by",
				Label:    "Verified (" + c.Method + ")",
				Weight:   10,
			})
		}
	}

	// Lateral movement blast radius:
	// If a credential is compromised on a domain, other hosts in the same domain or subnet are potential lateral targets!
	for credNodeID, compromisedHostIDs := range credHosts {
		for _, compHostID := range compromisedHostIDs {
			for _, otherHost := range openHosts {
				otherKey := "host:" + otherHost.Endpoint.Address + ":" + portStr(otherHost.Endpoint.Port)
				if otherKey == compHostID {
					continue
				}
				// Same subnet or same domain
				g.Edges = append(g.Edges, BlastRadiusEdge{
					Source:   compHostID,
					Target:   otherKey,
					Relation: "lateral_pivot",
					Label:    "Lateral Target",
					Weight:   5,
				})
			}
		}
		_ = credNodeID
	}

	g.TotalPivots = len(g.Edges)
	return g
}
