// Package score computes RDP hardening / compliance scores from scan results.
package score

import (
	"strings"

	"rdpshot/internal/model"
)

// RuleResult is one hardening control evaluation.
type RuleResult struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Passed bool   `json:"passed"`
	Weight int    `json:"weight"`
	Detail string `json:"detail,omitempty"`
}

// HostScore is the hardening posture of one open endpoint.
type HostScore struct {
	Address string       `json:"address"`
	Port    uint16       `json:"port"`
	Score   int          `json:"score"`
	Grade   string       `json:"grade"`
	Rules   []RuleResult `json:"rules"`
}

// ScanScore aggregates host hardening scores for one scan.
type ScanScore struct {
	ScanID      string       `json:"scan_id"`
	Score       int          `json:"score"`
	Grade       string       `json:"grade"`
	HostsScored int          `json:"hosts_scored"`
	Hosts       []HostScore  `json:"hosts"`
	Summary     []RuleResult `json:"summary"`
}

// EvaluateScan scores every open host in the scan.
func EvaluateScan(scanID string, hosts []model.Host, findings []model.Finding) ScanScore {
	byHost := map[string][]model.Finding{}
	for _, f := range findings {
		key := endpointKey(f.Address, f.Port)
		byHost[key] = append(byHost[key], f)
	}
	out := ScanScore{ScanID: scanID}
	var total int
	agg := map[string]*RuleResult{}
	for _, h := range hosts {
		if h.State != "open" {
			continue
		}
		hs := EvaluateHost(h, byHost[endpointKey(h.Endpoint.Address, h.Endpoint.Port)])
		out.Hosts = append(out.Hosts, hs)
		total += hs.Score
		out.HostsScored++
		for _, r := range hs.Rules {
			cur := agg[r.ID]
			if cur == nil {
				cp := r
				cp.Passed = r.Passed
				agg[r.ID] = &cp
				continue
			}
			if !r.Passed {
				cur.Passed = false
			}
		}
	}
	if out.HostsScored > 0 {
		out.Score = total / out.HostsScored
	} else {
		out.Score = 100
	}
	out.Grade = grade(out.Score)
	for _, id := range []string{"nla", "tls12", "trusted_cert", "strong_crypto", "no_critical", "not_legacy"} {
		if r := agg[id]; r != nil {
			out.Summary = append(out.Summary, *r)
		}
	}
	return out
}

// EvaluateHost scores one host.
func EvaluateHost(h model.Host, findings []model.Finding) HostScore {
	rules := []RuleResult{
		ruleNLA(h),
		ruleTLS(h),
		ruleCert(h),
		ruleCrypto(h),
		ruleNoCritical(findings),
		ruleNotLegacy(h, findings),
	}
	earned, weight := 0, 0
	for _, r := range rules {
		weight += r.Weight
		if r.Passed {
			earned += r.Weight
		}
	}
	score := 100
	if weight > 0 {
		score = (earned * 100) / weight
	}
	return HostScore{
		Address: h.Endpoint.Address,
		Port:    h.Endpoint.Port,
		Score:   score,
		Grade:   grade(score),
		Rules:   rules,
	}
}

func ruleNLA(h model.Host) RuleResult {
	r := RuleResult{ID: "nla", Title: "NLA / CredSSP required", Weight: 25}
	if h.Service != nil && h.Service.NLARequired {
		r.Passed = true
		r.Detail = "server requires NLA"
		return r
	}
	r.Detail = "NLA is not enforced"
	return r
}

func ruleTLS(h model.Host) RuleResult {
	r := RuleResult{ID: "tls12", Title: "TLS 1.2 or newer", Weight: 20}
	if h.Service == nil || h.Service.TLSVersion == "" {
		r.Detail = "TLS version not observed"
		return r
	}
	for _, v := range h.Service.SupportedTLSVersions {
		if v == "TLS 1.0" || v == "TLS 1.1" || v == "SSL 3.0" {
			r.Passed = false
			r.Detail = "accepts obsolete " + v
			return r
		}
	}
	v := h.Service.TLSVersion
	if v == "TLS 1.2" || v == "TLS 1.3" {
		r.Passed = true
		r.Detail = "negotiated " + v
		return r
	}
	r.Detail = "negotiated " + v
	return r
}

func ruleCert(h model.Host) RuleResult {
	r := RuleResult{ID: "trusted_cert", Title: "Trusted (non self-signed) certificate", Weight: 15}
	if h.Service == nil || h.Service.Certificate == nil {
		r.Detail = "no certificate captured"
		return r
	}
	if !h.Service.Certificate.SelfSigned {
		r.Passed = true
		r.Detail = "certificate is not self-signed"
		return r
	}
	r.Detail = "self-signed certificate"
	return r
}

func ruleCrypto(h model.Host) RuleResult {
	r := RuleResult{ID: "strong_crypto", Title: "Strong encryption / cipher", Weight: 15}
	if h.Service == nil {
		r.Detail = "no service fingerprint"
		return r
	}
	level := strings.ToLower(h.Service.EncryptionLevel)
	suite := strings.ToUpper(h.Service.TLSCipherSuite)
	weakSuite := strings.Contains(suite, "RC4") || strings.Contains(suite, "3DES") || strings.Contains(suite, "_NULL_")
	if len(h.Service.WeakCiphers) > 0 {
		weakSuite = true
	}
	if level == "none" || level == "low" || weakSuite {
		r.Detail = "weak encryption posture"
		return r
	}
	r.Passed = true
	r.Detail = "no weak encryption markers"
	return r
}

func ruleNoCritical(findings []model.Finding) RuleResult {
	r := RuleResult{ID: "no_critical", Title: "No critical vulnerable findings", Weight: 15}
	for _, f := range findings {
		if f.Severity == model.SeverityCritical && f.Status == model.FindingVulnerable {
			r.Detail = f.CheckID
			return r
		}
	}
	r.Passed = true
	r.Detail = "no confirmed critical findings"
	return r
}

func ruleNotLegacy(h model.Host, findings []model.Finding) RuleResult {
	r := RuleResult{ID: "not_legacy", Title: "Not a legacy RDP build / stack", Weight: 10}
	for _, f := range findings {
		if f.CheckID == "legacy-rdp-build" && (f.Status == model.FindingVulnerable || f.Status == model.FindingPotential) {
			r.Detail = f.Evidence
			return r
		}
	}
	if h.Service != nil && h.Service.ServerVersion != 0 && h.Service.ServerVersion < 0x00080000 {
		r.Detail = "legacy MCS server version"
		return r
	}
	r.Passed = true
	r.Detail = "no legacy stack markers"
	return r
}

func grade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

func endpointKey(addr string, port uint16) string {
	return addr + ":" + itoa(port)
}

func itoa(v uint16) string {
	if v == 0 {
		return "0"
	}
	var buf [5]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

// StandardPosture holds posture score and check summary for one regulatory benchmark.
type StandardPosture struct {
	Standard       string   `json:"standard"` // "CIS", "PCI-DSS", "NIST", "ISO-27001"
	Score          int      `json:"score"`
	Grade          string   `json:"grade"`
	TotalChecks    int      `json:"total_checks"`
	PassedChecks   int      `json:"passed_checks"`
	FailedChecks   int      `json:"failed_checks"`
	FailedCheckIDs []string `json:"failed_check_ids,omitempty"`
}

// CompliancePosture aggregates scores across standards for radar visualization.
type CompliancePosture struct {
	ScanID       string            `json:"scan_id"`
	OverallScore int               `json:"overall_score"`
	Grade        string            `json:"grade"`
	Standards    []StandardPosture `json:"standards"`
}

type benchmarkRule struct {
	checkID string
	aliases []string
	weight  int
}

// EvaluateCompliancePosture computes compliance percentages for CIS, PCI-DSS, NIST, and ISO-27001.
func EvaluateCompliancePosture(scanID string, hosts []model.Host, findings []model.Finding) CompliancePosture {
	benchmarks := []struct {
		standard string
		rules    []benchmarkRule
	}{
		{
			standard: "CIS",
			rules: []benchmarkRule{
				{checkID: "nla-not-required", aliases: []string{"rdp-nla-downgrade-vulnerable"}, weight: 25},
				{checkID: "rdp-security-without-tls", aliases: []string{"rdp-service-exposed"}, weight: 20},
				{checkID: "weak-tls", aliases: []string{"tls-legacy-version", "tls-legacy-1.0-1.1"}, weight: 15},
				{checkID: "weak-encryption", aliases: []string{"tls-weak-cipher"}, weight: 15},
				{checkID: "self-signed-cert", aliases: []string{"expired-cert", "cert-hostname-mismatch"}, weight: 15},
				{checkID: "rdp-shadow-unprompted-exposed", aliases: nil, weight: 10},
			},
		},
		{
			standard: "PCI-DSS",
			rules: []benchmarkRule{
				{checkID: "nla-not-required", aliases: []string{"rdp-nla-downgrade-vulnerable"}, weight: 30},
				{checkID: "bluekeep-cve-2019-0708", aliases: nil, weight: 30},
				{checkID: "weak-tls", aliases: []string{"tls-legacy-version", "tls-legacy-1.0-1.1"}, weight: 20},
				{checkID: "weak-encryption", aliases: []string{"tls-weak-cipher"}, weight: 10},
				{checkID: "self-signed-cert", aliases: []string{"expired-cert"}, weight: 10},
			},
		},
		{
			standard: "NIST",
			rules: []benchmarkRule{
				{checkID: "nla-not-required", aliases: []string{"rdp-nla-downgrade-vulnerable"}, weight: 25},
				{checkID: "bluekeep-cve-2019-0708", aliases: nil, weight: 25},
				{checkID: "rdp-security-without-tls", aliases: []string{"weak-tls"}, weight: 20},
				{checkID: "rdp-shadow-unprompted-exposed", aliases: nil, weight: 15},
				{checkID: "udp-3389-open", aliases: nil, weight: 15},
			},
		},
		{
			standard: "ISO-27001",
			rules: []benchmarkRule{
				{checkID: "nla-not-required", aliases: []string{"rdp-nla-downgrade-vulnerable"}, weight: 25},
				{checkID: "bluekeep-cve-2019-0708", aliases: nil, weight: 25},
				{checkID: "weak-tls", aliases: []string{"weak-encryption", "tls-weak-cipher"}, weight: 25},
				{checkID: "rdp-security-without-tls", aliases: []string{"self-signed-cert"}, weight: 25},
			},
		},
	}

	activeFindings := map[string]bool{}
	for _, f := range findings {
		if f.Status == model.FindingVulnerable || f.Status == model.FindingPotential {
			activeFindings[f.CheckID] = true
		}
	}

	// Host-level inspections
	hasOpenHost := false
	for _, h := range hosts {
		if h.State == "open" {
			hasOpenHost = true
			if h.Service != nil && !h.Service.NLARequired {
				activeFindings["nla-not-required"] = true
			}
		}
	}

	out := CompliancePosture{
		ScanID:    scanID,
		Standards: make([]StandardPosture, 0, len(benchmarks)),
	}

	totalScore := 0
	for _, b := range benchmarks {
		sp := StandardPosture{
			Standard:    b.standard,
			TotalChecks: len(b.rules),
		}
		earnedWeight := 0
		totalWeight := 0
		for _, r := range b.rules {
			totalWeight += r.weight
			failed := activeFindings[r.checkID]
			if !failed {
				for _, alias := range r.aliases {
					if activeFindings[alias] {
						failed = true
						break
					}
				}
			}
			if failed {
				sp.FailedChecks++
				sp.FailedCheckIDs = append(sp.FailedCheckIDs, r.checkID)
			} else {
				sp.PassedChecks++
				earnedWeight += r.weight
			}
		}

		if totalWeight > 0 {
			sp.Score = (earnedWeight * 100) / totalWeight
		} else {
			sp.Score = 100
		}
		if !hasOpenHost && len(findings) == 0 {
			sp.Score = 100
		}
		sp.Grade = grade(sp.Score)
		totalScore += sp.Score
		out.Standards = append(out.Standards, sp)
	}

	if len(out.Standards) > 0 {
		out.OverallScore = totalScore / len(out.Standards)
	} else {
		out.OverallScore = 100
	}
	out.Grade = grade(out.OverallScore)
	return out
}
