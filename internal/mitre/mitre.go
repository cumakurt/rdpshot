// Package mitre maps rdpshot findings to MITRE ATT&CK techniques and returns
// a heatmap showing which techniques are detected, mitigated, or not applicable
// for the scanned environment.
package mitre

import "rdpshot/internal/model"

// TechniqueStatus describes the detection / mitigation state of one technique.
type TechniqueStatus string

const (
	StatusDetected      TechniqueStatus = "detected"      // evidence found in findings/creds
	StatusMitigated     TechniqueStatus = "mitigated"     // positive control confirmed
	StatusPotential     TechniqueStatus = "potential"     // potential finding
	StatusNotApplicable TechniqueStatus = "not_applicable" // no relevant data
)

// Technique is one ATT&CK technique evaluated against scan data.
type Technique struct {
	ID          string          `json:"id"`           // e.g. "T1021.001"
	Name        string          `json:"name"`
	Tactic      string          `json:"tactic"`
	Description string          `json:"description"`
	Status      TechniqueStatus `json:"status"`
	Evidence    []string        `json:"evidence,omitempty"`   // check IDs or messages
	Mitigations []string        `json:"mitigations,omitempty"` // positive controls observed
}

// Heatmap is the full ATT&CK evaluation for a scan.
type Heatmap struct {
	ScanID     string      `json:"scan_id,omitempty"`
	Engagement string      `json:"engagement,omitempty"`
	Techniques []Technique `json:"techniques"`
	// Aggregated counters
	Detected    int `json:"detected"`
	Mitigated   int `json:"mitigated"`
	Potential   int `json:"potential"`
	NotApplicable int `json:"not_applicable"`
}

// catalog is the static list of RDP-relevant ATT&CK techniques with their
// check-ID mappings.
var catalog = []struct {
	id          string
	name        string
	tactic      string
	description string
	// checkIDs that — when vulnerable — indicate this technique is detected
	detectChecks []string
	// checkIDs that — when NOT vulnerable — contribute to mitigation
	mitigateChecks []string
}{
	{
		id:     "T1021.001",
		name:   "Remote Services: Remote Desktop Protocol",
		tactic: "Lateral Movement",
		description: "Adversaries may use Valid Accounts to log into a computer using Remote Desktop " +
			"Protocol (RDP). The adversary may then perform actions as the logged-on user.",
		detectChecks:   []string{"rdp-service-exposed", "nla-not-required", "rdp-security-without-tls"},
		mitigateChecks: []string{"mfa-enforced", "pam-proxy-detected"},
	},
	{
		id:     "T1110.003",
		name:   "Brute Force: Password Spraying",
		tactic: "Credential Access",
		description: "Adversaries may use a single or small list of commonly used passwords against " +
			"many different accounts to attempt to acquire valid account credentials.",
		detectChecks:   []string{"nla-not-required", "rdp-security-without-tls"},
		mitigateChecks: []string{"mfa-enforced"},
	},
	{
		id:     "T1078",
		name:   "Valid Accounts",
		tactic: "Defense Evasion / Persistence / Privilege Escalation / Initial Access",
		description: "Adversaries may obtain and abuse credentials of existing accounts to gain " +
			"Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
		detectChecks:   []string{}, // detected via verified credentials
		mitigateChecks: []string{"mfa-enforced", "pam-proxy-detected"},
	},
	{
		id:     "T1563.002",
		name:   "Remote Service Session Hijacking: RDP Hijacking",
		tactic: "Lateral Movement",
		description: "Adversaries may hijack a legitimate user's remote desktop session to move " +
			"laterally within an environment.",
		detectChecks:   []string{"rdp-shadow-unprompted-exposed"},
		mitigateChecks: []string{"nla-smartcard-required"},
	},
	{
		id:     "T1046",
		name:   "Network Service Discovery",
		tactic: "Discovery",
		description: "Adversaries may attempt to get a listing of services running on remote hosts " +
			"and local network infrastructure components.",
		detectChecks:   []string{"rdp-service-exposed", "rd-web-exposed", "rd-gateway-exposed", "udp-3389-open"},
		mitigateChecks: []string{},
	},
	{
		id:     "T1557",
		name:   "Adversary-in-the-Middle",
		tactic: "Credential Access / Collection",
		description: "Adversaries may attempt to position themselves between two or more networked " +
			"devices using an Adversary-in-the-Middle (AiTM) technique.",
		detectChecks:   []string{"rdp-nla-downgrade-vulnerable", "weak-tls", "tls-legacy-1.0-1.1", "tls-weak-cipher"},
		mitigateChecks: []string{"nla-kerberos-offered"},
	},
	{
		id:     "T1040",
		name:   "Network Sniffing",
		tactic: "Credential Access / Discovery",
		description: "Adversaries may sniff network traffic to capture information about an " +
			"environment, including authentication material passed over the network.",
		detectChecks:   []string{"rdp-security-without-tls", "weak-encryption", "tls-weak-cipher", "tls-legacy-1.0-1.1"},
		mitigateChecks: []string{},
	},
	{
		id:     "T1190",
		name:   "Exploit Public-Facing Application",
		tactic: "Initial Access",
		description: "Adversaries may attempt to take advantage of a weakness in an Internet-facing " +
			"computer or program using software, data, or commands.",
		detectChecks:   []string{"bluekeep-cve-2019-0708"},
		mitigateChecks: []string{},
	},
}

// BuildHeatmap evaluates ATT&CK coverage for a set of hosts, findings, and credentials.
func BuildHeatmap(scanID, engagement string, hosts []model.Host, findings []model.Finding, creds []model.Credential) Heatmap {
	// Index active findings by check ID.
	vulnerable := map[string]bool{}
	potential := map[string]bool{}
	notVulnerable := map[string]bool{}
	for _, f := range findings {
		switch f.Status {
		case model.FindingVulnerable:
			vulnerable[f.CheckID] = true
		case model.FindingPotential:
			potential[f.CheckID] = true
		case model.FindingNotVulnerable:
			notVulnerable[f.CheckID] = true
		}
	}

	// MFA and PAM positive controls (special finding check IDs).
	mfaEnforced := notVulnerable["mfa-enforced"] || anyHostHas(hosts, func(h model.Host) bool {
		return h.Service != nil && h.Service.MFAEnforced
	})
	pamProxy := notVulnerable["pam-proxy-detected"] || anyHostHas(hosts, func(h model.Host) bool {
		return h.Service != nil && h.Service.PAMProxy
	})
	_ = pamProxy

	hasVerifiedCreds := len(creds) > 0

	hm := Heatmap{ScanID: scanID, Engagement: engagement}

	for _, cat := range catalog {
		tech := Technique{
			ID:          cat.id,
			Name:        cat.name,
			Tactic:      cat.tactic,
			Description: cat.description,
		}

		// Special case: T1078 is detected if there are verified credentials.
		if cat.id == "T1078" && hasVerifiedCreds {
			tech.Status = StatusDetected
			tech.Evidence = append(tech.Evidence, "verified credentials found in scan")
		}

		// Check detection evidence.
		for _, cid := range cat.detectChecks {
			if vulnerable[cid] {
				tech.Status = StatusDetected
				tech.Evidence = append(tech.Evidence, cid)
			} else if potential[cid] && tech.Status != StatusDetected {
				tech.Status = StatusPotential
				tech.Evidence = append(tech.Evidence, cid+" (potential)")
			}
		}

		// Check mitigations (only meaningful if not already detected).
		mitigated := false
		for _, cid := range cat.mitigateChecks {
			switch cid {
			case "mfa-enforced":
				if mfaEnforced {
					tech.Mitigations = append(tech.Mitigations, "MFA enforced")
					mitigated = true
				}
			case "pam-proxy-detected":
				if pamProxy {
					tech.Mitigations = append(tech.Mitigations, "PAM/jump-server proxy detected")
					mitigated = true
				}
			default:
				if notVulnerable[cid] {
					tech.Mitigations = append(tech.Mitigations, cid)
					mitigated = true
				}
			}
		}

		if tech.Status == "" {
			if mitigated {
				tech.Status = StatusMitigated
			} else if len(cat.detectChecks) == 0 && !hasVerifiedCreds {
				tech.Status = StatusNotApplicable
			} else {
				tech.Status = StatusNotApplicable
			}
		}

		// Count aggregates.
		switch tech.Status {
		case StatusDetected:
			hm.Detected++
		case StatusMitigated:
			hm.Mitigated++
		case StatusPotential:
			hm.Potential++
		default:
			hm.NotApplicable++
		}

		hm.Techniques = append(hm.Techniques, tech)
	}

	return hm
}

func anyHostHas(hosts []model.Host, fn func(model.Host) bool) bool {
	for _, h := range hosts {
		if fn(h) {
			return true
		}
	}
	return false
}
