// Package vuln evaluates reconnaissance results against the RDP vulnerability
// and misconfiguration catalog.
//
// Policy: only emit findings that are positively observed (vulnerable) or
// positively ruled out (not_vulnerable). Speculative "potential"/"inconclusive"
// outcomes are omitted so reports do not raise false-positive critical noise
// (for example BlueKeep-on-NLA without a confirmed MS_T120 trigger).
package vuln

import (
	"fmt"
	"net"
	"strings"
	"time"

	"rdpshot/internal/model"
	"rdpshot/internal/rdp"
)

// Input is everything the checks need about one endpoint.
type Input struct {
	// Service is the fingerprint gathered by the reconnaissance probe.
	Service *model.ServiceInfo
	// BlueKeep is the outcome of the safe CVE-2019-0708 detection probe and
	// may be nil when the probe was not requested or not possible.
	BlueKeep *rdp.BlueKeepResult
	// TargetHost is the address/hostname used for the scan (for SAN matching).
	TargetHost string
}

type check struct {
	id          string
	title       string
	severity    model.Severity
	cve         string
	cvss        float64
	remediation string
	// evaluate returns the finding status and evidence. An empty status skips
	// the finding entirely (used when a condition is clearly not present or
	// cannot be proven remotely).
	evaluate func(in Input) (model.FindingStatus, string)
}

// catalog returns the ordered check definitions.
func catalog() []check {
	return []check{
		{
			id:          "rdp-service-exposed",
			title:       "Remote Desktop service exposed",
			severity:    model.SeverityInfo,
			cvss:        0,
			remediation: "Expose RDP only through a VPN, RD Gateway or an allow-list; restrict network access to trusted sources.",
			evaluate: func(in Input) (model.FindingStatus, string) {
				return model.FindingVulnerable, "TCP port accepted an RDP connection"
			},
		},
		{
			id:          "nla-not-required",
			title:       "Network Level Authentication (NLA) is not enforced",
			severity:    model.SeverityHigh,
			cvss:        7.5,
			remediation: "Require NLA: set 'User Authentication must be required for remote connections' (fDenyTSConnections / RequireNLA policy).",
			evaluate: func(in Input) (model.FindingStatus, string) {
				if in.Service == nil {
					return "", ""
				}
				if in.Service.NLARequired {
					return model.FindingNotVulnerable, "server requires CredSSP/NLA before the session is established"
				}
				// Only assert missing NLA when negotiation clearly selected a
				// non-CredSSP path (standard RDP or TLS-only).
				switch in.Service.NegotiatedProtocol {
				case rdp.ProtocolRDP, rdp.ProtocolSSL:
					return model.FindingVulnerable,
						"negotiation selected " + rdp.ProtocolName(in.Service.NegotiatedProtocol) + " without NLA"
				default:
					return "", ""
				}
			},
		},
		{
			id:          "rdp-security-without-tls",
			title:       "Legacy RDP security layer negotiated without TLS",
			severity:    model.SeverityMedium,
			cvss:        5.3,
			remediation: "Configure the RDP listener to use TLS (Security Layer = Negotiate or SSL) and disable the legacy RDP security layer.",
			evaluate: func(in Input) (model.FindingStatus, string) {
				if in.Service == nil || in.Service.NegotiatedProtocol != rdp.ProtocolRDP {
					return "", ""
				}
				return model.FindingVulnerable,
					fmt.Sprintf("selected protocol is %s (encryption level: %s)",
						rdp.ProtocolName(in.Service.NegotiatedProtocol), in.Service.EncryptionLevel)
			},
		},
		{
			id:          "bluekeep-cve-2019-0708",
			title:       "BlueKeep pre-auth RCE in RDS (CVE-2019-0708)",
			severity:    model.SeverityCritical,
			cve:         "CVE-2019-0708",
			cvss:        9.8,
			remediation: "Apply the security update for CVE-2019-0708 or disable RDP on the host. Enabling NLA blocks pre-auth exploitation but does not fix the bug.",
			evaluate:    evaluateBlueKeep,
		},
		{
			id:          "weak-encryption",
			title:       "Weak or disabled RDP encryption",
			severity:    model.SeverityHigh,
			cvss:        7.5,
			remediation: "Set the RDP encryption level to 'High' or 'FIPS Compliant' and disable 40/56-bit RC4 methods.",
			evaluate: func(in Input) (model.FindingStatus, string) {
				if in.Service == nil {
					return "", ""
				}
				level := strings.ToLower(in.Service.EncryptionLevel)
				if level == "" {
					return "", ""
				}
				switch level {
				case "none", "low":
					return model.FindingVulnerable,
						fmt.Sprintf("encryption level is %q (methods 0x%08x)", in.Service.EncryptionLevel, in.Service.EncryptionMethods)
				case "client_compatible":
					// Only confirm when the advertised methods are exclusively
					// 40-bit and/or 56-bit RC4 (bits 0x1 and 0x8) with no 128-bit.
					methods := in.Service.EncryptionMethods
					legacyOnly := methods != 0 &&
						methods&^uint32(0x00000009) == 0 &&
						methods&0x00000002 == 0
					if legacyOnly {
						return model.FindingVulnerable,
							fmt.Sprintf("only legacy RC4 key lengths negotiated (methods 0x%08x)", methods)
					}
					// Ambiguous client-compatible profiles are not reported.
					return "", ""
				}
				return "", ""
			},
		},
		{
			id:          "weak-tls",
			title:       "Obsolete TLS version or weak cipher suite",
			severity:    model.SeverityMedium,
			cvss:        5.3,
			remediation: "Disable TLS 1.0/1.1 and SSL 3.0 on the RDP listener and remove RC4/3DES cipher suites.",
			evaluate:    evaluateWeakTLS,
		},
		{
			id:          "self-signed-cert",
			title:       "Self-signed certificate on the RDP listener",
			severity:    model.SeverityMedium,
			cvss:        4.3,
			remediation: "Deploy a certificate issued by a trusted CA (or an internal PKI) for the RDP listener so clients can authenticate the server.",
			evaluate: func(in Input) (model.FindingStatus, string) {
				if in.Service == nil {
					return "", ""
				}
				cert := in.Service.Certificate
				if cert == nil || !cert.SelfSigned {
					return "", ""
				}
				return model.FindingVulnerable,
					fmt.Sprintf("certificate subject %q is issued by itself (SHA-256 %s)", cert.Subject, cert.Fingerprint)
			},
		},
		{
			id:          "expired-cert",
			title:       "Expired certificate on the RDP listener",
			severity:    model.SeverityMedium,
			cvss:        4.3,
			remediation: "Replace the expired certificate on the RDP listener and automate renewal.",
			evaluate: func(in Input) (model.FindingStatus, string) {
				if in.Service == nil {
					return "", ""
				}
				cert := in.Service.Certificate
				if cert == nil || cert.NotAfter.IsZero() {
					return "", ""
				}
				now := time.Now()
				if now.After(cert.NotAfter) {
					return model.FindingVulnerable,
						fmt.Sprintf("certificate expired on %s (subject %q)", cert.NotAfter.Format(time.RFC3339), cert.Subject)
				}
				// Soon-to-expire is operational hygiene, not a confirmed vuln.
				return "", ""
			},
		},
		{
			id:          "rdp-negotiation-failure",
			title:       "RDP protocol negotiation failed",
			severity:    model.SeverityLow,
			cvss:        2.0,
			remediation: "Review RDP security layer policy and supported protocols so authorized clients can negotiate TLS/CredSSP.",
			evaluate: func(in Input) (model.FindingStatus, string) {
				if in.Service == nil || in.Service.NegotiationFailureCode == nil {
					return "", ""
				}
				return model.FindingVulnerable,
					fmt.Sprintf("server returned RDP_NEG_FAILURE code 0x%08x", *in.Service.NegotiationFailureCode)
			},
		},
		{
			id:          "cert-hostname-mismatch",
			title:       "RDP certificate does not match the scanned hostname",
			severity:    model.SeverityMedium,
			cvss:        5.3,
			remediation: "Issue a certificate whose CN/SAN matches the hostname clients use to connect, or connect only by the certified name.",
			evaluate:    evaluateCertHostname,
		},
		{
			id:          "rd-web-exposed",
			title:       "RD Web Access portal appears exposed",
			severity:    model.SeverityInfo,
			cvss:        0,
			remediation: "Restrict RD Web to VPN or trusted networks and enforce MFA.",
			evaluate: func(in Input) (model.FindingStatus, string) {
				if in.Service == nil || !in.Service.RDWeb || strings.TrimSpace(in.Service.RDWebURL) == "" {
					return "", ""
				}
				return model.FindingVulnerable, "RD Web markers observed at " + in.Service.RDWebURL
			},
		},
		{
			id:          "rd-gateway-exposed",
			title:       "RD Gateway endpoint appears exposed",
			severity:    model.SeverityInfo,
			cvss:        0,
			remediation: "Publish RD Gateway only through controlled ingress and require strong authentication.",
			evaluate: func(in Input) (model.FindingStatus, string) {
				if in.Service == nil || !in.Service.RDGateway {
					return "", ""
				}
				return model.FindingVulnerable, "RD Gateway HTTP/RPC path responded"
			},
		},
		{
			id:          "udp-3389-open",
			title:       "UDP/3389 appears reachable",
			severity:    model.SeverityLow,
			cvss:        3.1,
			remediation: "Disable UDP transport for RDP unless required, or restrict it to trusted networks.",
			evaluate: func(in Input) (model.FindingStatus, string) {
				if in.Service == nil || !in.Service.UDP3389 {
					return "", ""
				}
				// Only confirm when discovery recorded a positive UDP response.
				ev := ""
				if in.Service.Evidence != nil {
					ev = in.Service.Evidence["udp_3389"]
				}
				if !strings.Contains(strings.ToLower(ev), "responded") {
					return "", ""
				}
				return model.FindingVulnerable, ev
			},
		},
		{
			id:          "nla-smartcard-required",
			title:       "Smart-card logon indicated by NLA",
			severity:    model.SeverityInfo,
			cvss:        0,
			remediation: "Document smart-card requirements in the engagement ROE; password sprays will not succeed against these accounts.",
			evaluate: func(in Input) (model.FindingStatus, string) {
				if in.Service == nil || !in.Service.SmartCardRequired {
					return "", ""
				}
				// Capability note, not a vulnerability.
				return model.FindingNotVulnerable, "CredSSP/NLA reported smart-card logon requirement"
			},
		},
	}
}

func evaluateCertHostname(in Input) (model.FindingStatus, string) {
	if in.Service == nil || in.Service.Certificate == nil || in.TargetHost == "" {
		return "", ""
	}
	host := strings.TrimSpace(in.TargetHost)
	if parseIPLike(host) {
		// IP targets cannot be matched against DNS SANs with certainty.
		return "", ""
	}
	if len(in.Service.Certificate.DNSNames) == 0 {
		// Without SANs we cannot prove a hostname mismatch.
		return "", ""
	}
	host = strings.ToLower(host)
	for _, san := range in.Service.Certificate.DNSNames {
		if strings.EqualFold(san, host) || matchWildcard(san, host) {
			return model.FindingNotVulnerable, "certificate SAN matches " + host
		}
	}
	return model.FindingVulnerable, fmt.Sprintf("certificate SANs %v do not include scanned host %q", in.Service.Certificate.DNSNames, host)
}

func parseIPLike(host string) bool {
	return net.ParseIP(host) != nil
}

func matchWildcard(pattern, host string) bool {
	pattern = strings.ToLower(pattern)
	host = strings.ToLower(host)
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}
	suffix := pattern[1:] // .example.com
	if !strings.HasSuffix(host, suffix) {
		return false
	}
	prefix := host[:len(host)-len(suffix)]
	return prefix != "" && !strings.Contains(prefix, ".")
}

// evaluateBlueKeep reports only confirmed probe outcomes. NLA-blocked hosts
// (probe not run) are omitted: Critical "potential" findings without an
// MS_T120 Disconnect Provider Ultimatum are treated as false-positive noise.
func evaluateBlueKeep(in Input) (model.FindingStatus, string) {
	if in.BlueKeep == nil || !in.BlueKeep.Attempted {
		return "", ""
	}
	if in.BlueKeep.Triggered {
		if !blueKeepTriggerConfirmed(in.BlueKeep) {
			return "", ""
		}
		return model.FindingVulnerable,
			in.BlueKeep.Reason + " (" + in.BlueKeep.Evidence + ")"
	}
	return model.FindingNotVulnerable,
		in.BlueKeep.Reason + " (" + in.BlueKeep.Evidence + ")"
}

// blueKeepTriggerConfirmed requires the MCS Disconnect Provider Ultimatum
// signal that the safe MS_T120 probe looks for. Generic disconnects are not
// enough to claim CVE-2019-0708.
func blueKeepTriggerConfirmed(bk *rdp.BlueKeepResult) bool {
	if bk == nil || !bk.Triggered {
		return false
	}
	blob := strings.ToLower(bk.Reason + " " + bk.Evidence)
	return strings.Contains(blob, "disconnect provider")
}

func evaluateWeakTLS(in Input) (model.FindingStatus, string) {
	if in.Service == nil || in.Service.TLSVersion == "" {
		return "", ""
	}
	var issues []string
	switch in.Service.TLSVersion {
	case "SSL 3.0", "TLS 1.0", "TLS 1.1":
		issues = append(issues, "negotiated "+in.Service.TLSVersion)
	}
	suite := strings.ToUpper(in.Service.TLSCipherSuite)
	for _, weak := range []string{"RC4", "3DES", "_NULL_", "EXPORT", "_ANON_", "DES_"} {
		if strings.Contains(suite, weak) {
			issues = append(issues, "weak cipher suite "+in.Service.TLSCipherSuite)
			break
		}
	}
	if len(issues) == 0 {
		return "", ""
	}
	return model.FindingVulnerable, strings.Join(issues, "; ")
}

// Evaluate runs every applicable check against one endpoint and returns the
// findings. Conditions that are clearly absent are not reported. Speculative
// potential/inconclusive outcomes are filtered out so only confirmed
// vulnerable / not_vulnerable results reach the report.
func Evaluate(ep model.Endpoint, in Input) []model.Finding {
	var findings []model.Finding
	now := time.Now().UTC()
	for _, c := range catalog() {
		status, evidence := c.evaluate(in)
		if status == "" {
			continue
		}
		if status != model.FindingVulnerable && status != model.FindingNotVulnerable {
			continue
		}
		findings = append(findings, model.Finding{
			Address:     ep.Address,
			Port:        ep.Port,
			CheckID:     c.id,
			Title:       c.title,
			Severity:    c.severity,
			Status:      status,
			CVE:         c.cve,
			CVSS:        c.cvss,
			Evidence:    evidence,
			Remediation: c.remediation,
			DetectedAt:  now,
		})
	}
	return findings
}
