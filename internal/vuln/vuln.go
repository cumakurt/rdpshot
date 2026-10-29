// Package vuln evaluates reconnaissance results against the RDP vulnerability
// and misconfiguration catalog.
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
	// the finding entirely (used when a condition is clearly not present).
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
				if in.Service.NLARequired {
					return model.FindingNotVulnerable, "server requires CredSSP/NLA before the session is established"
				}
				return model.FindingVulnerable,
					"negotiation selected " + rdp.ProtocolName(in.Service.NegotiatedProtocol) + " without NLA"
			},
		},
		{
			id:          "rdp-security-without-tls",
			title:       "Legacy RDP security layer negotiated without TLS",
			severity:    model.SeverityMedium,
			cvss:        5.3,
			remediation: "Configure the RDP listener to use TLS (Security Layer = Negotiate or SSL) and disable the legacy RDP security layer.",
			evaluate: func(in Input) (model.FindingStatus, string) {
				if in.Service.NegotiatedProtocol != rdp.ProtocolRDP {
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
			id:          "dejablue-cve-2019-1181-1182",
			title:       "Possible DejaBlue RDS vulnerabilities (CVE-2019-1181/1182)",
			severity:    model.SeverityCritical,
			cve:         "CVE-2019-1182",
			cvss:        9.8,
			remediation: "Apply the August 2019 cumulative update (or later) and enforce NLA. Verify the patch state locally; remote detection is not conclusive.",
			evaluate: func(in Input) (model.FindingStatus, string) {
				if in.Service.NLARequired {
					return "", ""
				}
				return model.FindingPotential,
					"RDP is reachable without NLA; DejaBlue affects unpatched Windows 7/Server 2008 R2 through Server 2019 and cannot be confirmed remotely. Verify the patch level."
			},
		},
		{
			id:          "weak-encryption",
			title:       "Weak or disabled RDP encryption",
			severity:    model.SeverityHigh,
			cvss:        7.5,
			remediation: "Set the RDP encryption level to 'High' or 'FIPS Compliant' and disable 40/56-bit RC4 methods.",
			evaluate: func(in Input) (model.FindingStatus, string) {
				level := strings.ToLower(in.Service.EncryptionLevel)
				if level == "" {
					return "", ""
				}
				switch level {
				case "none", "low":
					return model.FindingVulnerable,
						fmt.Sprintf("encryption level is %q (methods 0x%08x)", in.Service.EncryptionLevel, in.Service.EncryptionMethods)
				case "client_compatible":
					if in.Service.EncryptionMethods != 0 && in.Service.EncryptionMethods&0x0000000B == in.Service.EncryptionMethods &&
						in.Service.EncryptionMethods&0x00000002 == 0 {
						return model.FindingVulnerable,
							fmt.Sprintf("only legacy RC4 key lengths negotiated (methods 0x%08x)", in.Service.EncryptionMethods)
					}
					return model.FindingPotential,
						fmt.Sprintf("encryption level is client compatible (methods 0x%08x)", in.Service.EncryptionMethods)
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
				cert := in.Service.Certificate
				if cert == nil || cert.NotAfter.IsZero() {
					return "", ""
				}
				now := time.Now()
				if now.After(cert.NotAfter) {
					return model.FindingVulnerable,
						fmt.Sprintf("certificate expired on %s (subject %q)", cert.NotAfter.Format(time.RFC3339), cert.Subject)
				}
				if cert.NotAfter.Sub(now) < 30*24*time.Hour {
					return model.FindingPotential,
						fmt.Sprintf("certificate expires on %s (subject %q)", cert.NotAfter.Format(time.RFC3339), cert.Subject)
				}
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
				if in.Service.NegotiationFailureCode == nil {
					return "", ""
				}
				return model.FindingVulnerable,
					fmt.Sprintf("server returned RDP_NEG_FAILURE code 0x%08x", *in.Service.NegotiationFailureCode)
			},
		},
		{
			id:          "hybrid-ex-not-offered",
			title:       "Modern CredSSP (HYBRID_EX) not selected",
			severity:    model.SeverityInfo,
			cvss:        0,
			remediation: "Prefer HYBRID_EX where supported so CredSSP early-user-auth hardening is available to clients.",
			evaluate: func(in Input) (model.FindingStatus, string) {
				switch in.Service.NegotiatedProtocol {
				case rdp.ProtocolHybridEx:
					return model.FindingNotVulnerable, "negotiation selected HYBRID_EX"
				case rdp.ProtocolHybrid:
					return model.FindingPotential, "negotiation selected HYBRID (CredSSP) without HYBRID_EX"
				case rdp.ProtocolSSL:
					return model.FindingPotential, "negotiation selected SSL/TLS without CredSSP"
				default:
					return "", ""
				}
			},
		},
		{
			id:          "cert-missing-san",
			title:       "RDP certificate lacks subject alternative names",
			severity:    model.SeverityLow,
			cvss:        3.1,
			remediation: "Issue an RDP certificate with DNS/IP SANs matching the listener hostname so clients can validate identity.",
			evaluate: func(in Input) (model.FindingStatus, string) {
				cert := in.Service.Certificate
				if cert == nil {
					return "", ""
				}
				if len(cert.DNSNames) > 0 {
					return model.FindingNotVulnerable, fmt.Sprintf("certificate SANs: %s", strings.Join(cert.DNSNames, ", "))
				}
				return model.FindingPotential,
					fmt.Sprintf("certificate subject %q has no DNS SANs", cert.Subject)
			},
		},
		{
			id:          "legacy-rdp-build",
			title:       "Legacy RDP server build advertised",
			severity:    model.SeverityMedium,
			cvss:        5.0,
			remediation: "Upgrade Windows / Remote Desktop Services to a supported build and confirm cumulative updates are applied.",
			evaluate: func(in Input) (model.FindingStatus, string) {
				if in.Service.ServerVersion == 0 {
					return "", ""
				}
				// RDP 5.x / early 6.x era builds commonly appear below 0x00080000.
				if in.Service.ServerVersion < 0x00080000 {
					return model.FindingPotential,
						fmt.Sprintf("MCS server core version 0x%08x suggests a legacy RDP stack", in.Service.ServerVersion)
				}
				return "", ""
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
				if in.Service == nil || !in.Service.RDWeb {
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
				return model.FindingPotential, "UDP/3389 probe indicated a reachable service"
			},
		},
		{
			id:          "nla-kerberos-offered",
			title:       "Kerberos mechanism offered during NLA",
			severity:    model.SeverityInfo,
			cvss:        0,
			remediation: "Prefer Kerberos over NTLM for NLA when domain-joined; ensure ticket caches are rotated and constrained delegation is reviewed.",
			evaluate: func(in Input) (model.FindingStatus, string) {
				if in.Service == nil || !in.Service.KerberosOffered {
					return "", ""
				}
				return model.FindingVulnerable, "CredSSP SPNEGO advertised Kerberos (ccache/keytab available on scanner)"
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
				return model.FindingVulnerable, "CredSSP/NLA reported smart-card logon requirement"
			},
		},
	}
}

func evaluateCertHostname(in Input) (model.FindingStatus, string) {
	if in.Service == nil || in.Service.Certificate == nil || in.TargetHost == "" {
		return "", ""
	}
	host := strings.TrimSpace(in.TargetHost)
	if netIP := parseIPLike(host); netIP {
		// IP targets rarely match DNS SANs; treat as informational potential.
		if len(in.Service.Certificate.DNSNames) == 0 {
			return model.FindingPotential, "scanned by IP and certificate has no DNS SANs"
		}
		return "", ""
	}
	host = strings.ToLower(host)
	subject := strings.ToLower(in.Service.Certificate.Subject)
	for _, san := range in.Service.Certificate.DNSNames {
		if strings.EqualFold(san, host) || matchWildcard(san, host) {
			return model.FindingNotVulnerable, "certificate SAN matches " + host
		}
	}
	if strings.Contains(subject, "cn="+host) {
		return model.FindingPotential, "CN appears to match but SAN verification failed for " + host
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

func evaluateBlueKeep(in Input) (model.FindingStatus, string) {
	switch {
	case in.BlueKeep == nil:
		if in.Service.NLARequired {
			return model.FindingPotential,
				"NLA is enforced, which blocks pre-auth exploitation; the underlying bug may still be unpatched. Verify the update state."
		}
		return model.FindingInconclusive,
			"MS_T120 detection probe was not executed for this endpoint"
	case in.BlueKeep.Attempted && in.BlueKeep.Triggered:
		return model.FindingVulnerable,
			in.BlueKeep.Reason + " (" + in.BlueKeep.Evidence + ")"
	case in.BlueKeep.Attempted:
		return model.FindingNotVulnerable,
			in.BlueKeep.Reason + " (" + in.BlueKeep.Evidence + ")"
	default:
		return model.FindingInconclusive,
			in.BlueKeep.Reason + " (" + in.BlueKeep.Evidence + ")"
	}
}

func evaluateWeakTLS(in Input) (model.FindingStatus, string) {
	if in.Service.TLSVersion == "" {
		return "", ""
	}
	var issues []string
	switch in.Service.TLSVersion {
	case "SSL 3.0", "TLS 1.0", "TLS 1.1":
		issues = append(issues, "negotiated "+in.Service.TLSVersion)
	}
	suite := strings.ToUpper(in.Service.TLSCipherSuite)
	for _, weak := range []string{"RC4", "3DES", "_NULL_", "EXPORT", "_anon_", "DES_"} {
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
// findings. Conditions that are clearly absent are not reported; checks with
// security relevance (for example BlueKeep) are always reported so the report
// documents both confirmed and ruled-out risk.
func Evaluate(ep model.Endpoint, in Input) []model.Finding {
	var findings []model.Finding
	now := time.Now().UTC()
	for _, c := range catalog() {
		status, evidence := c.evaluate(in)
		if status == "" {
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
