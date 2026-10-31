package model

// ComplianceRef links a finding to an industry security benchmark.
type ComplianceRef struct {
	Standard string `json:"standard"` // "CIS", "PCI-DSS", "NIST", "ISO-27001"
	Section  string `json:"section"`  // e.g. "2.3.1.5", "8.3.1", "AC-17"
	Title    string `json:"title,omitempty"`
}

// LookupCompliance returns standard compliance mappings for a check ID.
func LookupCompliance(checkID string) []ComplianceRef {
	switch checkID {
	case "nla-not-required":
		return []ComplianceRef{
			{Standard: "CIS", Section: "2.3.1.5", Title: "Ensure Network Level Authentication is set to Enabled"},
			{Standard: "PCI-DSS", Section: "8.3.1", Title: "Multi-factor authentication for remote access"},
			{Standard: "NIST", Section: "IA-2", Title: "Identification and Authentication (Organizational Users)"},
			{Standard: "ISO-27001", Section: "A.9.4.2", Title: "Secure log-on procedures"},
		}
	case "rdp-service-exposed":
		return []ComplianceRef{
			{Standard: "CIS", Section: "2.3.1.5", Title: "Restrict Remote Desktop Services access"},
			{Standard: "PCI-DSS", Section: "1.3.1", Title: "Inbound traffic restricted to only authorized protocols"},
			{Standard: "NIST", Section: "AC-17", Title: "Remote Access Controls"},
			{Standard: "ISO-27001", Section: "A.13.1.1", Title: "Network controls"},
		}
	case "bluekeep-cve-2019-0708":
		return []ComplianceRef{
			{Standard: "PCI-DSS", Section: "6.2", Title: "Protect all system components from known vulnerabilities"},
			{Standard: "NIST", Section: "SI-2", Title: "Flaw Remediation"},
			{Standard: "ISO-27001", Section: "A.12.6.1", Title: "Management of technical vulnerabilities"},
		}
	case "weak-tls", "tls-legacy-version", "tls-legacy-1.0-1.1":
		return []ComplianceRef{
			{Standard: "PCI-DSS", Section: "4.1", Title: "Use strong cryptography and security protocols (TLS 1.2+)"},
			{Standard: "NIST", Section: "SC-8", Title: "Transmission Confidentiality and Integrity"},
			{Standard: "CIS", Section: "1.1.1", Title: "Ensure legacy TLS protocols are disabled"},
			{Standard: "ISO-27001", Section: "A.10.1.1", Title: "Policy on the use of cryptographic controls"},
		}
	case "weak-encryption", "tls-weak-cipher":
		return []ComplianceRef{
			{Standard: "PCI-DSS", Section: "4.1", Title: "Use strong cryptography and security protocols"},
			{Standard: "NIST", Section: "SC-13", Title: "Cryptographic Protection"},
			{Standard: "CIS", Section: "2.3.1.6", Title: "Set RDP encryption level to High"},
			{Standard: "ISO-27001", Section: "A.10.1.2", Title: "Key management and strong ciphers"},
		}
	case "self-signed-cert", "expired-cert", "cert-hostname-mismatch":
		return []ComplianceRef{
			{Standard: "PCI-DSS", Section: "4.1", Title: "Verify trusted certificates for remote services"},
			{Standard: "NIST", Section: "SC-12", Title: "Cryptographic Key Establishment and Management"},
			{Standard: "CIS", Section: "2.3.1.6", Title: "Use verified server certificates"},
			{Standard: "ISO-27001", Section: "A.10.1.1", Title: "Cryptographic controls and PKI trust"},
		}
	case "rdp-security-without-tls":
		return []ComplianceRef{
			{Standard: "CIS", Section: "2.3.1.5", Title: "Require TLS for Remote Desktop connections"},
			{Standard: "PCI-DSS", Section: "4.1", Title: "Safeguard sensitive data in transmission"},
			{Standard: "NIST", Section: "SC-8", Title: "Transmission Confidentiality and Integrity"},
		}
	case "mfa-enforced":
		return []ComplianceRef{
			{Standard: "PCI-DSS", Section: "8.3.1", Title: "MFA for Remote Network Access (Compliant)"},
			{Standard: "NIST", Section: "IA-2(1)", Title: "Multi-Factor Authentication to Remote Access (Compliant)"},
			{Standard: "CIS", Section: "6.5", Title: "Require MFA for Remote Work (Compliant)"},
		}
	case "pam-proxy-detected":
		return []ComplianceRef{
			{Standard: "PCI-DSS", Section: "8.3.1", Title: "Privileged Access Management Proxy in place"},
			{Standard: "NIST", Section: "AC-2", Title: "Account and Session Management via Bastion/PAM"},
			{Standard: "ISO-27001", Section: "A.9.4.4", Title: "Use of privileged utility programs"},
		}
	case "rd-web-exposed", "rd-gateway-exposed":
		return []ComplianceRef{
			{Standard: "CIS", Section: "2.3.1.5", Title: "Restrict Remote Desktop Services access"},
			{Standard: "PCI-DSS", Section: "1.3.1", Title: "Inbound traffic restricted to authorized endpoints"},
			{Standard: "NIST", Section: "AC-17", Title: "Remote Access Monitoring and Boundaries"},
		}
	case "udp-3389-open":
		return []ComplianceRef{
			{Standard: "CIS", Section: "2.3.1.5", Title: "Restrict unneeded remote access protocols"},
			{Standard: "NIST", Section: "CM-7", Title: "Least Functionality (Disable unneeded UDP ports)"},
		}
	case "nla-smartcard-required", "nla-kerberos-offered":
		return []ComplianceRef{
			{Standard: "PCI-DSS", Section: "8.3.1", Title: "Strong authentication for remote access"},
			{Standard: "NIST", Section: "IA-2", Title: "Multi-factor / Strong Authentication"},
			{Standard: "CIS", Section: "6.5", Title: "Centralized / Kerberos authentication"},
		}
	case "rdp-nla-downgrade-vulnerable":
		return []ComplianceRef{
			{Standard: "CIS", Section: "2.3.1.5", Title: "Ensure Network Level Authentication is set to Enabled"},
			{Standard: "PCI-DSS", Section: "8.3.1", Title: "Strong authentication for non-console administrative access"},
			{Standard: "NIST", Section: "PR.AC-7", Title: "Users, devices, and other assets are authenticated"},
			{Standard: "ISO-27001", Section: "A.9.4.2", Title: "Secure log-on procedures without downgrade"},
		}
	case "rdp-shadow-unprompted-exposed":
		return []ComplianceRef{
			{Standard: "NIST", Section: "AC-3", Title: "Access Enforcement (Remote Session Shadowing)"},
			{Standard: "CIS", Section: "2.3.1.4", Title: "Set rules for remote control of Remote Desktop Services user sessions"},
			{Standard: "ISO-27001", Section: "A.9.4.2", Title: "Secure log-on procedures and session confidentiality"},
		}
	case "rdp-honeypot-detected":
		return []ComplianceRef{
			{Standard: "NIST", Section: "SC-26", Title: "Deception Environments and Honeypot Decoys"},
		}
	default:
		return nil
	}
}
