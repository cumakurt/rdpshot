// Package playbook provides static remediation playbooks keyed by check ID.
package playbook

// Entry is one operator-facing remediation guide.
type Entry struct {
	CheckID    string   `json:"check_id"`
	Title      string   `json:"title"`
	Summary    string   `json:"summary"`
	Steps      []string `json:"steps"`
	References []string `json:"references,omitempty"`
}

// All returns every known playbook.
func All() []Entry {
	out := make([]Entry, 0, len(catalog))
	for _, id := range order {
		out = append(out, catalog[id])
	}
	return out
}

// Get returns one playbook by check ID.
func Get(checkID string) (Entry, bool) {
	e, ok := catalog[checkID]
	return e, ok
}

var order = []string{
	"nla-not-required", "rdp-security-without-tls", "self-signed-cert", "expired-cert",
	"cert-hostname-mismatch", "bluekeep-cve-2019-0708", "legacy-rdp-build", "rd-web-exposed",
	"rd-gateway-exposed", "udp-3389-open", "nla-kerberos-offered", "nla-smartcard-required",
}

var catalog = map[string]Entry{
	"nla-not-required": {
		CheckID: "nla-not-required", Title: "Enforce Network Level Authentication",
		Summary: "Require NLA so credentials are protected before the desktop session starts.",
		Steps: []string{
			"Open Group Policy: Computer Configuration → Administrative Templates → Windows Components → Remote Desktop Services → Remote Desktop Session Host → Security.",
			"Enable \"Require user authentication for remote connections by using Network Level Authentication\".",
			"Confirm RDP listeners negotiate HYBRID or HYBRID_EX only.",
			"Re-scan the host with rdpshot vulnerability checks.",
		},
		References: []string{"https://learn.microsoft.com/windows-server/remote/remote-desktop-services/"},
	},
	"rdp-security-without-tls": {
		CheckID: "rdp-security-without-tls", Title: "Disable legacy TLS for RDP",
		Summary: "Negotiate TLS 1.2+ with strong cipher suites on the RDP listener.",
		Steps: []string{
			"Disable TLS 1.0/1.1 via Schannel registry or IISCrypto / GPO.",
			"Remove RC4, 3DES, and NULL cipher suites.",
			"Restart TermService and re-test negotiation.",
		},
	},
	"self-signed-cert": {
		CheckID: "self-signed-cert", Title: "Deploy a trusted RDP certificate",
		Summary: "Replace the self-signed RDP certificate with one issued by your enterprise CA.",
		Steps: []string{
			"Issue a certificate with Server Authentication EKU and DNS SAN matching the hostname.",
			"Configure Remote Desktop to use the certificate (GPO or wmic / PowerShell).",
			"Verify clients no longer warn about untrusted identity.",
		},
	},
	"expired-cert": {
		CheckID: "expired-cert", Title: "Renew the RDP TLS certificate",
		Summary: "Expired certificates break trust and enable MitM confusion.",
		Steps: []string{
			"Renew or re-issue the certificate before NotAfter.",
			"Update the RDP listener binding.",
			"Document the renewal in the engagement evidence pack.",
		},
	},
	"cert-hostname-mismatch": {
		CheckID: "cert-hostname-mismatch", Title: "Align certificate SAN with connection name",
		Summary: "Clients validate identity against the hostname they dial.",
		Steps: []string{
			"Add every client-facing DNS name to the certificate SAN list.",
			"Prefer connecting by the certified name rather than raw IP.",
		},
	},
	"bluekeep-cve-2019-0708": {
		CheckID: "bluekeep-cve-2019-0708", Title: "Patch BlueKeep (CVE-2019-0708)",
		Summary: "Apply the Microsoft security update and keep NLA enforced.",
		Steps: []string{
			"Install the May 2019 (or later cumulative) Windows update for CVE-2019-0708.",
			"Ensure NLA is required as defense in depth.",
			"Re-run the rdpshot safe BlueKeep probe.",
		},
		References: []string{"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708"},
	},
	"legacy-rdp-build": {
		CheckID: "legacy-rdp-build", Title: "Upgrade legacy Remote Desktop stack",
		Summary: "Legacy MCS server versions indicate unsupported OS builds.",
		Steps: []string{
			"Upgrade the host to a supported Windows release.",
			"Apply current cumulative updates.",
		},
	},
	"rd-web-exposed": {
		CheckID: "rd-web-exposed", Title: "Restrict RD Web Access",
		Summary: "Publish RD Web only through controlled ingress with MFA.",
		Steps: []string{
			"Place RD Web behind VPN or reverse proxy with MFA.",
			"Disable anonymous discovery pages where unused.",
		},
	},
	"rd-gateway-exposed": {
		CheckID: "rd-gateway-exposed", Title: "Harden RD Gateway publication",
		Summary: "Limit RD Gateway to authorized networks and strong auth.",
		Steps: []string{
			"Require CAP policies with MFA.",
			"Restrict source IP ranges on the edge firewall.",
		},
	},
	"udp-3389-open": {
		CheckID: "udp-3389-open", Title: "Disable unused RDP UDP transport",
		Summary: "UDP/3389 widens exposure when TCP RDP already exists.",
		Steps: []string{
			"Disable UDP transport for Remote Desktop if not required.",
			"Block UDP/3389 at the perimeter.",
		},
	},
	"nla-kerberos-offered": {
		CheckID: "nla-kerberos-offered", Title: "Review Kerberos NLA path",
		Summary: "Kerberos was advertised during CredSSP negotiation.",
		Steps: []string{
			"Confirm ticket-granting hygiene and constrained delegation policy.",
			"Prefer Kerberos over NTLM for domain accounts.",
		},
	},
	"nla-smartcard-required": {
		CheckID: "nla-smartcard-required", Title: "Document smart-card requirement",
		Summary: "Password-based credential audits will not succeed against smart-card accounts.",
		Steps: []string{
			"Capture the requirement in the engagement ROE.",
			"Use approved smart-card test accounts when validating access.",
		},
	},
}
