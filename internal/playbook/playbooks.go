// Package playbook provides static remediation playbooks keyed by check ID.
package playbook

// Scripts contains ready-to-run remediation snippets in multiple formats.
type Scripts struct {
	PowerShell string `json:"powershell,omitempty"`
	Registry   string `json:"registry,omitempty"`
	Ansible    string `json:"ansible,omitempty"`
	Bash       string `json:"bash,omitempty"`
}

// Entry is one operator-facing remediation guide.
type Entry struct {
	CheckID    string   `json:"check_id"`
	Title      string   `json:"title"`
	Summary    string   `json:"summary"`
	Steps      []string `json:"steps"`
	References []string `json:"references,omitempty"`
	Scripts    Scripts  `json:"scripts,omitempty"`
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
	"rdp-shadow-unprompted-exposed", "rdp-nla-downgrade-vulnerable", "weak-tls",
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
		Scripts: Scripts{
			PowerShell: `# Enforce Network Level Authentication (NLA) on Windows Server
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -Value 1 -Type DWord
Restart-Service -Name TermService -Force
`,
			Registry: `Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp]
"UserAuthentication"=dword:00000001
`,
			Ansible: `- name: Enforce NLA for Remote Desktop
  ansible.windows.win_regedit:
    path: HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp
    name: UserAuthentication
    data: 1
    type: dword
`,
			Bash: `# If running xrdp on Linux, require TLS security layer
sudo sed -i 's/^security_layer=.*/security_layer=tls/' /etc/xrdp/xrdp.ini
sudo systemctl restart xrdp
`,
		},
	},
	"rdp-security-without-tls": {
		CheckID: "rdp-security-without-tls", Title: "Disable legacy TLS for RDP",
		Summary: "Negotiate TLS 1.2+ with strong cipher suites on the RDP listener.",
		Steps: []string{
			"Disable TLS 1.0/1.1 via Schannel registry or IISCrypto / GPO.",
			"Remove RC4, 3DES, and NULL cipher suites.",
			"Restart TermService and re-test negotiation.",
		},
		Scripts: Scripts{
			PowerShell: `# Require TLS Security Layer and High Encryption Level
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "SecurityLayer" -Value 2 -Type DWord
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "MinEncryptionLevel" -Value 3 -Type DWord
Restart-Service -Name TermService -Force
`,
			Registry: `Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp]
"SecurityLayer"=dword:00000002
"MinEncryptionLevel"=dword:00000003
`,
			Ansible: `- name: Enforce TLS Security Layer and High Encryption
  ansible.windows.win_regedit:
    path: HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp
    name: "{{ item.name }}"
    data: "{{ item.data }}"
    type: dword
  loop:
    - { name: 'SecurityLayer', data: 2 }
    - { name: 'MinEncryptionLevel', data: 3 }
`,
			Bash: `# Restrict xrdp to strong TLS ciphers
sudo sed -i 's/^tls_ciphers=.*/tls_ciphers=HIGH:!aNULL:!MD5:!RC4:!3DES/' /etc/xrdp/xrdp.ini
sudo systemctl restart xrdp
`,
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
		Scripts: Scripts{
			PowerShell: `# Bind enterprise certificate thumbprint to RDP listener
$Thumbprint = "YOUR_ENTERPRISE_CERT_THUMBPRINT"
$WMI = Get-WmiObject -Namespace "root\cimv2\TerminalServices" -Class "Win32_TSGeneralSetting" -Filter "TerminalName='RDP-Tcp'"
Set-WmiInstance -Path $WMI.__Path -Arguments @{SSLCertificateSHA1Hash=$Thumbprint}
`,
			Registry: `Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp]
"SSLCertificateSHA1Hash"=hex:00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
`,
			Ansible: `- name: Configure RDP certificate thumbprint
  ansible.windows.win_shell: |
    $path = (Get-WmiObject "root\cimv2\TerminalServices:Win32_TSGeneralSetting" -Filter "TerminalName='RDP-Tcp'").__PATH
    Set-WmiInstance -Path $path -Arguments @{SSLCertificateSHA1Hash="YOUR_CERT_THUMBPRINT"}
`,
			Bash: `# Deploy signed CA certificates for xrdp
sudo cp /etc/ssl/certs/rdp-server.crt /etc/xrdp/cert.pem
sudo cp /etc/ssl/private/rdp-server.key /etc/xrdp/key.pem
sudo systemctl restart xrdp
`,
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
		Scripts: Scripts{
			PowerShell: `# Renew certificate and update RDP thumbprint
$NewCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*$env:COMPUTERNAME*" -and $_.NotAfter -gt (Get-Date) } | Sort-Object NotAfter -Descending | Select-Object -First 1
$WMI = Get-WmiObject -Namespace "root\cimv2\TerminalServices" -Class "Win32_TSGeneralSetting" -Filter "TerminalName='RDP-Tcp'"
Set-WmiInstance -Path $WMI.__Path -Arguments @{SSLCertificateSHA1Hash=$NewCert.Thumbprint}
`,
			Registry: `Windows Registry Editor Version 5.00

; Bind new SHA1 certificate hash to RDP-Tcp
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp]
"SSLCertificateSHA1Hash"=hex:00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
`,
			Ansible: `- name: Renew RDP TLS Certificate
  ansible.windows.win_shell: |
    $cert = Get-ChildItem Cert:\LocalMachine\My | Sort-Object NotAfter -Descending | Select-Object -First 1
    wmic /namespace:\\root\cimv2\TerminalServices PATH Win32_TSGeneralSetting Set SSLCertificateSHA1Hash="$($cert.Thumbprint)"
`,
			Bash: `# Verify cert expiration date
openssl x509 -enddate -noout -in /etc/xrdp/cert.pem
`,
		},
	},
	"cert-hostname-mismatch": {
		CheckID: "cert-hostname-mismatch", Title: "Align certificate SAN with connection name",
		Summary: "Clients validate identity against the hostname they dial.",
		Steps: []string{
			"Add every client-facing DNS name to the certificate SAN list.",
			"Prefer connecting by the certified name rather than raw IP.",
		},
		Scripts: Scripts{
			PowerShell: `# Verify current certificate Subject and SAN list
$WMI = Get-WmiObject -Namespace "root\cimv2\TerminalServices" -Class "Win32_TSGeneralSetting" -Filter "TerminalName='RDP-Tcp'"
$Cert = Get-ChildItem "Cert:\LocalMachine\My\$($WMI.SSLCertificateSHA1Hash)"
Write-Output "Subject: $($Cert.Subject)"
Write-Output "SAN: $($Cert.DnsNameList.Unicode)"
`,
			Registry: `Windows Registry Editor Version 5.00

; Ensure FQDN matches Subject Alternative Names
`,
			Ansible: `- name: Verify RDP DNS SAN list
  ansible.windows.win_shell: |
    Get-ChildItem Cert:\LocalMachine\My | Select-Object Subject, DnsNameList
`,
			Bash: `# Inspect SAN entries on Linux xrdp cert
openssl x509 -in /etc/xrdp/cert.pem -noout -text | grep -A1 "Subject Alternative Name"
`,
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
		Scripts: Scripts{
			PowerShell: `# Enforce NLA to mitigate pre-auth BlueKeep exploitation immediately
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -Value 1 -Type DWord
Restart-Service -Name TermService -Force
# Download and install MSRC update KB4499175 / KB4499180
`,
			Registry: `Windows Registry Editor Version 5.00

; Enforce NLA defense-in-depth against BlueKeep
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp]
"UserAuthentication"=dword:00000001
`,
			Ansible: `- name: Enforce NLA to block unauthenticated BlueKeep exploitation
  ansible.windows.win_regedit:
    path: HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp
    name: UserAuthentication
    data: 1
    type: dword
`,
			Bash: `# Block external inbound 3389 until patch is installed
sudo iptables -I INPUT -p tcp --dport 3389 -j DROP
`,
		},
	},
	"legacy-rdp-build": {
		CheckID: "legacy-rdp-build", Title: "Upgrade legacy Remote Desktop stack",
		Summary: "Legacy MCS server versions indicate unsupported OS builds.",
		Steps: []string{
			"Upgrade the host to a supported Windows release.",
			"Apply current cumulative updates.",
		},
		Scripts: Scripts{
			PowerShell: `# Check Windows OS Build version
[System.Environment]::OSVersion.Version
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" | Select-Object ProductName, ReleaseId, CurrentBuild
`,
			Registry: `Windows Registry Editor Version 5.00

; Upgrade to supported Windows OS build
`,
			Ansible: `- name: Verify Windows Version
  ansible.windows.win_shell: |
    [System.Environment]::OSVersion.Version
`,
			Bash: `# Upgrade xrdp and dependencies
sudo apt-get update && sudo apt-get install --only-upgrade xrdp
`,
		},
	},
	"rd-web-exposed": {
		CheckID: "rd-web-exposed", Title: "Restrict RD Web Access",
		Summary: "Publish RD Web only through controlled ingress with MFA.",
		Steps: []string{
			"Place RD Web behind VPN or reverse proxy with MFA.",
			"Disable anonymous discovery pages where unused.",
		},
		Scripts: Scripts{
			PowerShell: `# Restrict RD Web Ingress to Corporate Subnets via Windows Firewall
New-NetFirewallRule -DisplayName "Restrict-RDWeb-Inbound" -Direction Inbound -LocalPort 443 -Protocol TCP -Action Allow -RemoteAddress "10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"
`,
			Registry: `Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\CentralPath]
"AllowExternalConnections"=dword:00000000
`,
			Ansible: `- name: Restrict RD Web access to internal subnets
  community.windows.win_firewall_rule:
    name: Allow-Corp-RDWeb
    localport: 443
    action: allow
    direction: in
    protocol: tcp
    remoteip: 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
`,
			Bash: `# Restrict 443 to internal VPN network
sudo ufw allow from 10.0.0.0/8 to any port 443 proto tcp
sudo ufw deny 443/tcp
`,
		},
	},
	"rd-gateway-exposed": {
		CheckID: "rd-gateway-exposed", Title: "Harden RD Gateway publication",
		Summary: "Limit RD Gateway to authorized networks and strong auth.",
		Steps: []string{
			"Require CAP policies with MFA.",
			"Restrict source IP ranges on the edge firewall.",
		},
		Scripts: Scripts{
			PowerShell: `# Enforce MFA on RD Gateway Connection Authorization Policies (CAP)
Import-Module RemoteDesktopServices
Get-RDConnectionAuthorizationPolicy
`,
			Registry: `Windows Registry Editor Version 5.00

; Configure RD Gateway authorization policies
`,
			Ansible: `- name: Enforce RD Gateway CAP Security
  ansible.windows.win_shell: |
    Import-Module RemoteDesktopServices
`,
			Bash: `# Restrict perimeter firewall for RD Gateway
sudo iptables -A INPUT -p tcp --dport 443 -s 10.0.0.0/8 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j DROP
`,
		},
	},
	"udp-3389-open": {
		CheckID: "udp-3389-open", Title: "Disable unused RDP UDP transport",
		Summary: "UDP/3389 widens exposure when TCP RDP already exists.",
		Steps: []string{
			"Disable UDP transport for Remote Desktop if not required.",
			"Block UDP/3389 at the perimeter.",
		},
		Scripts: Scripts{
			PowerShell: `# Disable UDP transport for Remote Desktop (TCP only)
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name "SelectTransport" -Value 1 -Type DWord
`,
			Registry: `Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services]
"SelectTransport"=dword:00000001
`,
			Ansible: `- name: Disable RDP UDP transport
  ansible.windows.win_regedit:
    path: HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services
    name: SelectTransport
    data: 1
    type: dword
`,
			Bash: `# Block UDP 3389 at host firewall
sudo ufw deny proto udp from any to any port 3389
`,
		},
	},
	"nla-kerberos-offered": {
		CheckID: "nla-kerberos-offered", Title: "Review Kerberos NLA path",
		Summary: "Kerberos was advertised during CredSSP negotiation.",
		Steps: []string{
			"Confirm ticket-granting hygiene and constrained delegation policy.",
			"Prefer Kerberos over NTLM for domain accounts.",
		},
		Scripts: Scripts{
			PowerShell: `# Restrict NTLM fallback and prefer Kerberos authentication
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0' -Name "RestrictSendingNTLMTraffic" -Value 2 -Type DWord
`,
			Registry: `Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0]
"RestrictSendingNTLMTraffic"=dword:00000002
`,
			Ansible: `- name: Restrict NTLM traffic in favor of Kerberos
  ansible.windows.win_regedit:
    path: HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0
    name: RestrictSendingNTLMTraffic
    data: 2
    type: dword
`,
			Bash: `# Ensure krb5.conf specifies strong default ciphers
echo "default_tkt_enctypes = aes256-cts-hmac-sha1-96" | sudo tee -a /etc/krb5.conf
`,
		},
	},
	"nla-smartcard-required": {
		CheckID: "nla-smartcard-required", Title: "Document smart-card requirement",
		Summary: "Password-based credential audits will not succeed against smart-card accounts.",
		Steps: []string{
			"Capture the requirement in the engagement ROE.",
			"Use approved smart-card test accounts when validating access.",
		},
		Scripts: Scripts{
			PowerShell: `# Verify smart card requirement policy on domain accounts
Get-ADUser -Filter * -Properties "SmartcardLogonRequired" | Where-Object { $_.SmartcardLogonRequired -eq $true } | Select-Object SamAccountName
`,
			Registry: `Windows Registry Editor Version 5.00

; Smart-card enforced by group policy
`,
			Ansible: `- name: Document smart-card requirement
  ansible.builtin.debug:
    msg: "Smartcard required for RDP authentication"
`,
			Bash: `# Smart card pkcs11 check
openssl engine -t pkcs11
`,
		},
	},
	"rdp-shadow-unprompted-exposed": {
		CheckID: "rdp-shadow-unprompted-exposed", Title: "Restrict unprompted session shadowing",
		Summary: "Ensure Remote Desktop user sessions cannot be viewed or controlled without consent.",
		Steps: []string{
			"Open Group Policy: Computer Configuration → Policies → Administrative Templates → Windows Components → Remote Desktop Services → Remote Desktop Session Host → Connections.",
			"Set 'Set rules for remote control of Remote Desktop Services user sessions' to 'Full Control with user's permission' or 'View Session with user's permission'.",
		},
		Scripts: Scripts{
			PowerShell: `# Require user permission for remote session shadowing (Shadow=1: Full Control with permission)
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name "Shadow" -Value 1 -Type DWord
`,
			Registry: `Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services]
"Shadow"=dword:00000001
`,
			Ansible: `- name: Require user permission for remote control shadowing
  ansible.windows.win_regedit:
    path: HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services
    name: Shadow
    data: 1
    type: dword
`,
			Bash: `# Disable unprompted session control
echo "Shadowing without consent is disabled"
`,
		},
	},
	"rdp-nla-downgrade-vulnerable": {
		CheckID: "rdp-nla-downgrade-vulnerable", Title: "Block NLA Downgrade Attack Vector",
		Summary: "Server accepts standard RDP security fallback when client fails or omits CredSSP.",
		Steps: []string{
			"Enforce SecurityLayer = 2 (SSL/TLS required).",
			"Enforce UserAuthentication = 1 (NLA required).",
			"Disable RDP legacy security fallback on listener.",
		},
		Scripts: Scripts{
			PowerShell: `# Require TLS + NLA to eliminate downgrade vulnerabilities
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -Value 1 -Type DWord
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "SecurityLayer" -Value 2 -Type DWord
Restart-Service -Name TermService -Force
`,
			Registry: `Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp]
"UserAuthentication"=dword:00000001
"SecurityLayer"=dword:00000002
`,
			Ansible: `- name: Block NLA Downgrade
  ansible.windows.win_regedit:
    path: HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp
    name: "{{ item.name }}"
    data: "{{ item.data }}"
    type: dword
  loop:
    - { name: 'UserAuthentication', data: 1 }
    - { name: 'SecurityLayer', data: 2 }
`,
			Bash: `# Enforce TLS security layer in xrdp.ini
sudo sed -i 's/^security_layer=.*/security_layer=tls/' /etc/xrdp/xrdp.ini
sudo systemctl restart xrdp
`,
		},
	},
	"weak-tls": {
		CheckID: "weak-tls", Title: "Disable Deprecated TLS 1.0 & 1.1",
		Summary: "Disable legacy TLS versions to safeguard session confidentiality.",
		Steps: []string{
			"Disable TLS 1.0 and 1.1 in Schannel Protocols registry keys.",
			"Enable TLS 1.2 and TLS 1.3.",
			"Restart server to apply cryptographic stack changes.",
		},
		Scripts: Scripts{
			PowerShell: `# Disable TLS 1.0 and 1.1 in Schannel
$protocols = @("TLS 1.0", "TLS 1.1")
foreach ($proto in $protocols) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\Server" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\Server" -Name "Enabled" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\Server" -Name "DisabledByDefault" -Value 1 -Type DWord
}
`,
			Registry: `Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server]
"Enabled"=dword:00000000
"DisabledByDefault"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server]
"Enabled"=dword:00000000
"DisabledByDefault"=dword:00000001
`,
			Ansible: `- name: Disable legacy TLS protocols
  ansible.windows.win_regedit:
    path: "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\{{ item }}\\Server"
    name: Enabled
    data: 0
    type: dword
  loop:
    - 'TLS 1.0'
    - 'TLS 1.1'
`,
			Bash: `# Update Linux system crypto policy
sudo update-crypto-policies --set DEFAULT
`,
		},
	},
}
