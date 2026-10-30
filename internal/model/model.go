// Package model defines the shared domain types used across rdpshot packages.
// It has no dependencies on other internal packages.
package model

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Severity classifies the impact of a finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Valid reports whether the severity is one of the known values.
func (s Severity) Valid() bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return true
	}
	return false
}

// Rank returns a comparable rank where higher is more severe.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	}
	return 0
}

// ScanStatus is the lifecycle state of a scan.
type ScanStatus string

const (
	ScanPending   ScanStatus = "pending"
	ScanRunning   ScanStatus = "running"
	ScanPaused    ScanStatus = "paused"
	ScanCompleted ScanStatus = "completed"
	ScanFailed    ScanStatus = "failed"
	ScanCancelled ScanStatus = "cancelled"
)

// Terminal reports whether the scan will not produce further results.
func (s ScanStatus) Terminal() bool {
	switch s {
	case ScanCompleted, ScanFailed, ScanCancelled:
		return true
	}
	return false
}

// FindingStatus states how confident a check outcome is.
type FindingStatus string

const (
	// FindingVulnerable means the condition was positively observed.
	FindingVulnerable FindingStatus = "vulnerable"
	// FindingPotential means the condition is plausible but not proven remotely.
	FindingPotential FindingStatus = "potential"
	// FindingNotVulnerable means the condition was checked and not observed.
	FindingNotVulnerable FindingStatus = "not_vulnerable"
	// FindingInconclusive means evidence was insufficient to decide.
	FindingInconclusive FindingStatus = "inconclusive"
)

// NewID returns a random identifier with the given prefix, for example
// "scan-4f2a9c1d8b6e3a70". It falls back to a timestamp when the system
// randomness source is unavailable.
func NewID(prefix string) string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	}
	return prefix + "-" + hex.EncodeToString(buf[:])
}

// Endpoint is a resolved scan target: one address and one TCP port.
type Endpoint struct {
	Address string `json:"address"`
	Port    uint16 `json:"port"`
}

// Key returns a stable identifier for the endpoint.
func (e Endpoint) Key() string {
	return e.Address + ":" + strconv.Itoa(int(e.Port))
}

// ScanOptions captures the parameters a scan was started with.
type ScanOptions struct {
	Targets          []string `json:"targets"`
	Ports            []uint16 `json:"ports"`
	Blacklist        []string `json:"blacklist,omitempty"`
	TimeoutMS        int      `json:"timeout_ms"`
	Concurrency      int      `json:"concurrency"`
	RatePerSecond    float64  `json:"rate_per_second"`
	EnableVuln       bool     `json:"enable_vuln"`
	EnableAuth       bool     `json:"enable_auth"`
	EnableScreens    bool     `json:"enable_screens"`
	EnableDiscovery  bool     `json:"enable_discovery"`
	// MaxAuthFailures caps rejected logins per host (lockout fail-safe).
	// The product default is 5; 0 disables the limit for aggressive audits.
	MaxAuthFailures int `json:"max_auth_failures"`
	UserWordlist     string   `json:"user_wordlist,omitempty"`
	PasswordWordlist string   `json:"password_wordlist,omitempty"`
	// AuthMode selects how credentials are supplied for auth checks:
	// wordlist (default), single, or pth (pass-the-hash).
	AuthMode string `json:"auth_mode,omitempty"`
	// AuthUsername is used by single and pth modes.
	AuthUsername string `json:"auth_username,omitempty"`
	// AuthDomain is the default NetBIOS/DNS domain for all auth modes (wordlist
	// entries that already embed DOMAIN\user or user@domain keep their own).
	AuthDomain string `json:"auth_domain,omitempty"`
	// AuthPassword is the cleartext secret for AuthMode=single (redacted on API read).
	AuthPassword string `json:"auth_password,omitempty"`
	// AuthNTHash is the NT hash (hex or LM:NT) for AuthMode=pth (redacted on API read).
	AuthNTHash string `json:"auth_nthash,omitempty"`
	// BaseScanID when set restricts the run to a delta against a prior scan
	// (new/changed hosts and hosts with open triage findings).
	BaseScanID string `json:"base_scan_id,omitempty"`
	// Path labels the network vantage used for this audit (internal/external).
	Path string `json:"path,omitempty"`
	// MaxRuntimeSec when > 0 cancels the scan after that many seconds.
	MaxRuntimeSec int `json:"max_runtime_sec,omitempty"`
	// Acknowledged records that the operator confirmed authorization for the
	// intrusive checks (auth attempts and screenshot capture).
	Acknowledged bool `json:"acknowledged"`
}

// Auth mode constants for ScanOptions.AuthMode.
const (
	AuthModeWordlist = "wordlist"
	AuthModeSingle   = "single"
	AuthModePTH      = "pth"
)

// Credential method markers used while candidates are in flight.
const (
	CredMethodPassword = "password"
	CredMethodNTHash   = "nthash"
)

// RedactAuthSecrets returns a copy of options with password/hash fields cleared.
func (o ScanOptions) RedactAuthSecrets() ScanOptions {
	o.AuthPassword = ""
	o.AuthNTHash = ""
	return o
}

// AuthModeImpliesScreenshot reports whether a successful credential check in
// this auth mode must capture a screenshot and disconnect immediately
// (single credential and pass-the-hash).
func (o ScanOptions) AuthModeImpliesScreenshot() bool {
	mode := strings.ToLower(strings.TrimSpace(o.AuthMode))
	return mode == AuthModeSingle || mode == AuthModePTH
}

// Progress tracks live scan counters.
type Progress struct {
	Total      int64 `json:"total"`
	Done       int64 `json:"done"`
	Open       int64 `json:"open"`
	Closed     int64 `json:"closed"`
	Findings   int64 `json:"findings"`
	Creds      int64 `json:"creds"`
	Screens    int64 `json:"screens"`
	ActiveJobs int64 `json:"active_jobs"`
}

// Scan is one scan job.
type Scan struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Status     ScanStatus  `json:"status"`
	CreatedAt  time.Time   `json:"created_at"`
	StartedAt  *time.Time  `json:"started_at,omitempty"`
	FinishedAt *time.Time  `json:"finished_at,omitempty"`
	Options    ScanOptions `json:"options"`
	Progress   Progress    `json:"progress"`
	Error      string      `json:"error,omitempty"`
	// Engagement groups scans under a client or engagement label.
	Engagement string `json:"engagement,omitempty"`
	// Tags are free-form labels for filtering and reporting.
	Tags []string `json:"tags,omitempty"`
	// ScheduleID links a scan back to the schedule that queued it, when any.
	ScheduleID string `json:"schedule_id,omitempty"`
}

// CertificateInfo describes the TLS certificate presented by the server.
type CertificateInfo struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	SerialNumber string    `json:"serial_number"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	SelfSigned   bool      `json:"self_signed"`
	Fingerprint  string    `json:"fingerprint_sha256"`
	DNSNames     []string  `json:"dns_names,omitempty"`
}

// ServiceInfo is the recon result for one open endpoint.
type ServiceInfo struct {
	// NegotiatedProtocol is the RDP selected protocol (0=RDP, 1=SSL, 2=HYBRID, 8=HYBRID_EX).
	NegotiatedProtocol uint32 `json:"negotiated_protocol"`
	// NegotiationFailureCode is set when the server answered with RDP_NEG_FAILURE.
	NegotiationFailureCode *uint32 `json:"negotiation_failure_code,omitempty"`
	NLARequired            bool    `json:"nla_required"`
	// Encryption describes the standard RDP security layer when negotiated.
	EncryptionLevel   string           `json:"encryption_level,omitempty"`
	EncryptionMethods uint32           `json:"encryption_methods,omitempty"`
	TLSVersion        string           `json:"tls_version,omitempty"`
	TLSCipherSuite    string           `json:"tls_cipher_suite,omitempty"`
	Certificate       *CertificateInfo `json:"certificate,omitempty"`
	// ServerVersion is the MCS server core version when available.
	ServerVersion uint32 `json:"server_version,omitempty"`
	// MCSChannelIDs lists the static virtual channel IDs offered by the server.
	MCSChannelIDs []uint16 `json:"mcs_channel_ids,omitempty"`
	OSGuess       string   `json:"os_guess,omitempty"`
	Banner        string   `json:"banner,omitempty"`
	// Evidence holds protocol-level details for reporting.
	Evidence map[string]string `json:"evidence,omitempty"`
	// Alternate exposure paths discovered by optional probes.
	RDWeb          bool   `json:"rd_web,omitempty"`
	RDWebURL       string `json:"rd_web_url,omitempty"`
	RDGateway      bool   `json:"rd_gateway,omitempty"`
	RDGatewayAuth  string `json:"rd_gateway_auth,omitempty"`
	UDP3389        bool   `json:"udp_3389,omitempty"`
	// KerberosOffered is set when the client advertised Kerberos during NLA.
	KerberosOffered bool `json:"kerberos_offered,omitempty"`
	// SmartCardRequired is set when CredSSP/NLA indicates smart-card logon.
	SmartCardRequired bool `json:"smart_card_required,omitempty"`
	// LoginUsers are account tiles observed on the pre-auth Winlogon UI
	// (OCR from a TLS login-screen capture). Best-effort; may be empty.
	LoginUsers []string `json:"login_users,omitempty"`
	// AuthAttempts / AuthFailures summarise the credential audit for this host.
	AuthAttempts int `json:"auth_attempts,omitempty"`
	AuthFailures int `json:"auth_failures,omitempty"`
	// AuthStoppedReason explains why the audit stopped or was skipped.
	AuthStoppedReason string `json:"auth_stopped_reason,omitempty"`
}

// Auth attempt outcome values persisted without secrets.
const (
	AuthOutcomeSuccess     = "success"
	AuthOutcomeInvalid     = "invalid"
	AuthOutcomeLocked      = "locked"
	AuthOutcomeTransport   = "transport"
	AuthOutcomeSkipped     = "skipped"
	AuthOutcomeUnavailable = "unavailable"
)

// AuthAttempt is one credential check against a host (secret never stored).
type AuthAttempt struct {
	ID          int64     `json:"id"`
	ScanID      string    `json:"scan_id"`
	HostID      int64     `json:"host_id"`
	Address     string    `json:"address"`
	Port        uint16    `json:"port"`
	Username    string    `json:"username"`
	Domain      string    `json:"domain,omitempty"`
	Outcome     string    `json:"outcome"`
	Detail      string    `json:"detail,omitempty"`
	AttemptedAt time.Time `json:"attempted_at"`
}

// Host is one probed endpoint within a scan.
type Host struct {
	ID        int64        `json:"id"`
	ScanID    string       `json:"scan_id"`
	Endpoint  Endpoint     `json:"endpoint"`
	State     string       `json:"state"` // open | closed | filtered
	Service   *ServiceInfo `json:"service,omitempty"`
	UpdatedAt time.Time    `json:"updated_at"`
}

// TriageStatus is the operator workflow state of a finding.
type TriageStatus string

const (
	TriageOpen          TriageStatus = "open"
	TriageConfirmed     TriageStatus = "confirmed"
	TriageFalsePositive TriageStatus = "false_positive"
	TriageRemediated    TriageStatus = "remediated"
)

// Valid reports whether the triage status is known.
func (t TriageStatus) Valid() bool {
	switch t {
	case TriageOpen, TriageConfirmed, TriageFalsePositive, TriageRemediated:
		return true
	}
	return false
}

// Finding is one check outcome attached to a host.
type Finding struct {
	ID              int64         `json:"id"`
	ScanID          string        `json:"scan_id"`
	HostID          int64         `json:"host_id"`
	Address         string        `json:"address"`
	Port            uint16        `json:"port"`
	CheckID         string        `json:"check_id"`
	Title           string        `json:"title"`
	Severity        Severity      `json:"severity"`
	Status          FindingStatus `json:"status"`
	CVE             string        `json:"cve,omitempty"`
	CVSS            float64       `json:"cvss,omitempty"`
	Evidence        string        `json:"evidence,omitempty"`
	Remediation     string        `json:"remediation,omitempty"`
	DetectedAt      time.Time     `json:"detected_at"`
	TriageStatus    TriageStatus  `json:"triage_status"`
	TriageNote      string        `json:"triage_note,omitempty"`
	TriageUpdatedAt *time.Time    `json:"triage_updated_at,omitempty"`
}

// Credential is a verified or attempted login record.
type Credential struct {
	ID         int64     `json:"id"`
	ScanID     string    `json:"scan_id"`
	HostID     int64     `json:"host_id"`
	Address    string    `json:"address"`
	Port       uint16    `json:"port"`
	Username   string    `json:"username"`
	Secret     string    `json:"secret,omitempty"`
	Domain     string    `json:"domain,omitempty"`
	Method     string    `json:"method"`
	VerifiedAt time.Time `json:"verified_at"`
}

// Masked returns the credential with the secret hidden for display.
func (c Credential) Masked() Credential {
	c.Secret = "********"
	return c
}

// IsNTHash reports whether the credential carries an NT hash instead of a password.
func (c Credential) IsNTHash() bool {
	return c.Method == CredMethodNTHash || c.Method == "credssp-nla-pth"
}

// Screenshot is metadata for a captured session image.
type Screenshot struct {
	ID         int64     `json:"id"`
	ScanID     string    `json:"scan_id"`
	HostID     int64     `json:"host_id"`
	Address    string    `json:"address"`
	Port       uint16    `json:"port"`
	Username   string    `json:"username,omitempty"`
	FilePath   string    `json:"file_path"`
	Width      int       `json:"width,omitempty"`
	Height     int       `json:"height,omitempty"`
	CapturedAt time.Time `json:"captured_at"`
}

// SeverityCount is one bucket of the severity distribution.
type SeverityCount struct {
	Severity Severity `json:"severity"`
	Count    int64    `json:"count"`
}

// Summary aggregates counters for dashboards and reports.
type Summary struct {
	ScansTotal    int64           `json:"scans_total"`
	HostsTotal    int64           `json:"hosts_total"`
	HostsOpen     int64           `json:"hosts_open"`
	FindingsTotal int64           `json:"findings_total"`
	CredsTotal    int64           `json:"creds_total"`
	ScreensTotal  int64           `json:"screens_total"`
	BySeverity    []SeverityCount `json:"by_severity"`
}

// CountBySeverity returns the count for the requested severity.
func (s Summary) CountBySeverity(sev Severity) int64 {
	for _, bucket := range s.BySeverity {
		if bucket.Severity == sev {
			return bucket.Count
		}
	}
	return 0
}

// CVEStat groups findings by CVE identifier for the reports hub.
type CVEStat struct {
	CVE   string   `json:"cve"`
	Title string   `json:"title"`
	Count int64    `json:"count"`
	Hosts []string `json:"hosts"`
}

// LabeledCount is one bucket of a labelled distribution, such as the TLS
// versions observed across scanned hosts.
type LabeledCount struct {
	Label string `json:"label"`
	Count int64  `json:"count"`
}

// HostRisk aggregates the findings of one endpoint across every scan. The
// reports hub ranks endpoints by RiskScore so the most exposed systems are
// listed first.
type HostRisk struct {
	Address     string   `json:"address"`
	Port        uint16   `json:"port"`
	OSGuess     string   `json:"os_guess,omitempty"`
	TLSVersion  string   `json:"tls_version,omitempty"`
	NLARequired bool     `json:"nla_required"`
	SelfSigned  bool     `json:"self_signed"`
	Open        bool     `json:"open"`
	Findings    int64    `json:"findings"`
	RiskScore   float64  `json:"risk_score"`
	MaxSeverity Severity `json:"max_severity"`
}

// Analytics is the cross-scan posture summary rendered by the reports hub.
// Repeated observations of the same endpoint are collapsed so one estate does
// not inflate the numbers just because it was scanned several times.
type Analytics struct {
	HostsScanned     int64          `json:"hosts_scanned"`
	HostsOpen        int64          `json:"hosts_open"`
	NLAMissing       int64          `json:"nla_missing"`
	LegacyTLS        int64          `json:"legacy_tls"`
	SelfSigned       int64          `json:"self_signed"`
	CertsExpiring30d int64          `json:"certs_expiring_30d"`
	CriticalFindings int64          `json:"critical_findings"`
	AvgCVSS          float64        `json:"avg_cvss"`
	Exposure         []LabeledCount `json:"exposure"`
	OSTypes          []LabeledCount `json:"os_types"`
	Statuses         []LabeledCount `json:"statuses"`
	TopHosts         []HostRisk     `json:"top_hosts"`
	ExpiringCerts    []HostRisk     `json:"expiring_certs,omitempty"`
}

// EventType enumerates live event kinds published over SSE.
type EventType string

const (
	EventScanStarted  EventType = "scan.started"
	EventScanProgress EventType = "scan.progress"
	EventScanPaused   EventType = "scan.paused"
	EventScanResumed  EventType = "scan.resumed"
	EventHostDone     EventType = "host.done"
	EventFinding      EventType = "finding"
	EventCredential   EventType = "credential"
	EventScreenshot   EventType = "screenshot"
	EventLog          EventType = "log"
	EventScanFinished EventType = "scan.finished"
	EventScanFailed   EventType = "scan.failed"
)

// Event is one live update published to the UI.
type Event struct {
	Type    EventType `json:"type"`
	ScanID  string    `json:"scan_id,omitempty"`
	At      time.Time `json:"at"`
	Payload any       `json:"payload,omitempty"`
}

// LogPayload is the payload of EventLog.
type LogPayload struct {
	Level   string `json:"level"`
	Message string `json:"message"`
}

// Schedule defines a recurring scan job. Cadence is either IntervalSeconds or
// a five-field CronExpr (minute hour day-of-month month day-of-week).
type Schedule struct {
	ID               string      `json:"id"`
	Name             string      `json:"name"`
	Enabled          bool        `json:"enabled"`
	IntervalSeconds  int         `json:"interval_seconds"`
	CronExpr         string      `json:"cron_expr,omitempty"`
	Options          ScanOptions `json:"options"`
	NotifyWebhook    string      `json:"notify_webhook,omitempty"`
	NotifyOnComplete bool        `json:"notify_on_complete"`
	NotifyOnCritical bool        `json:"notify_on_critical"`
	CreatedAt        time.Time   `json:"created_at"`
	UpdatedAt        time.Time   `json:"updated_at"`
	LastRunAt        *time.Time  `json:"last_run_at,omitempty"`
	NextRunAt        *time.Time  `json:"next_run_at,omitempty"`
	LastScanID       string      `json:"last_scan_id,omitempty"`
	LastError        string      `json:"last_error,omitempty"`
}

// WordlistSet is a named pair of user/password wordlist paths.
type WordlistSet struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	UserPath     string    `json:"user_path"`
	PasswordPath string    `json:"password_path"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// UserRole controls what a local portal account may do.
type UserRole string

const (
	RoleViewer   UserRole = "viewer"
	RoleOperator UserRole = "operator"
	RoleAdmin    UserRole = "admin"
)

// Valid reports whether the role is known.
func (r UserRole) Valid() bool {
	switch r {
	case RoleViewer, RoleOperator, RoleAdmin:
		return true
	}
	return false
}

// CanWrite reports whether the role may mutate state.
func (r UserRole) CanWrite() bool {
	return r == RoleOperator || r == RoleAdmin
}

// CanAdmin reports whether the role may manage users and branding.
func (r UserRole) CanAdmin() bool {
	return r == RoleAdmin
}

// CanIntrusive reports whether the role may start credential/screenshot work
// or delete scan artifacts.
func (r UserRole) CanIntrusive() bool {
	return r == RoleOperator || r == RoleAdmin
}

// User is a local portal account.
type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	Role         UserRole  `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// AuditEntry records one privileged or mutating action.
type AuditEntry struct {
	ID        int64     `json:"id"`
	At        time.Time `json:"at"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Target    string    `json:"target,omitempty"`
	Detail    string    `json:"detail,omitempty"`
	RemoteIP  string    `json:"remote_ip,omitempty"`
}

// ReportBranding customizes generated reports.
type ReportBranding struct {
	Organization string `json:"organization,omitempty"`
	Engagement   string `json:"engagement,omitempty"`
	PreparedBy   string `json:"prepared_by,omitempty"`
	FooterNote   string `json:"footer_note,omitempty"`
	LogoDataURI  string `json:"logo_data_uri,omitempty"`
}

// HostNote is an operator annotation for one endpoint within an engagement.
type HostNote struct {
	ID         int64     `json:"id"`
	Engagement string    `json:"engagement"`
	Address    string    `json:"address"`
	Port       uint16    `json:"port"`
	Note       string    `json:"note"`
	UpdatedAt  time.Time `json:"updated_at"`
	UpdatedBy  string    `json:"updated_by,omitempty"`
}

// AlertRules configures outbound alerts evaluated when a scan finishes.
type AlertRules struct {
	WebhookURL      string `json:"webhook_url,omitempty"`
	OnCritical      bool   `json:"on_critical"`
	OnHigh          bool   `json:"on_high"`
	OnNLARegressed  bool   `json:"on_nla_regressed"`
	OnCredReuseMin  int    `json:"on_cred_reuse_min"`
	// MinHardeningScore fires when the scan score is strictly below this value.
	// Zero disables the SLA check.
	MinHardeningScore int `json:"min_hardening_score"`
	// OnOpenTriageCritical fires when any critical finding is still triage=open.
	OnOpenTriageCritical bool `json:"on_open_triage_critical"`
	Enabled              bool `json:"enabled"`
}

// TrendPoint is one sample in a posture time series.
type TrendPoint struct {
	At              time.Time `json:"at"`
	ScanID          string    `json:"scan_id"`
	ScanName        string    `json:"scan_name"`
	HostsOpen       int64     `json:"hosts_open"`
	FindingsTotal   int64     `json:"findings_total"`
	Critical        int64     `json:"critical"`
	High            int64     `json:"high"`
	OpenTriage      int64     `json:"open_triage"`
}

// TrendSeries is the baseline/trend payload for the reports hub.
type TrendSeries struct {
	Engagement string       `json:"engagement,omitempty"`
	Points     []TrendPoint `json:"points"`
}

// ScanDiff summarises the posture delta between a base scan and a later one.
type ScanDiff struct {
	BaseID          string            `json:"base_id"`
	AgainstID       string            `json:"against_id"`
	BaseName        string            `json:"base_name"`
	AgainstName     string            `json:"against_name"`
	HostsAdded      []Host            `json:"hosts_added"`
	HostsRemoved    []Host            `json:"hosts_removed"`
	HostsChanged    []HostChange      `json:"hosts_changed"`
	FindingsAdded   []Finding         `json:"findings_added"`
	FindingsRemoved []Finding         `json:"findings_removed"`
	FindingsChanged []FindingChange   `json:"findings_changed"`
	Summary         ScanDiffSummary   `json:"summary"`
}

// ScanDiffSummary is the compact counter block shown above a diff.
type ScanDiffSummary struct {
	HostsAdded           int `json:"hosts_added"`
	HostsRemoved         int `json:"hosts_removed"`
	HostsChanged         int `json:"hosts_changed"`
	FindingsAdded        int `json:"findings_added"`
	FindingsRemoved      int `json:"findings_removed"`
	FindingsChanged      int `json:"findings_changed"`
	FindingsRemediated   int `json:"findings_remediated"`
	HardeningScoreDelta  int `json:"hardening_score_delta"`
}

// HostChange records field-level differences for one endpoint that appears in
// both scans.
type HostChange struct {
	Address string   `json:"address"`
	Port    uint16   `json:"port"`
	Before  HostSnap `json:"before"`
	After   HostSnap `json:"after"`
}

// HostSnap is the comparable posture snapshot of one host.
type HostSnap struct {
	State       string `json:"state"`
	NLARequired bool   `json:"nla_required"`
	TLSVersion  string `json:"tls_version,omitempty"`
	OSGuess     string `json:"os_guess,omitempty"`
	SelfSigned  bool   `json:"self_signed"`
}

// FindingChange records a finding that exists on both scans but changed status
// or severity.
type FindingChange struct {
	Address  string         `json:"address"`
	Port     uint16         `json:"port"`
	CheckID  string         `json:"check_id"`
	Title    string         `json:"title"`
	Before   FindingSnap    `json:"before"`
	After    FindingSnap    `json:"after"`
}

// FindingSnap is the comparable slice of a finding.
type FindingSnap struct {
	Severity Severity      `json:"severity"`
	Status   FindingStatus `json:"status"`
	CVSS     float64       `json:"cvss"`
	CVE      string        `json:"cve,omitempty"`
}
