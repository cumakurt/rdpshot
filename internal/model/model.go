// Package model defines the shared domain types used across rdpshot packages.
// It has no dependencies on other internal packages.
package model

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
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
	ScanCompleted ScanStatus = "completed"
	ScanFailed    ScanStatus = "failed"
	ScanCancelled ScanStatus = "cancelled"
)

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
	MaxAuthFailures  int      `json:"max_auth_failures"`
	UserWordlist     string   `json:"user_wordlist,omitempty"`
	PasswordWordlist string   `json:"password_wordlist,omitempty"`
	// Acknowledged records that the operator confirmed authorization for the
	// intrusive checks (auth attempts and screenshot capture).
	Acknowledged bool `json:"acknowledged"`
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

// Finding is one check outcome attached to a host.
type Finding struct {
	ID          int64         `json:"id"`
	ScanID      string        `json:"scan_id"`
	HostID      int64         `json:"host_id"`
	Address     string        `json:"address"`
	Port        uint16        `json:"port"`
	CheckID     string        `json:"check_id"`
	Title       string        `json:"title"`
	Severity    Severity      `json:"severity"`
	Status      FindingStatus `json:"status"`
	CVE         string        `json:"cve,omitempty"`
	CVSS        float64       `json:"cvss,omitempty"`
	Evidence    string        `json:"evidence,omitempty"`
	Remediation string        `json:"remediation,omitempty"`
	DetectedAt  time.Time     `json:"detected_at"`
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

// EventType enumerates live event kinds published over SSE.
type EventType string

const (
	EventScanStarted  EventType = "scan.started"
	EventScanProgress EventType = "scan.progress"
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
