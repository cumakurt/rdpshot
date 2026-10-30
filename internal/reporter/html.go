package reporter

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"strconv"

	"rdpshot/internal/about"
	"rdpshot/internal/model"
)

//go:embed report.html.tmpl
var reportTemplateSource string

// reportTemplate is parsed once at init; templates are safe for concurrent
// execution afterwards, so no shared mutable state is exposed.
var reportTemplate = template.Must(template.New("report.html").Parse(reportTemplateSource))

// htmlView is the pre-formatted model the HTML template renders. Every value
// is a plain string or number so html/template auto-escapes all target-derived
// content.
type htmlView struct {
	ToolName     string
	ToolVersion  string
	Developer    string
	Copyright    string
	GeneratedAt  string
	Organization string
	Engagement   string
	PreparedBy   string
	FooterNote   string
	LogoDataURI  template.URL
	Scan         scanView
	Cards        []cardView
	TopFindings  []findingView
	Severity     []severityBucket
	Findings     []findingView
	Hosts        []hostView
	Credentials  []credentialView
	Screenshots  []screenshotView
}

type scanView struct {
	Name  string
	ID    string
	Scope string
}

type cardView struct {
	Label string
	Value int64
	Class string
}

type findingView struct {
	Severity      string
	SeverityClass string
	CheckID       string
	Title         string
	CVE           string
	CVSS          string
	Status        string
	HostPort      string
	Evidence      string
	Remediation   string
}

type hostView struct {
	Address     string
	Port        string
	State       string
	NLA         string
	Protocol    string
	TLSVersion  string
	Certificate string
	OSGuess     string
}

type credentialView struct {
	HostPort   string
	Domain     string
	Username   string
	Secret     string
	Method     string
	VerifiedAt string
}

type screenshotView struct {
	FilePath     string
	HostPort     string
	Username     string
	Label        string
	CapturedAt   string
	ImageDataURI template.URL
	HasImage     bool
}

// HTML writes a complete, self-contained (inline CSS, no external requests) HTML report.
func HTML(w io.Writer, d Data) error {
	if err := reportTemplate.Execute(w, buildHTMLView(d)); err != nil {
		return fmt.Errorf("render html report: %w", err)
	}
	return nil
}

// buildHTMLView converts the domain data into pre-formatted template values.
func buildHTMLView(d Data) htmlView {
	view := htmlView{
		ToolName:     toolName,
		ToolVersion:  orDash(d.ToolVersion),
		Developer:    about.Developer,
		Copyright:    about.CopyrightLine(),
		GeneratedAt:  orDash(formatTime(d.GeneratedAt)),
		Organization: orDash(d.Branding.Organization),
		Engagement:   orDash(firstNonEmpty(d.Branding.Engagement, d.Scan.Engagement)),
		PreparedBy:   orDash(d.Branding.PreparedBy),
		FooterNote:   orDash(d.Branding.FooterNote),
		LogoDataURI:  template.URL(d.Branding.LogoDataURI),
		Scan: scanView{
			Name:  orDash(d.Scan.Name),
			ID:    orDash(d.Scan.ID),
			Scope: orDash(scopeText(d.Scan)),
		},
		Cards:    summaryCards(d),
		Severity: severityBuckets(d),
	}
	for _, f := range sortedFindings(d.Findings) {
		row := findingView{
			Severity:      string(f.Severity),
			SeverityClass: severityClass(f.Severity),
			CheckID:       orDash(f.CheckID),
			Title:         orDash(f.Title),
			CVE:           orDash(f.CVE),
			CVSS:          orDash(formatCVSS(f.CVSS)),
			Status:        string(f.Status),
			HostPort:      endpointText(f.Address, f.Port),
			Evidence:      orDash(singleLine(f.Evidence)),
			Remediation:   orDash(singleLine(f.Remediation)),
		}
		view.Findings = append(view.Findings, row)
		if len(view.TopFindings) < 3 && (f.Status == model.FindingVulnerable || f.Status == model.FindingPotential) {
			view.TopFindings = append(view.TopFindings, row)
		}
	}
	for _, h := range d.Hosts {
		view.Hosts = append(view.Hosts, hostRow(h))
	}
	for _, c := range d.Credentials {
		// Defense in depth: callers must pre-mask secrets, but the report must
		// never print a raw secret even if they forget.
		masked := c.Masked()
		view.Credentials = append(view.Credentials, credentialView{
			HostPort:   endpointText(masked.Address, masked.Port),
			Domain:     orDash(masked.Domain),
			Username:   orDash(masked.Username),
			Secret:     masked.Secret,
			Method:     orDash(masked.Method),
			VerifiedAt: orDash(formatTime(masked.VerifiedAt)),
		})
	}
	for _, s := range reportScreens(d.Screens) {
		row := screenshotView{
			FilePath:   orDash(s.FilePath),
			HostPort:   endpointText(s.Address, s.Port),
			Username:   orDash(s.Username),
			Label:      screenshotLabel(s.Username),
			CapturedAt: orDash(formatTime(s.CapturedAt)),
		}
		if uri, err := loadScreenshotDataURI(s.FilePath); err == nil {
			row.ImageDataURI = template.URL(uri)
			row.HasImage = true
		}
		view.Screenshots = append(view.Screenshots, row)
	}
	return view
}

// summaryCards builds the executive summary counters.
func summaryCards(d Data) []cardView {
	extra := computeExecutiveExtras(d)
	cards := []cardView{
		{Label: "Hardening Score", Value: int64(d.HardeningScore)},
		{Label: "Hosts Total", Value: d.Summary.HostsTotal},
		{Label: "Hosts Open", Value: d.Summary.HostsOpen},
		{Label: "NLA Coverage %", Value: extra.NLACoveragePct},
		{Label: "Open Findings", Value: extra.OpenVulnerable},
		{Label: "Hosts Auth Audited", Value: extra.HostsAudited},
		{Label: "Auth Skipped (no CredSSP)", Value: extra.AuthSkippedNoNLA},
	}
	for _, bucket := range severityBuckets(d) {
		cards = append(cards, cardView{
			Label: "Findings " + bucket.Severity,
			Value: bucket.Count,
			Class: bucket.Class,
		})
	}
	cards = append(cards,
		cardView{Label: "Credentials Found", Value: d.Summary.CredsTotal},
		cardView{Label: "Screenshots", Value: int64(len(reportScreens(d.Screens)))},
	)
	return cards
}

// hostRow renders one host with display-ready protocol and certificate fields.
func hostRow(h model.Host) hostView {
	row := hostView{
		Address:     orDash(h.Endpoint.Address),
		Port:        strconv.FormatUint(uint64(h.Endpoint.Port), 10),
		State:       orDash(h.State),
		NLA:         "-",
		Protocol:    "-",
		TLSVersion:  "-",
		Certificate: "-",
		OSGuess:     "-",
	}
	if h.Service == nil {
		return row
	}
	svc := h.Service
	if svc.NLARequired {
		row.NLA = "required"
	} else {
		row.NLA = "not required"
	}
	row.Protocol = protocolName(svc.NegotiatedProtocol)
	if svc.TLSVersion != "" {
		row.TLSVersion = svc.TLSVersion
	}
	if svc.OSGuess != "" {
		row.OSGuess = svc.OSGuess
	}
	if svc.Certificate != nil {
		row.Certificate = orDash(svc.Certificate.Subject)
		if svc.Certificate.SelfSigned {
			row.Certificate += " (self-signed)"
		}
	}
	return row
}
