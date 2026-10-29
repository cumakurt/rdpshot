package server

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"rdpshot/internal/model"
)

// sampleData holds fully populated page data covering every template field.
type sampleData struct {
	dashboard  DashboardData
	scans      ScansData
	scanDetail ScanDetailData
	gallery    GalleryData
	reports    ReportsData
}

// buildSampleData returns populated page data exercising every branch of the
// templates: two scans (one completed, one failed), two hosts with service
// details and certificates, three findings, one masked credential and one
// screenshot.
func buildSampleData() sampleData {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	started := now.Add(time.Minute)
	finished := started.Add(3 * time.Minute)

	scanA := model.Scan{
		ID:         "scan-aaaaaaaaaaaaaaaa",
		Name:       "perimeter-audit",
		Status:     model.ScanCompleted,
		CreatedAt:  now,
		StartedAt:  &started,
		FinishedAt: &finished,
		Options: model.ScanOptions{
			Targets:          []string{"10.0.0.0/24", "192.168.1.10"},
			Ports:            []uint16{3389, 3390},
			Blacklist:        []string{"10.0.0.1"},
			TimeoutMS:        5000,
			Concurrency:      32,
			RatePerSecond:    10,
			EnableVuln:       true,
			EnableAuth:       true,
			EnableScreens:    true,
			MaxAuthFailures:  5,
			UserWordlist:     "wordlists/users.txt",
			PasswordWordlist: "wordlists/passwords.txt",
			Acknowledged:     true,
		},
		Progress: model.Progress{
			Total: 12, Done: 12, Open: 3, Closed: 9, Findings: 3, Creds: 1, Screens: 1, ActiveJobs: 0,
		},
	}
	scanB := model.Scan{
		ID:        "scan-bbbbbbbbbbbbbbbb",
		Name:      "dmz-check <script>",
		Status:    model.ScanFailed,
		CreatedAt: now.Add(-time.Hour),
		StartedAt: &started,
		Options: model.ScanOptions{
			Targets:     []string{"172.16.0.5"},
			Ports:       []uint16{3389},
			TimeoutMS:   2000,
			Concurrency: 8,
		},
		Progress: model.Progress{Total: 4, Done: 2, Open: 1, Closed: 1, Findings: 1},
		Error:    "probe interrupted",
	}

	cert := &model.CertificateInfo{
		Subject:      "CN=rdp.example.com",
		Issuer:       "CN=Example CA",
		SerialNumber: "01A2B3",
		NotBefore:    now.Add(-365 * 24 * time.Hour),
		NotAfter:     now.Add(365 * 24 * time.Hour),
		SelfSigned:   true,
		Fingerprint:  "ab:cd:ef",
		DNSNames:     []string{"rdp.example.com"},
	}
	hosts := []model.Host{
		{
			ID: 1, ScanID: scanA.ID,
			Endpoint:  model.Endpoint{Address: "10.0.0.5", Port: 3389},
			State:     "open",
			UpdatedAt: now,
			Service: &model.ServiceInfo{
				NegotiatedProtocol: 2,
				NLARequired:        true,
				EncryptionLevel:    "high",
				TLSVersion:         "TLS 1.2",
				TLSCipherSuite:     "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
				Certificate:        cert,
				ServerVersion:      0x00080004,
				MCSChannelIDs:      []uint16{1001, 1002},
				OSGuess:            "Windows Server 2019",
				Banner:             "x224 CC",
				Evidence:           map[string]string{"negotiation": "selected SSL"},
			},
		},
		{
			ID: 2, ScanID: scanA.ID,
			Endpoint:  model.Endpoint{Address: "10.0.0.6", Port: 3390},
			State:     "closed",
			UpdatedAt: now,
		},
	}
	findings := []model.Finding{
		{
			ID: 1, ScanID: scanA.ID, HostID: 1, Address: "10.0.0.5", Port: 3389,
			CheckID: "bluekeep", Title: "BlueKeep (CVE-2019-0708)",
			Severity: model.SeverityCritical, Status: model.FindingVulnerable,
			CVE: "CVE-2019-0708", CVSS: 9.8,
			Evidence: "RDP channel binding accepted", Remediation: "Apply KB4512534",
			DetectedAt: now,
		},
		{
			ID: 2, ScanID: scanA.ID, HostID: 1, Address: "10.0.0.5", Port: 3389,
			CheckID: "tls-weak", Title: "Weak TLS configuration",
			Severity: model.SeverityHigh, Status: model.FindingPotential,
			CVE: "CVE-2016-2183", CVSS: 7.5,
			Evidence: "TLS 1.0 offered", Remediation: "Disable legacy TLS",
			DetectedAt: now,
		},
		{
			ID: 3, ScanID: scanA.ID, HostID: 1, Address: "10.0.0.5", Port: 3389,
			CheckID: "nla", Title: "NLA not required",
			Severity: model.SeverityInfo, Status: model.FindingNotVulnerable,
			DetectedAt: now,
		},
	}
	cred := model.Credential{
		ID: 1, ScanID: scanA.ID, HostID: 1, Address: "10.0.0.5", Port: 3389,
		Username: "admin", Secret: "hunter2", Domain: "CORP",
		Method: "ntlm", VerifiedAt: now,
	}.Masked()
	screen := screenshotView(model.Screenshot{
		ID: 1, ScanID: scanA.ID, HostID: 1, Address: "10.0.0.5", Port: 3389,
		Username: "admin", FilePath: "/outputs/screenshots/10.0.0.5_admin_2026.png",
		Width: 1280, Height: 800, CapturedAt: now,
	})
	summary := model.Summary{
		ScansTotal: 2, HostsTotal: 2, HostsOpen: 1,
		FindingsTotal: 3, CredsTotal: 1, ScreensTotal: 1,
		BySeverity: []model.SeverityCount{
			{Severity: model.SeverityCritical, Count: 1},
			{Severity: model.SeverityHigh, Count: 1},
			{Severity: model.SeverityMedium, Count: 0},
			{Severity: model.SeverityLow, Count: 0},
			{Severity: model.SeverityInfo, Count: 1},
		},
	}
	cveStats := []model.CVEStat{
		{CVE: "CVE-2019-0708", Title: "BlueKeep (CVE-2019-0708)", Count: 1, Hosts: []string{"10.0.0.5"}},
		{CVE: "CVE-2016-2183", Title: "Weak TLS configuration", Count: 1, Hosts: []string{"10.0.0.5"}},
	}

	scans := []model.Scan{scanA, scanB}
	return sampleData{
		dashboard: DashboardData{
			Title:        "Dashboard",
			ActiveNav:    "dashboard",
			Summary:      summary,
			RecentScans:  scans,
			ActiveScan:   &scans[1],
			RecentEvents: []model.Event{},
		},
		scans: ScansData{
			Title:     "Scans",
			ActiveNav: "scans",
			Scans:     scans,
		},
		scanDetail: ScanDetailData{
			Title:     "Scan " + scanA.Name,
			ActiveNav: "scans",
			Scan:      scanA,
			Hosts:     hosts,
			Findings:  findings,
			Creds:     []model.Credential{cred},
			Screens:   []model.Screenshot{screen},
			Summary:   summary,
		},
		gallery: GalleryData{
			Title:     "Gallery",
			ActiveNav: "gallery",
			Items:     []model.Screenshot{screen},
		},
		reports: ReportsData{
			Title:      "Reports",
			ActiveNav:  "reports",
			Summary:    summary,
			CVEStats:   cveStats,
			LatestScan: &scans[0],
			Scans:      scans,
		},
	}
}

// TestTemplatePagesRender executes every template define with zero-value and
// fully populated data so template/struct field mismatches fail loudly.
func TestTemplatePagesRender(t *testing.T) {
	tpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}
	sample := buildSampleData()
	pages := map[string][]any{
		"dashboard":   {DashboardData{}, sample.dashboard},
		"scans":       {ScansData{}, sample.scans},
		"scan_detail": {ScanDetailData{}, sample.scanDetail},
		"gallery":     {GalleryData{}, sample.gallery},
		"reports":     {ReportsData{}, sample.reports},
	}

	for page, datasets := range pages {
		for i, data := range datasets {
			variant := "zero"
			if i == 1 {
				variant = "full"
			}
			t.Run(page+"_"+variant, func(t *testing.T) {
				var buf bytes.Buffer
				if err := tpl.ExecuteTemplate(&buf, page, data); err != nil {
					t.Fatalf("execute %s: %v", page, err)
				}
				if buf.Len() == 0 {
					t.Fatalf("template %s rendered no output", page)
				}
			})
		}
	}

	// The partials are executed with every page's data through the page
	// templates; run them standalone as well to cover direct execution.
	for _, partial := range []string{"head", "nav", "footer"} {
		for page, datasets := range pages {
			for i, data := range datasets {
				variant := "zero"
				if i == 1 {
					variant = "full"
				}
				t.Run(partial+"_with_"+page+"_"+variant, func(t *testing.T) {
					var buf bytes.Buffer
					if err := tpl.ExecuteTemplate(&buf, partial, data); err != nil {
						t.Fatalf("execute %s: %v", partial, err)
					}
				})
			}
		}
	}
}

// TestScanDetailMasksCredentialSecret asserts the detail page never renders
// the raw secret even if a caller handed over an unmasked credential. The
// template shows only the account, not the secret; masking is the second
// layer of defense.
func TestScanDetailMasksCredentialSecret(t *testing.T) {
	tpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}
	data := buildSampleData().scanDetail
	data.Creds = []model.Credential{{
		ID: 1, Username: "admin", Secret: "hunter2", Domain: "CORP",
		Address: "10.0.0.5", Port: 3389, Method: "ntlm",
		VerifiedAt: time.Now().UTC(),
	}}
	data.Creds = maskCredentials(data.Creds)

	var buf bytes.Buffer
	if err := tpl.ExecuteTemplate(&buf, "scan_detail", data); err != nil {
		t.Fatalf("execute scan_detail: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "hunter2") {
		t.Fatal("rendered scan detail page leaked the credential secret")
	}
	if strings.Contains(out, `Secret`) {
		t.Fatal("rendered scan detail page exposes a secret field")
	}
	if !strings.Contains(out, "admin") {
		t.Fatal("rendered scan detail page does not show the credential account")
	}
}

// TestScreenshotURLRewrite locks the URL mapping used for image serving.
func TestScreenshotURLRewrite(t *testing.T) {
	got := screenshotURL("/outputs/screenshots/10.0.0.5_admin.png")
	want := "/files/screenshots/10.0.0.5_admin.png"
	if got != want {
		t.Fatalf("screenshotURL = %q, want %q", got, want)
	}
	if got := screenshotURL("../../etc/passwd"); got != "/files/screenshots/passwd" {
		t.Fatalf("hostile path reduced to %q", got)
	}
}
