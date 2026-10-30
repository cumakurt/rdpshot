package reporter

import (
	"bytes"
	"encoding/csv"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"rdpshot/internal/model"
)

const (
	testScanID    = "scan-42"
	testRawSecret = "hunter2-raw-secret"
)

// testReportData builds a synthetic report: 2 hosts, 3 findings across three
// severities, 1 credential and 1 screenshot.
func testReportData() Data {
	started := time.Date(2026, 10, 29, 9, 0, 0, 0, time.UTC)
	finished := time.Date(2026, 10, 29, 9, 30, 0, 0, time.UTC)
	return Data{
		Scan: model.Scan{
			ID:         testScanID,
			Name:       "Quarterly RDP Audit",
			Status:     model.ScanCompleted,
			CreatedAt:  started,
			StartedAt:  &started,
			FinishedAt: &finished,
			Options:    model.ScanOptions{Targets: []string{"10.0.0.0/24"}},
		},
		Summary: model.Summary{
			HostsTotal:    2,
			HostsOpen:     2,
			FindingsTotal: 3,
			CredsTotal:    1,
			ScreensTotal:  1,
			BySeverity: []model.SeverityCount{
				{Severity: model.SeverityCritical, Count: 1},
				{Severity: model.SeverityHigh, Count: 1},
				{Severity: model.SeverityInfo, Count: 1},
			},
		},
		Hosts: []model.Host{
			{
				Endpoint: model.Endpoint{Address: "10.0.0.1", Port: 3389},
				State:    "open",
				Service: &model.ServiceInfo{
					NegotiatedProtocol: 2,
					NLARequired:        true,
					TLSVersion:         "TLS 1.2",
					Certificate: &model.CertificateInfo{
						Subject:    "CN=10.0.0.1",
						SelfSigned: true,
					},
					OSGuess: "Windows Server 2019",
				},
			},
			{
				Endpoint: model.Endpoint{Address: "10.0.0.2", Port: 3389},
				State:    "open",
				Service: &model.ServiceInfo{
					NegotiatedProtocol: 1,
					NLARequired:        false,
					TLSVersion:         "TLS 1.0",
				},
			},
		},
		Findings: []model.Finding{
			{
				ScanID:      testScanID,
				Address:     "10.0.0.2",
				Port:        3389,
				CheckID:     "RDP-002",
				Title:       "Weak TLS version negotiated",
				Severity:    model.SeverityHigh,
				Status:      model.FindingVulnerable,
				Evidence:    "negotiated TLS 1.0",
				Remediation: "Disable TLS 1.0 on the RDP listener.",
			},
			{
				ScanID:   testScanID,
				Address:  "10.0.0.1",
				Port:     3389,
				CheckID:  "RDP-001",
				Title:    "Self-signed certificate presented",
				Severity: model.SeverityCritical,
				Status:   model.FindingVulnerable,
				CVE:      "CVE-2026-0001",
				CVSS:     9.1,
				// Target-derived payload must be escaped, never executed.
				Evidence:    "<script>alert('xss')</script> in cert subject",
				Remediation: "Replace the certificate with one issued by a trusted CA.",
			},
			{
				ScanID:   testScanID,
				Address:  "10.0.0.1",
				Port:     3389,
				CheckID:  "RDP-003",
				Title:    "NLA information",
				Severity: model.SeverityInfo,
				Status:   model.FindingNotVulnerable,
				// Multi-line evidence must be collapsed to one CSV line.
				Evidence:    "NLA required\nprotocol HYBRID",
				Remediation: "No action needed.",
			},
		},
		Credentials: []model.Credential{
			{
				ScanID:     testScanID,
				Address:    "10.0.0.1",
				Port:       3389,
				Username:   "administrator",
				Secret:     testRawSecret,
				Domain:     "CORP",
				Method:     "ntlm",
				VerifiedAt: time.Date(2026, 10, 29, 9, 15, 0, 0, time.UTC),
			},
		},
		Screens: []model.Screenshot{
			{
				ScanID:     testScanID,
				Address:    "10.0.0.1",
				Port:       3389,
				Username:   "administrator",
				FilePath:   "outputs/screens/10.0.0.1.png",
				CapturedAt: time.Date(2026, 10, 29, 9, 16, 0, 0, time.UTC),
			},
		},
		GeneratedAt: time.Date(2026, 10, 29, 10, 0, 0, 0, time.UTC),
		ToolVersion: "1.0.0",
	}
}

func TestCSV(t *testing.T) {
	d := testReportData()
	var buf bytes.Buffer
	if err := CSV(&buf, d); err != nil {
		t.Fatalf("CSV() error: %v", err)
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	const wantHeader = "scan_id,address,port,check_id,title,severity,status,cve,cvss,detected_at,evidence,remediation"
	if lines[0] != wantHeader {
		t.Fatalf("header mismatch:\ngot  %q\nwant %q", lines[0], wantHeader)
	}
	if len(lines) != 4 {
		t.Fatalf("want 1 header + 3 data rows, got %d lines", len(lines))
	}
	if strings.Contains(buf.String(), testRawSecret) {
		t.Error("csv output contains the raw secret")
	}

	records, err := csv.NewReader(bytes.NewReader(buf.Bytes())).ReadAll()
	if err != nil {
		t.Fatalf("csv output is not RFC 4180 parseable: %v", err)
	}
	if records[1][3] != "RDP-001" || records[2][3] != "RDP-002" || records[3][3] != "RDP-003" {
		t.Errorf("rows are not sorted by severity: got %q, %q, %q",
			records[1][3], records[2][3], records[3][3])
	}
	for _, record := range records[1:] {
		evidence := record[10]
		if strings.ContainsAny(evidence, "\r\n") {
			t.Errorf("evidence %q must stay on a single line", evidence)
		}
	}
}

func writeTestPNG(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "shot.png")
	img := image.NewRGBA(image.Rect(0, 0, 32, 24))
	for y := 0; y < 24; y++ {
		for x := 0; x < 32; x++ {
			img.Set(x, y, color.RGBA{R: 40, G: 120, B: 200, A: 255})
		}
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := png.Encode(f, img); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestHTML(t *testing.T) {
	d := testReportData()
	d.Screens[0].FilePath = writeTestPNG(t)
	d.Screens[0].Username = "rdp-login"
	var buf bytes.Buffer
	if err := HTML(&buf, d); err != nil {
		t.Fatalf("HTML() error: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "<!DOCTYPE html>") {
		t.Error("output is missing the HTML doctype")
	}
	if !strings.Contains(out, testScanID) {
		t.Error("output is missing the scan id")
	}
	for _, checkID := range []string{"RDP-001", "RDP-002", "RDP-003"} {
		if !strings.Contains(out, checkID) {
			t.Errorf("output is missing check id %q", checkID)
		}
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Error("evidence payload is not escaped")
	}
	if strings.Contains(out, "<script>") {
		t.Error("output contains a raw script tag from target data")
	}
	if strings.Contains(out, testRawSecret) {
		t.Error("html output contains the raw secret")
	}
	if !strings.Contains(out, `src="data:image/png;base64,`) {
		t.Error("html report must embed screenshot as data URI")
	}
	if !strings.Contains(out, "Login screen") {
		t.Error("html report missing login-screen caption")
	}
}

func TestPDF(t *testing.T) {
	d := testReportData()
	d.Screens[0].FilePath = writeTestPNG(t)
	var buf bytes.Buffer
	if err := PDF(&buf, d); err != nil {
		t.Fatalf("PDF() error: %v", err)
	}
	out := buf.Bytes()
	if !bytes.HasPrefix(out, []byte("%PDF")) {
		t.Error("pdf output does not start with %PDF")
	}
	if len(out) <= 1000 {
		t.Errorf("pdf output too small: %d bytes", len(out))
	}
}

func TestReportScreensOmitsSyntheticOpenHost(t *testing.T) {
	got := reportScreens([]model.Screenshot{
		{Username: "rdp-open", FilePath: "a.png"},
		{Username: "rdp-login", FilePath: "b.png"},
	})
	if len(got) != 1 || got[0].Username != "rdp-login" {
		t.Fatalf("got %#v", got)
	}
}

func TestEmptyData(t *testing.T) {
	d := Data{GeneratedAt: time.Date(2026, 10, 29, 10, 0, 0, 0, time.UTC), ToolVersion: "1.0.0"}

	var csvBuf bytes.Buffer
	if err := CSV(&csvBuf, d); err != nil {
		t.Fatalf("CSV() with empty data: %v", err)
	}
	if got := strings.Split(csvBuf.String(), "\n")[0]; got != "scan_id,address,port,check_id,title,severity,status,cve,cvss,detected_at,evidence,remediation" {
		t.Errorf("unexpected csv header %q", got)
	}

	var htmlBuf bytes.Buffer
	if err := HTML(&htmlBuf, d); err != nil {
		t.Fatalf("HTML() with empty data: %v", err)
	}
	if !strings.Contains(htmlBuf.String(), "<!DOCTYPE html>") {
		t.Error("empty html output is missing the doctype")
	}

	var pdfBuf bytes.Buffer
	if err := PDF(&pdfBuf, d); err != nil {
		t.Fatalf("PDF() with empty data: %v", err)
	}
	if !bytes.HasPrefix(pdfBuf.Bytes(), []byte("%PDF")) {
		t.Error("empty pdf output does not start with %PDF")
	}
}
