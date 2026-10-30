package engagement

import (
	"strings"
	"testing"
	"time"

	"rdpshot/internal/model"
	"rdpshot/internal/screenshot"
)

func TestAssemblePackV2(t *testing.T) {
	files, err := AssemblePack(PackInput{
		Scan:           model.Scan{ID: "s1", Name: "demo", Engagement: "acme"},
		ToolVersion:    "test",
		HardeningScore: 72,
		HardeningGrade: "C",
		Hosts: []model.Host{{
			ScanID: "s1", Endpoint: model.Endpoint{Address: "10.0.0.1", Port: 3389},
			State: "open",
		}},
		Findings: []model.Finding{{
			ScanID: "s1", CheckID: "nla-not-required", Title: "NLA",
			Severity: model.SeverityHigh, Status: model.FindingVulnerable,
			DetectedAt: time.Now().UTC(),
		}},
		Credentials: []model.Credential{{
			Username: "admin", Secret: "********", Method: "credssp-nla",
		}},
		AuthAttempts: []model.AuthAttempt{{
			Username: "admin", Outcome: model.AuthOutcomeInvalid,
		}},
		ReportHTML:  []byte("<html></html>"),
		FindingsCSV: []byte("a,b\n"),
		Screenshots: map[string][]byte{"screenshots/a.png": []byte("png")},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"meta.json", "hosts.json", "findings.json", "credentials-masked.json",
		"auth_attempts.json", "score.json", "report.html", "findings.csv",
		"screenshots/a.png", "PACK_README.txt",
	} {
		if _, ok := files[name]; !ok {
			t.Fatalf("missing %s", name)
		}
	}
	if !strings.Contains(string(files["PACK_README.txt"]), "evidence pack v2") {
		t.Fatalf("readme = %s", files["PACK_README.txt"])
	}
	m, err := BuildManifest(model.Scan{ID: "s1", Name: "demo"}, files)
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != PackVersion {
		t.Fatalf("manifest version = %q", m.Version)
	}
}

func TestFilterPackScreenshots(t *testing.T) {
	in := []model.Screenshot{
		{Username: screenshot.LoginScreenLabel, FilePath: "a.png"},
		{Username: screenshot.OpenHostLabel, FilePath: "b.png"},
		{Username: "admin", FilePath: "c.png"},
	}
	out := FilterPackScreenshots(in)
	if len(out) != 2 {
		t.Fatalf("out = %+v", out)
	}
	for _, sc := range out {
		if sc.Username == screenshot.OpenHostLabel {
			t.Fatal("rdp-open must be filtered")
		}
	}
}
