package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"rdpshot/internal/model"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func sampleScan(id string) model.Scan {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	return model.Scan{
		ID:        id,
		Name:      "scan-" + id,
		Status:    model.ScanPending,
		CreatedAt: now,
		Options: model.ScanOptions{
			Targets:     []string{"10.0.0.0/24"},
			Ports:       []uint16{3389},
			Concurrency: 8,
		},
		Progress: model.Progress{Total: 254},
	}
}

func TestScanLifecycle(t *testing.T) {
	s := openTestStore(t)
	sc := sampleScan("s1")
	if err := s.CreateScan(sc); err != nil {
		t.Fatalf("create scan: %v", err)
	}
	got, err := s.GetScan("s1")
	if err != nil {
		t.Fatalf("get scan: %v", err)
	}
	if got.Name != sc.Name || got.Options.Concurrency != 8 || got.Progress.Total != 254 {
		t.Fatalf("scan mismatch: %+v", got)
	}

	started := time.Date(2026, 10, 29, 12, 1, 0, 0, time.UTC)
	got.Status = model.ScanRunning
	got.StartedAt = &started
	got.Progress.Done = 10
	if err := s.UpdateScan(got); err != nil {
		t.Fatalf("update scan: %v", err)
	}
	updated, err := s.GetScan("s1")
	if err != nil {
		t.Fatalf("get scan: %v", err)
	}
	if updated.Status != model.ScanRunning || updated.Progress.Done != 10 {
		t.Fatalf("update not applied: %+v", updated)
	}
	if updated.StartedAt == nil || !updated.StartedAt.Equal(started) {
		t.Fatalf("started_at not preserved: %v", updated.StartedAt)
	}
}

func TestGetScanNotFound(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.GetScan("missing"); !errors.Is(err, ErrScanNotFound) {
		t.Fatalf("err = %v, want ErrScanNotFound", err)
	}
}

func TestUpdateScanNotFound(t *testing.T) {
	s := openTestStore(t)
	if err := s.UpdateScan(sampleScan("missing")); !errors.Is(err, ErrScanNotFound) {
		t.Fatalf("err = %v, want ErrScanNotFound", err)
	}
}

func TestListScansNewestFirst(t *testing.T) {
	s := openTestStore(t)
	first := sampleScan("s1")
	second := sampleScan("s2")
	second.CreatedAt = first.CreatedAt.Add(time.Hour)
	for _, sc := range []model.Scan{first, second} {
		if err := s.CreateScan(sc); err != nil {
			t.Fatalf("create scan: %v", err)
		}
	}
	scans, err := s.ListScans(0)
	if err != nil {
		t.Fatalf("list scans: %v", err)
	}
	if len(scans) != 2 || scans[0].ID != "s2" {
		t.Fatalf("unexpected order: %+v", scans)
	}
}

func TestUpsertHostIsIdempotent(t *testing.T) {
	s := openTestStore(t)
	host := model.Host{
		ScanID:    "s1",
		Endpoint:  model.Endpoint{Address: "10.0.0.1", Port: 3389},
		State:     "open",
		Service:   &model.ServiceInfo{NLARequired: true, TLSVersion: "TLS 1.2"},
		UpdatedAt: time.Now().UTC(),
	}
	id1, err := s.UpsertHost(host)
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	host.Service.NLARequired = false
	id2, err := s.UpsertHost(host)
	if err != nil {
		t.Fatalf("upsert again: %v", err)
	}
	if id1 != id2 {
		t.Fatalf("upsert changed row id: %d != %d", id1, id2)
	}
	hosts, err := s.ListHosts("s1")
	if err != nil {
		t.Fatalf("list hosts: %v", err)
	}
	if len(hosts) != 1 {
		t.Fatalf("expected single host, got %d", len(hosts))
	}
	if hosts[0].Service == nil || hosts[0].Service.NLARequired {
		t.Fatalf("service update not applied: %+v", hosts[0].Service)
	}
}

func TestFindingsAndSummary(t *testing.T) {
	s := openTestStore(t)
	findings := []model.Finding{
		{ScanID: "s1", HostID: 1, Address: "10.0.0.1", Port: 3389, CheckID: "bluekeep",
			Title: "BlueKeep", Severity: model.SeverityCritical, Status: model.FindingVulnerable,
			CVE: "CVE-2019-0708", CVSS: 9.8, DetectedAt: time.Now().UTC()},
		{ScanID: "s1", HostID: 1, Address: "10.0.0.1", Port: 3389, CheckID: "weak-tls",
			Title: "Weak TLS", Severity: model.SeverityMedium, Status: model.FindingPotential,
			DetectedAt: time.Now().UTC()},
		{ScanID: "s1", HostID: 2, Address: "10.0.0.2", Port: 3389, CheckID: "nla",
			Title: "NLA not required", Severity: model.SeverityHigh, Status: model.FindingVulnerable,
			CVE: "CVE-2019-0708", DetectedAt: time.Now().UTC()},
	}
	for _, f := range findings {
		if _, err := s.InsertFinding(f); err != nil {
			t.Fatalf("insert finding: %v", err)
		}
	}
	got, err := s.ListFindings("s1")
	if err != nil {
		t.Fatalf("list findings: %v", err)
	}
	if len(got) != 3 || got[0].Severity != model.SeverityCritical {
		t.Fatalf("unexpected findings order: %+v", got)
	}

	if _, err := s.InsertCredential(model.Credential{ScanID: "s1", HostID: 1, Address: "10.0.0.1",
		Port: 3389, Username: "Administrator", Secret: "redacted", Method: "credssp",
		VerifiedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("insert credential: %v", err)
	}
	if _, err := s.InsertScreenshot(model.Screenshot{ScanID: "s1", HostID: 1, Address: "10.0.0.1",
		Port: 3389, FilePath: "outputs/screenshots/a.png", CapturedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("insert screenshot: %v", err)
	}

	sum, err := s.Summary("s1")
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if sum.FindingsTotal != 3 || sum.CredsTotal != 1 || sum.ScreensTotal != 1 {
		t.Fatalf("unexpected summary: %+v", sum)
	}
	if sum.CountBySeverity(model.SeverityCritical) != 1 || sum.CountBySeverity(model.SeverityHigh) != 1 {
		t.Fatalf("severity distribution wrong: %+v", sum.BySeverity)
	}

	stats, err := s.CVEStats("s1")
	if err != nil {
		t.Fatalf("cve stats: %v", err)
	}
	if len(stats) != 1 || stats[0].CVE != "CVE-2019-0708" || stats[0].Count != 2 {
		t.Fatalf("unexpected cve stats: %+v", stats)
	}
	if len(stats[0].Hosts) != 2 {
		t.Fatalf("expected two affected hosts, got %v", stats[0].Hosts)
	}
}

func TestSummaryGlobal(t *testing.T) {
	s := openTestStore(t)
	for _, id := range []string{"s1", "s2"} {
		if err := s.CreateScan(sampleScan(id)); err != nil {
			t.Fatalf("create scan: %v", err)
		}
	}
	sum, err := s.Summary("")
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if sum.ScansTotal != 2 {
		t.Fatalf("expected 2 scans, got %+v", sum)
	}
	if len(sum.BySeverity) != 5 {
		t.Fatalf("expected 5 severity buckets, got %d", len(sum.BySeverity))
	}
}

func TestDatabaseFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "perm.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("database permissions = %o, want 600", perm)
	}
}
