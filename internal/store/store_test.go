package store

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

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

func TestDeleteScanRemovesChildren(t *testing.T) {
	s := openTestStore(t)
	if err := s.CreateScan(sampleScan("s-del")); err != nil {
		t.Fatalf("create scan: %v", err)
	}
	hostID, err := s.UpsertHost(model.Host{
		ScanID:    "s-del",
		Endpoint:  model.Endpoint{Address: "10.0.0.1", Port: 3389},
		State:     "open",
		UpdatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("upsert host: %v", err)
	}
	if _, err := s.InsertFinding(model.Finding{
		ScanID: "s-del", HostID: hostID, Address: "10.0.0.1", Port: 3389,
		CheckID: "rdp-service-exposed", Title: "exposed", Severity: model.SeverityInfo,
		Status: model.FindingVulnerable, DetectedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("insert finding: %v", err)
	}
	if err := s.DeleteScan("s-del"); err != nil {
		t.Fatalf("delete scan: %v", err)
	}
	if _, err := s.GetScan("s-del"); !errors.Is(err, ErrScanNotFound) {
		t.Fatalf("get deleted scan err = %v, want ErrScanNotFound", err)
	}
	findings, err := s.ListFindings("s-del")
	if err != nil {
		t.Fatalf("list findings: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings after delete, got %d", len(findings))
	}
	hosts, err := s.ListHosts("s-del")
	if err != nil {
		t.Fatalf("list hosts: %v", err)
	}
	if len(hosts) != 0 {
		t.Fatalf("expected no hosts after delete, got %d", len(hosts))
	}
}

func TestPurgeOrphanHostsAndSummary(t *testing.T) {
	s := openTestStore(t)
	if err := s.CreateScan(sampleScan("s-keep")); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.UpsertHost(model.Host{
		ScanID: "s-keep", Endpoint: model.Endpoint{Address: "10.0.0.1", Port: 3389},
		State: "open", UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("host keep: %v", err)
	}
	// Simulate an interrupted delete: child rows without a parent scan.
	if _, err := s.db.Exec(
		`INSERT INTO hosts (scan_id, address, port, state, service_json, updated_at)
		 VALUES ('s-gone', '10.0.0.9', 3389, 'open', '{}', ?)`,
		time.Now().UTC().Format(time.RFC3339Nano),
	); err != nil {
		t.Fatalf("orphan host: %v", err)
	}
	sum, err := s.Summary("")
	if err != nil {
		t.Fatalf("summary before purge: %v", err)
	}
	if sum.HostsTotal != 1 || sum.HostsOpen != 1 {
		t.Fatalf("summary before purge = %+v, want hosts_total/open 1", sum)
	}
	n, err := s.PurgeOrphanScanChildren()
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if n < 1 {
		t.Fatalf("purged = %d, want >= 1", n)
	}
	sum, err = s.Summary("")
	if err != nil {
		t.Fatalf("summary after purge: %v", err)
	}
	if sum.HostsTotal != 1 {
		t.Fatalf("summary after purge = %+v", sum)
	}
}

func TestRenameScan(t *testing.T) {
	s := openTestStore(t)
	if err := s.CreateScan(sampleScan("s-ren")); err != nil {
		t.Fatalf("create scan: %v", err)
	}
	if err := s.RenameScan("s-ren", "renamed audit"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	got, err := s.GetScan("s-ren")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "renamed audit" {
		t.Fatalf("name = %q", got.Name)
	}
}

func TestAnalyticsDeduplicatesHosts(t *testing.T) {
	s := openTestStore(t)
	for _, id := range []string{"s-a", "s-b"} {
		if err := s.CreateScan(sampleScan(id)); err != nil {
			t.Fatalf("create scan: %v", err)
		}
		if _, err := s.UpsertHost(model.Host{
			ScanID:   id,
			Endpoint: model.Endpoint{Address: "10.0.0.8", Port: 3389},
			State:    "open",
			Service: &model.ServiceInfo{
				NLARequired: false,
				TLSVersion:  "TLS 1.0",
				OSGuess:     "Windows Server",
				Certificate: &model.CertificateInfo{SelfSigned: true},
			},
			UpdatedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("upsert host: %v", err)
		}
		if _, err := s.InsertFinding(model.Finding{
			ScanID: id, Address: "10.0.0.8", Port: 3389,
			CheckID: "nla-not-required", Title: "NLA missing",
			Severity: model.SeverityHigh, Status: model.FindingVulnerable,
			CVSS: 7.5, DetectedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("insert finding: %v", err)
		}
	}

	a, err := s.Analytics()
	if err != nil {
		t.Fatalf("analytics: %v", err)
	}
	if a.HostsScanned != 1 || a.HostsOpen != 1 {
		t.Fatalf("hosts scanned/open = %d/%d, want 1/1", a.HostsScanned, a.HostsOpen)
	}
	if a.NLAMissing != 1 || a.LegacyTLS != 1 || a.SelfSigned != 1 {
		t.Fatalf("posture counters = %+v", a)
	}
	if len(a.TopHosts) != 1 || a.TopHosts[0].Findings != 1 {
		t.Fatalf("top hosts = %+v", a.TopHosts)
	}
}

func TestDiffScans(t *testing.T) {
	s := openTestStore(t)
	for _, id := range []string{"base", "next"} {
		if err := s.CreateScan(sampleScan(id)); err != nil {
			t.Fatalf("create: %v", err)
		}
	}
	if _, err := s.UpsertHost(model.Host{
		ScanID: "base", Endpoint: model.Endpoint{Address: "10.0.0.1", Port: 3389},
		State: "open", UpdatedAt: time.Now().UTC(),
		Service: &model.ServiceInfo{NLARequired: false, TLSVersion: "TLS 1.0"},
	}); err != nil {
		t.Fatalf("host base: %v", err)
	}
	if _, err := s.UpsertHost(model.Host{
		ScanID: "next", Endpoint: model.Endpoint{Address: "10.0.0.1", Port: 3389},
		State: "open", UpdatedAt: time.Now().UTC(),
		Service: &model.ServiceInfo{NLARequired: true, TLSVersion: "TLS 1.2"},
	}); err != nil {
		t.Fatalf("host next: %v", err)
	}
	if _, err := s.UpsertHost(model.Host{
		ScanID: "next", Endpoint: model.Endpoint{Address: "10.0.0.2", Port: 3389},
		State: "open", UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("host added: %v", err)
	}
	if _, err := s.InsertFinding(model.Finding{
		ScanID: "base", Address: "10.0.0.1", Port: 3389, CheckID: "nla-not-required",
		Title: "NLA", Severity: model.SeverityHigh, Status: model.FindingVulnerable,
		DetectedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("finding: %v", err)
	}

	diff, err := s.DiffScans("base", "next")
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if diff.Summary.HostsAdded != 1 || diff.Summary.HostsChanged != 1 {
		t.Fatalf("host summary = %+v", diff.Summary)
	}
	if diff.Summary.FindingsRemoved != 1 {
		t.Fatalf("findings removed = %d", diff.Summary.FindingsRemoved)
	}
	if diff.Summary.FindingsRemediated != 1 {
		t.Fatalf("findings remediated = %d", diff.Summary.FindingsRemediated)
	}
}

func TestAuthAttemptsLifecycle(t *testing.T) {
	s := openTestStore(t)
	if err := s.CreateScan(sampleScan("s-auth")); err != nil {
		t.Fatalf("create: %v", err)
	}
	id, err := s.InsertAuthAttempt(model.AuthAttempt{
		ScanID: "s-auth", HostID: 1, Address: "10.0.0.1", Port: 3389,
		Username: "admin", Domain: "LAB", Outcome: model.AuthOutcomeInvalid,
		Detail: "invalid credentials", AttemptedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if id == 0 {
		t.Fatal("expected non-zero id")
	}
	got, err := s.ListAuthAttempts("s-auth")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0].Username != "admin" || got[0].Outcome != model.AuthOutcomeInvalid {
		t.Fatalf("got = %+v", got)
	}
}

func TestScheduleLifecycle(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().UTC()
	next := now.Add(time.Hour)
	sch := model.Schedule{
		ID: "sched-1", Name: "nightly", Enabled: true, IntervalSeconds: 3600,
		Options:   model.ScanOptions{Targets: []string{"10.0.0.0/24"}, Ports: []uint16{3389}},
		CreatedAt: now, UpdatedAt: now, NextRunAt: &next,
	}
	if err := s.CreateSchedule(sch); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.GetSchedule("sched-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "nightly" || got.IntervalSeconds != 3600 {
		t.Fatalf("got = %+v", got)
	}
	due, err := s.DueSchedules(now.Add(2 * time.Hour))
	if err != nil {
		t.Fatalf("due: %v", err)
	}
	if len(due) != 1 {
		t.Fatalf("due = %d", len(due))
	}
	if err := s.DeleteSchedule("sched-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

// TestMigrateFromV2Shape reproduces a pre-v3 database whose findings/scans
// tables lack the newer columns. Opening it must ALTER the tables before any
// index that references triage_status / engagement is created.
func TestMigrateFromV2Shape(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v2.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	_, err = db.Exec(`
CREATE TABLE scans (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT,
  options_json TEXT NOT NULL,
  progress_json TEXT NOT NULL,
  error TEXT
);
CREATE TABLE findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  host_id INTEGER NOT NULL,
  address TEXT NOT NULL,
  port INTEGER NOT NULL,
  check_id TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  status TEXT NOT NULL,
  cvss REAL NOT NULL DEFAULT 0,
  cve TEXT,
  evidence TEXT,
  remediation TEXT,
  detected_at TEXT NOT NULL
);
CREATE TABLE schedules (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  interval_seconds INTEGER NOT NULL,
  options_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_run_at TEXT,
  next_run_at TEXT,
  last_scan_id TEXT,
  last_error TEXT
);
PRAGMA user_version = 2;
`)
	if err != nil {
		t.Fatalf("seed v2 schema: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close raw db: %v", err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open migrated store: %v", err)
	}
	defer s.Close()

	ok, err := s.hasColumn("findings", "triage_status")
	if err != nil || !ok {
		t.Fatalf("triage_status missing after migrate: ok=%v err=%v", ok, err)
	}
	ok, err = s.hasColumn("scans", "engagement")
	if err != nil || !ok {
		t.Fatalf("engagement missing after migrate: ok=%v err=%v", ok, err)
	}

	sc := sampleScan("migrated-1")
	if err := s.CreateScan(sc); err != nil {
		t.Fatalf("create scan after migrate: %v", err)
	}
	if _, err := s.InsertFinding(model.Finding{
		ScanID: sc.ID, HostID: 1, Address: "10.0.0.1", Port: 3389,
		CheckID: "rdp-service-exposed", Title: "exposed", Severity: model.SeverityInfo,
		Status: model.FindingVulnerable, DetectedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("insert finding after migrate: %v", err)
	}
}
