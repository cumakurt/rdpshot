// Package store persists scans, hosts, findings, credentials and screenshot
// metadata in an embedded SQLite database.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"rdpshot/internal/model"
)

// ErrScanNotFound is returned when a scan id does not exist.
var ErrScanNotFound = errors.New("store: scan not found")

// schemaVersion is the current on-disk schema revision.
const schemaVersion = 1

const schemaSQL = `
CREATE TABLE IF NOT EXISTS scans (
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
CREATE TABLE IF NOT EXISTS hosts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  address TEXT NOT NULL,
  port INTEGER NOT NULL,
  state TEXT NOT NULL,
  service_json TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(scan_id, address, port)
);
CREATE TABLE IF NOT EXISTS findings (
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
CREATE TABLE IF NOT EXISTS credentials (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  host_id INTEGER NOT NULL,
  address TEXT NOT NULL,
  port INTEGER NOT NULL,
  username TEXT NOT NULL,
  secret TEXT NOT NULL,
  domain TEXT,
  method TEXT NOT NULL,
  verified_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS screenshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  host_id INTEGER NOT NULL,
  address TEXT NOT NULL,
  port INTEGER NOT NULL,
  username TEXT,
  file_path TEXT NOT NULL,
  width INTEGER,
  height INTEGER,
  captured_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id, severity);
CREATE INDEX IF NOT EXISTS idx_hosts_scan ON hosts(scan_id);
CREATE INDEX IF NOT EXISTS idx_credentials_scan ON credentials(scan_id);
CREATE INDEX IF NOT EXISTS idx_screenshots_scan ON screenshots(scan_id);
`

// Store is the persistence layer.
type Store struct {
	db *sql.DB
}

// Open opens (creating when needed) the SQLite database at path. The database
// file is created with 0600 permissions because it may hold credentials.
func Open(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("store: create database directory: %w", err)
		}
	}
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open database: %w", err)
	}
	// A small pool avoids SQLITE_BUSY contention while still letting the web
	// readers run alongside the scanner writers; write transactions are short.
	db.SetMaxOpenConns(4)

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: restrict database permissions: %w", err)
	}
	return s, nil
}

func (s *Store) migrate() error {
	if _, err := s.db.Exec(schemaSQL); err != nil {
		return fmt.Errorf("store: apply schema: %w", err)
	}
	var current int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&current); err != nil {
		return fmt.Errorf("store: read schema version: %w", err)
	}
	if current > schemaVersion {
		return fmt.Errorf("store: database schema %d is newer than supported %d", current, schemaVersion)
	}
	if _, err := s.db.Exec(fmt.Sprintf("PRAGMA user_version = %d", schemaVersion)); err != nil {
		return fmt.Errorf("store: update schema version: %w", err)
	}
	return nil
}

// Close releases the database handle.
func (s *Store) Close() error {
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("store: close database: %w", err)
	}
	return nil
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func formatTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return formatTime(*t)
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func parseTimePtr(s string) *time.Time {
	if s == "" {
		return nil
	}
	t := parseTime(s)
	return &t
}

// CreateScan inserts a new scan record.
func (s *Store) CreateScan(sc model.Scan) error {
	options, err := json.Marshal(sc.Options)
	if err != nil {
		return fmt.Errorf("store: encode scan options: %w", err)
	}
	progress, err := json.Marshal(sc.Progress)
	if err != nil {
		return fmt.Errorf("store: encode scan progress: %w", err)
	}
	_, err = s.db.Exec(
		`INSERT INTO scans (id, name, status, created_at, started_at, finished_at, options_json, progress_json, error)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sc.ID, sc.Name, string(sc.Status), formatTime(sc.CreatedAt),
		formatTimePtr(sc.StartedAt), formatTimePtr(sc.FinishedAt),
		string(options), string(progress), sc.Error,
	)
	if err != nil {
		return fmt.Errorf("store: insert scan %q: %w", sc.ID, err)
	}
	return nil
}

// UpdateScan overwrites the mutable fields of a scan.
func (s *Store) UpdateScan(sc model.Scan) error {
	options, err := json.Marshal(sc.Options)
	if err != nil {
		return fmt.Errorf("store: encode scan options: %w", err)
	}
	progress, err := json.Marshal(sc.Progress)
	if err != nil {
		return fmt.Errorf("store: encode scan progress: %w", err)
	}
	res, err := s.db.Exec(
		`UPDATE scans SET name = ?, status = ?, started_at = ?, finished_at = ?,
		 options_json = ?, progress_json = ?, error = ? WHERE id = ?`,
		sc.Name, string(sc.Status), formatTimePtr(sc.StartedAt), formatTimePtr(sc.FinishedAt),
		string(options), string(progress), sc.Error, sc.ID,
	)
	if err != nil {
		return fmt.Errorf("store: update scan %q: %w", sc.ID, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: update scan %q: %w", sc.ID, err)
	}
	if affected == 0 {
		return fmt.Errorf("store: update scan %q: %w", sc.ID, ErrScanNotFound)
	}
	return nil
}

// GetScan loads one scan by id.
func (s *Store) GetScan(id string) (model.Scan, error) {
	row := s.db.QueryRow(
		`SELECT id, name, status, created_at, started_at, finished_at, options_json, progress_json, error
		 FROM scans WHERE id = ?`, id)
	return scanFromRow(row)
}

// ListScans returns the most recent scans, newest first.
func (s *Store) ListScans(limit int) ([]model.Scan, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(
		`SELECT id, name, status, created_at, started_at, finished_at, options_json, progress_json, error
		 FROM scans ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list scans: %w", err)
	}
	defer rows.Close()
	var scans []model.Scan
	for rows.Next() {
		sc, err := scanFromRow(rows)
		if err != nil {
			return nil, err
		}
		scans = append(scans, sc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list scans: %w", err)
	}
	return scans, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanFromRow(row rowScanner) (model.Scan, error) {
	var (
		sc         model.Scan
		status     string
		createdAt  string
		startedAt  sql.NullString
		finishedAt sql.NullString
		options    string
		progress   string
		errText    sql.NullString
	)
	err := row.Scan(&sc.ID, &sc.Name, &status, &createdAt, &startedAt, &finishedAt,
		&options, &progress, &errText)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Scan{}, fmt.Errorf("store: %w", ErrScanNotFound)
	}
	if err != nil {
		return model.Scan{}, fmt.Errorf("store: read scan: %w", err)
	}
	sc.Status = model.ScanStatus(status)
	sc.CreatedAt = parseTime(createdAt)
	sc.StartedAt = parseTimePtr(startedAt.String)
	sc.FinishedAt = parseTimePtr(finishedAt.String)
	sc.Error = errText.String
	if err := json.Unmarshal([]byte(options), &sc.Options); err != nil {
		return model.Scan{}, fmt.Errorf("store: decode scan options: %w", err)
	}
	if err := json.Unmarshal([]byte(progress), &sc.Progress); err != nil {
		return model.Scan{}, fmt.Errorf("store: decode scan progress: %w", err)
	}
	return sc, nil
}

// UpsertHost inserts or updates a host row and returns its id.
func (s *Store) UpsertHost(h model.Host) (int64, error) {
	service := ""
	if h.Service != nil {
		encoded, err := json.Marshal(h.Service)
		if err != nil {
			return 0, fmt.Errorf("store: encode service info: %w", err)
		}
		service = string(encoded)
	}
	updated := formatTime(h.UpdatedAt)
	if updated == "" {
		updated = formatTime(time.Now())
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("store: begin host upsert: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(
		`INSERT INTO hosts (scan_id, address, port, state, service_json, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(scan_id, address, port) DO UPDATE SET
		   state = excluded.state, service_json = excluded.service_json, updated_at = excluded.updated_at`,
		h.ScanID, h.Endpoint.Address, int(h.Endpoint.Port), h.State, service, updated,
	)
	if err != nil {
		return 0, fmt.Errorf("store: upsert host %s: %w", h.Endpoint.Key(), err)
	}
	var id int64
	err = tx.QueryRow(`SELECT id FROM hosts WHERE scan_id = ? AND address = ? AND port = ?`,
		h.ScanID, h.Endpoint.Address, int(h.Endpoint.Port)).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("store: read host id %s: %w", h.Endpoint.Key(), err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: commit host upsert: %w", err)
	}
	return id, nil
}

// ListHosts returns all hosts of a scan ordered by address and port.
func (s *Store) ListHosts(scanID string) ([]model.Host, error) {
	rows, err := s.db.Query(
		`SELECT id, scan_id, address, port, state, service_json, updated_at
		 FROM hosts WHERE scan_id = ? ORDER BY address, port`, scanID)
	if err != nil {
		return nil, fmt.Errorf("store: list hosts: %w", err)
	}
	defer rows.Close()
	var hosts []model.Host
	for rows.Next() {
		var (
			h           model.Host
			port        int
			serviceJSON string
			updatedAt   string
		)
		if err := rows.Scan(&h.ID, &h.ScanID, &h.Endpoint.Address, &port, &h.State, &serviceJSON, &updatedAt); err != nil {
			return nil, fmt.Errorf("store: read host: %w", err)
		}
		h.Endpoint.Port = uint16(port)
		h.UpdatedAt = parseTime(updatedAt)
		if serviceJSON != "" {
			var svc model.ServiceInfo
			if err := json.Unmarshal([]byte(serviceJSON), &svc); err != nil {
				return nil, fmt.Errorf("store: decode service info for host %d: %w", h.ID, err)
			}
			h.Service = &svc
		}
		hosts = append(hosts, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list hosts: %w", err)
	}
	return hosts, nil
}

// InsertFinding stores one finding and returns its id.
func (s *Store) InsertFinding(f model.Finding) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO findings (scan_id, host_id, address, port, check_id, title, severity, status,
		 cvss, cve, evidence, remediation, detected_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ScanID, f.HostID, f.Address, int(f.Port), f.CheckID, f.Title, string(f.Severity),
		string(f.Status), f.CVSS, f.CVE, f.Evidence, f.Remediation, formatTime(f.DetectedAt),
	)
	if err != nil {
		return 0, fmt.Errorf("store: insert finding %q: %w", f.CheckID, err)
	}
	return res.LastInsertId()
}

// ListFindings returns the findings of a scan sorted by severity (desc) and host.
func (s *Store) ListFindings(scanID string) ([]model.Finding, error) {
	rows, err := s.db.Query(
		`SELECT id, scan_id, host_id, address, port, check_id, title, severity, status,
		        cvss, cve, evidence, remediation, detected_at
		 FROM findings WHERE scan_id = ?
		 ORDER BY CASE severity
		   WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
		   WHEN 'low' THEN 2 ELSE 1 END DESC, address, port, check_id`, scanID)
	if err != nil {
		return nil, fmt.Errorf("store: list findings: %w", err)
	}
	defer rows.Close()
	var findings []model.Finding
	for rows.Next() {
		var (
			f           model.Finding
			port        int
			severity    string
			status      string
			cve         sql.NullString
			evidence    sql.NullString
			remediation sql.NullString
			detectedAt  string
		)
		if err := rows.Scan(&f.ID, &f.ScanID, &f.HostID, &f.Address, &port, &f.CheckID, &f.Title,
			&severity, &status, &f.CVSS, &cve, &evidence, &remediation, &detectedAt); err != nil {
			return nil, fmt.Errorf("store: read finding: %w", err)
		}
		f.Port = uint16(port)
		f.Severity = model.Severity(severity)
		f.Status = model.FindingStatus(status)
		f.CVE = cve.String
		f.Evidence = evidence.String
		f.Remediation = remediation.String
		f.DetectedAt = parseTime(detectedAt)
		findings = append(findings, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list findings: %w", err)
	}
	return findings, nil
}

// InsertCredential stores one verified credential and returns its id.
func (s *Store) InsertCredential(c model.Credential) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO credentials (scan_id, host_id, address, port, username, secret, domain, method, verified_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ScanID, c.HostID, c.Address, int(c.Port), c.Username, c.Secret, c.Domain, c.Method,
		formatTime(c.VerifiedAt),
	)
	if err != nil {
		return 0, fmt.Errorf("store: insert credential: %w", err)
	}
	return res.LastInsertId()
}

// ListCredentials returns the credentials of a scan, newest first.
func (s *Store) ListCredentials(scanID string) ([]model.Credential, error) {
	rows, err := s.db.Query(
		`SELECT id, scan_id, host_id, address, port, username, secret, domain, method, verified_at
		 FROM credentials WHERE scan_id = ? ORDER BY verified_at DESC`, scanID)
	if err != nil {
		return nil, fmt.Errorf("store: list credentials: %w", err)
	}
	defer rows.Close()
	var creds []model.Credential
	for rows.Next() {
		var (
			c          model.Credential
			port       int
			domain     sql.NullString
			verifiedAt string
		)
		if err := rows.Scan(&c.ID, &c.ScanID, &c.HostID, &c.Address, &port, &c.Username,
			&c.Secret, &domain, &c.Method, &verifiedAt); err != nil {
			return nil, fmt.Errorf("store: read credential: %w", err)
		}
		c.Port = uint16(port)
		c.Domain = domain.String
		c.VerifiedAt = parseTime(verifiedAt)
		creds = append(creds, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list credentials: %w", err)
	}
	return creds, nil
}

// InsertScreenshot stores screenshot metadata and returns its id.
func (s *Store) InsertScreenshot(sc model.Screenshot) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO screenshots (scan_id, host_id, address, port, username, file_path, width, height, captured_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sc.ScanID, sc.HostID, sc.Address, int(sc.Port), sc.Username, sc.FilePath, sc.Width, sc.Height,
		formatTime(sc.CapturedAt),
	)
	if err != nil {
		return 0, fmt.Errorf("store: insert screenshot: %w", err)
	}
	return res.LastInsertId()
}

// ListScreenshots returns screenshot metadata of a scan, newest first.
func (s *Store) ListScreenshots(scanID string) ([]model.Screenshot, error) {
	rows, err := s.db.Query(
		`SELECT id, scan_id, host_id, address, port, username, file_path, width, height, captured_at
		 FROM screenshots WHERE scan_id = ? ORDER BY captured_at DESC`, scanID)
	if err != nil {
		return nil, fmt.Errorf("store: list screenshots: %w", err)
	}
	defer rows.Close()
	var items []model.Screenshot
	for rows.Next() {
		var (
			sc         model.Screenshot
			port       int
			username   sql.NullString
			capturedAt string
		)
		if err := rows.Scan(&sc.ID, &sc.ScanID, &sc.HostID, &sc.Address, &port, &username,
			&sc.FilePath, &sc.Width, &sc.Height, &capturedAt); err != nil {
			return nil, fmt.Errorf("store: read screenshot: %w", err)
		}
		sc.Port = uint16(port)
		sc.Username = username.String
		sc.CapturedAt = parseTime(capturedAt)
		items = append(items, sc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list screenshots: %w", err)
	}
	return items, nil
}

// Summary aggregates counters. An empty scanID aggregates every scan.
func (s *Store) Summary(scanID string) (model.Summary, error) {
	var sum model.Summary
	where, args := "", []any{}
	if scanID != "" {
		where, args = " WHERE scan_id = ?", []any{scanID}
	}

	if scanID == "" {
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM scans`).Scan(&sum.ScansTotal); err != nil {
			return sum, fmt.Errorf("store: count scans: %w", err)
		}
	}
	counts := []struct {
		query string
		dst   *int64
	}{
		{`SELECT COUNT(*) FROM hosts` + where, &sum.HostsTotal},
		{`SELECT COUNT(*) FROM hosts` + andWhere(where, "state = 'open'"), &sum.HostsOpen},
		{`SELECT COUNT(*) FROM findings` + where, &sum.FindingsTotal},
		{`SELECT COUNT(*) FROM credentials` + where, &sum.CredsTotal},
		{`SELECT COUNT(*) FROM screenshots` + where, &sum.ScreensTotal},
	}
	for _, c := range counts {
		if err := s.db.QueryRow(c.query, args...).Scan(c.dst); err != nil {
			return sum, fmt.Errorf("store: aggregate summary: %w", err)
		}
	}

	rows, err := s.db.Query(`SELECT severity, COUNT(*) FROM findings`+where+` GROUP BY severity`, args...)
	if err != nil {
		return sum, fmt.Errorf("store: severity distribution: %w", err)
	}
	defer rows.Close()
	bySeverity := map[model.Severity]int64{}
	for rows.Next() {
		var (
			severity string
			count    int64
		)
		if err := rows.Scan(&severity, &count); err != nil {
			return sum, fmt.Errorf("store: read severity row: %w", err)
		}
		bySeverity[model.Severity(severity)] = count
	}
	if err := rows.Err(); err != nil {
		return sum, fmt.Errorf("store: severity distribution: %w", err)
	}
	for _, sev := range []model.Severity{
		model.SeverityCritical, model.SeverityHigh, model.SeverityMedium,
		model.SeverityLow, model.SeverityInfo,
	} {
		sum.BySeverity = append(sum.BySeverity, model.SeverityCount{Severity: sev, Count: bySeverity[sev]})
	}
	return sum, nil
}

// CVEStats groups findings by CVE identifier. An empty scanID aggregates every scan.
func (s *Store) CVEStats(scanID string) ([]model.CVEStat, error) {
	where, args := " WHERE cve IS NOT NULL AND cve != ''", []any{}
	if scanID != "" {
		where += " AND scan_id = ?"
		args = append(args, scanID)
	}
	rows, err := s.db.Query(
		`SELECT cve, MIN(title), COUNT(*) FROM findings`+where+
			` GROUP BY cve ORDER BY COUNT(*) DESC, cve`, args...)
	if err != nil {
		return nil, fmt.Errorf("store: cve stats: %w", err)
	}
	// Collect the aggregate rows before querying hosts: nested queries on a
	// single connection would deadlock.
	type aggregate struct {
		cve, title string
		count      int64
	}
	var aggregates []aggregate
	for rows.Next() {
		var a aggregate
		if err := rows.Scan(&a.cve, &a.title, &a.count); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: read cve stat: %w", err)
		}
		aggregates = append(aggregates, a)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("store: cve stats: %w", err)
	}
	rows.Close()

	var stats []model.CVEStat
	for _, a := range aggregates {
		hosts, err := s.cveHosts(a.cve, scanID)
		if err != nil {
			return nil, err
		}
		stats = append(stats, model.CVEStat{CVE: a.cve, Title: a.title, Count: a.count, Hosts: hosts})
	}
	return stats, nil
}

func (s *Store) cveHosts(cve, scanID string) ([]string, error) {
	query := `SELECT DISTINCT address FROM findings WHERE cve = ?`
	args := []any{cve}
	if scanID != "" {
		query += " AND scan_id = ?"
		args = append(args, scanID)
	}
	query += " ORDER BY address"
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: cve hosts: %w", err)
	}
	defer rows.Close()
	var hosts []string
	for rows.Next() {
		var address string
		if err := rows.Scan(&address); err != nil {
			return nil, fmt.Errorf("store: read cve host: %w", err)
		}
		hosts = append(hosts, address)
	}
	return hosts, rows.Err()
}

// andWhere appends an extra condition to an existing WHERE clause, preserving
// the leading space of the clause so query concatenation stays valid.
func andWhere(where, condition string) string {
	if strings.TrimSpace(where) == "" {
		return " WHERE " + condition
	}
	return where + " AND " + condition
}
