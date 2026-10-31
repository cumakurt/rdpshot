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
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"rdpshot/internal/model"
)

// ErrScanNotFound is returned when a scan id does not exist.
var ErrScanNotFound = errors.New("store: scan not found")

// schemaVersion is the current on-disk schema revision.
const schemaVersion = 6

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
  error TEXT,
  engagement TEXT NOT NULL DEFAULT '',
  tags_json TEXT NOT NULL DEFAULT '[]',
  schedule_id TEXT NOT NULL DEFAULT ''
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
  detected_at TEXT NOT NULL,
  triage_status TEXT NOT NULL DEFAULT 'open',
  triage_note TEXT NOT NULL DEFAULT '',
  triage_updated_at TEXT
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
CREATE TABLE IF NOT EXISTS schedules (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  interval_seconds INTEGER NOT NULL DEFAULT 0,
  cron_expr TEXT NOT NULL DEFAULT '',
  options_json TEXT NOT NULL,
  notify_webhook TEXT NOT NULL DEFAULT '',
  notify_on_complete INTEGER NOT NULL DEFAULT 0,
  notify_on_critical INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_run_at TEXT,
  next_run_at TEXT,
  last_scan_id TEXT,
  last_error TEXT
);
CREATE TABLE IF NOT EXISTS wordlist_sets (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  user_path TEXT NOT NULL,
  password_path TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '',
  remote_ip TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS host_notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  engagement TEXT NOT NULL DEFAULT '',
  address TEXT NOT NULL,
  port INTEGER NOT NULL,
  note TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL DEFAULT '',
  UNIQUE(engagement, address, port)
);
CREATE TABLE IF NOT EXISTS auth_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  host_id INTEGER NOT NULL,
  address TEXT NOT NULL,
  port INTEGER NOT NULL,
  username TEXT NOT NULL,
  domain TEXT NOT NULL DEFAULT '',
  outcome TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  attempted_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id, severity);
CREATE INDEX IF NOT EXISTS idx_hosts_scan ON hosts(scan_id);
CREATE INDEX IF NOT EXISTS idx_credentials_scan ON credentials(scan_id);
CREATE INDEX IF NOT EXISTS idx_screenshots_scan ON screenshots(scan_id);
CREATE INDEX IF NOT EXISTS idx_schedules_next ON schedules(enabled, next_run_at);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log(at);
CREATE INDEX IF NOT EXISTS idx_auth_attempts_scan ON auth_attempts(scan_id, attempted_at);
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
	// Always ensure v3 columns exist. CREATE TABLE IF NOT EXISTS leaves older
	// table shapes unchanged, and indexes that reference new columns must run
	// only after the ALTER TABLE steps below.
	if err := s.migrateToV3(); err != nil {
		return err
	}
	if err := s.migrateToV4(); err != nil {
		return err
	}
	if err := s.migrateToV5(); err != nil {
		return err
	}
	if err := s.migrateToV6(); err != nil {
		return err
	}
	if _, err := s.db.Exec(fmt.Sprintf("PRAGMA user_version = %d", schemaVersion)); err != nil {
		return fmt.Errorf("store: update schema version: %w", err)
	}
	// Heal dashboards after historical deletes that left child rows behind.
	if _, err := s.PurgeOrphanScanChildren(); err != nil {
		return err
	}
	return nil
}

// migrateToV5 adds auth_attempts for credential-audit timelines (no secrets).
func (s *Store) migrateToV5() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS auth_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  host_id INTEGER NOT NULL,
  address TEXT NOT NULL,
  port INTEGER NOT NULL,
  username TEXT NOT NULL,
  domain TEXT NOT NULL DEFAULT '',
  outcome TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  attempted_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_attempts_scan ON auth_attempts(scan_id, attempted_at);
`)
	if err != nil {
		return fmt.Errorf("store: migrate v5: %w", err)
	}
	return nil
}

// migrateToV6 adds decoy_events for the honeypot listener.
func (s *Store) migrateToV6() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS decoy_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  remote_addr TEXT NOT NULL,
  remote_ip TEXT NOT NULL,
  ntlm_username TEXT NOT NULL DEFAULT '',
  ntlm_domain TEXT NOT NULL DEFAULT '',
  raw TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_decoy_events_at ON decoy_events(at);
`)
	if err != nil {
		return fmt.Errorf("store: migrate v6: %w", err)
	}
	return nil
}

// migrateToV4 adds host_notes used by the engagement workspace.
func (s *Store) migrateToV4() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS host_notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  engagement TEXT NOT NULL DEFAULT '',
  address TEXT NOT NULL,
  port INTEGER NOT NULL,
  note TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL DEFAULT '',
  UNIQUE(engagement, address, port)
);
CREATE INDEX IF NOT EXISTS idx_host_notes_engagement ON host_notes(engagement);
`)
	if err != nil {
		return fmt.Errorf("store: migrate v4: %w", err)
	}
	return nil
}

// migrateToV3 adds engagement/triage/notification columns to databases created
// under schema v2 whose CREATE TABLE IF NOT EXISTS left the old shape intact.
func (s *Store) migrateToV3() error {
	alters := []struct {
		table, column, decl string
	}{
		{"scans", "engagement", "TEXT NOT NULL DEFAULT ''"},
		{"scans", "tags_json", "TEXT NOT NULL DEFAULT '[]'"},
		{"scans", "schedule_id", "TEXT NOT NULL DEFAULT ''"},
		{"findings", "triage_status", "TEXT NOT NULL DEFAULT 'open'"},
		{"findings", "triage_note", "TEXT NOT NULL DEFAULT ''"},
		{"findings", "triage_updated_at", "TEXT"},
		{"schedules", "cron_expr", "TEXT NOT NULL DEFAULT ''"},
		{"schedules", "notify_webhook", "TEXT NOT NULL DEFAULT ''"},
		{"schedules", "notify_on_complete", "INTEGER NOT NULL DEFAULT 0"},
		{"schedules", "notify_on_critical", "INTEGER NOT NULL DEFAULT 0"},
	}
	for _, a := range alters {
		ok, err := s.hasColumn(a.table, a.column)
		if err != nil {
			return err
		}
		if ok {
			continue
		}
		stmt := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", a.table, a.column, a.decl)
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("store: migrate v3 %s.%s: %w", a.table, a.column, err)
		}
	}
	// Indexes that depend on columns added above.
	for _, stmt := range []string{
		`CREATE INDEX IF NOT EXISTS idx_findings_triage ON findings(scan_id, triage_status)`,
		`CREATE INDEX IF NOT EXISTS idx_scans_engagement ON scans(engagement)`,
	} {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("store: migrate v3 index: %w", err)
		}
	}
	return nil
}

func (s *Store) hasColumn(table, column string) (bool, error) {
	rows, err := s.db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return false, fmt.Errorf("store: table_info %s: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false, fmt.Errorf("store: table_info scan %s: %w", table, err)
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
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
	tags, err := json.Marshal(normalizeTags(sc.Tags))
	if err != nil {
		return fmt.Errorf("store: encode scan tags: %w", err)
	}
	_, err = s.db.Exec(
		`INSERT INTO scans (id, name, status, created_at, started_at, finished_at, options_json, progress_json, error,
		 engagement, tags_json, schedule_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sc.ID, sc.Name, string(sc.Status), formatTime(sc.CreatedAt),
		formatTimePtr(sc.StartedAt), formatTimePtr(sc.FinishedAt),
		string(options), string(progress), sc.Error,
		strings.TrimSpace(sc.Engagement), string(tags), strings.TrimSpace(sc.ScheduleID),
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
	tags, err := json.Marshal(normalizeTags(sc.Tags))
	if err != nil {
		return fmt.Errorf("store: encode scan tags: %w", err)
	}
	res, err := s.db.Exec(
		`UPDATE scans SET name = ?, status = ?, started_at = ?, finished_at = ?,
		 options_json = ?, progress_json = ?, error = ?, engagement = ?, tags_json = ?, schedule_id = ?
		 WHERE id = ?`,
		sc.Name, string(sc.Status), formatTimePtr(sc.StartedAt), formatTimePtr(sc.FinishedAt),
		string(options), string(progress), sc.Error,
		strings.TrimSpace(sc.Engagement), string(tags), strings.TrimSpace(sc.ScheduleID), sc.ID,
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
		`SELECT id, name, status, created_at, started_at, finished_at, options_json, progress_json, error,
		        engagement, tags_json, schedule_id
		 FROM scans WHERE id = ?`, id)
	return scanFromRow(row)
}

// RenameScan updates the display name of an existing scan.
func (s *Store) RenameScan(id, name string) error {
	res, err := s.db.Exec(`UPDATE scans SET name = ? WHERE id = ?`, name, id)
	if err != nil {
		return fmt.Errorf("store: rename scan %q: %w", id, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: rename scan %q: %w", id, err)
	}
	if affected == 0 {
		return fmt.Errorf("store: rename scan %q: %w", id, ErrScanNotFound)
	}
	return nil
}

// DeleteScan removes a scan together with its hosts, findings, credentials,
// screenshot metadata and auth attempts. The deletes run in one transaction so
// a partial failure never leaves orphaned child rows behind.
func (s *Store) DeleteScan(id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: begin delete scan %q: %w", id, err)
	}
	defer tx.Rollback()

	for _, table := range []string{"findings", "credentials", "screenshots", "auth_attempts", "hosts"} {
		if _, err := tx.Exec(`DELETE FROM `+table+` WHERE scan_id = ?`, id); err != nil {
			return fmt.Errorf("store: delete scan %q: clear %s: %w", id, table, err)
		}
	}
	res, err := tx.Exec(`DELETE FROM scans WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete scan %q: %w", id, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: delete scan %q: %w", id, err)
	}
	if affected == 0 {
		return fmt.Errorf("store: delete scan %q: %w", id, ErrScanNotFound)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit delete scan %q: %w", id, err)
	}
	return nil
}

// PurgeOrphanScanChildren removes hosts/findings/credentials/screenshots/
// auth_attempts whose scan_id no longer exists in scans. Dashboard totals
// otherwise keep counting deleted audits.
func (s *Store) PurgeOrphanScanChildren() (int64, error) {
	var total int64
	for _, table := range []string{"findings", "credentials", "screenshots", "auth_attempts", "hosts"} {
		res, err := s.db.Exec(`DELETE FROM ` + table + ` WHERE scan_id NOT IN (SELECT id FROM scans)`)
		if err != nil {
			return total, fmt.Errorf("store: purge orphan %s: %w", table, err)
		}
		n, _ := res.RowsAffected()
		total += n
	}
	return total, nil
}

// ListScans returns the most recent scans, newest first.
func (s *Store) ListScans(limit int) ([]model.Scan, error) {
	if limit <= 0 {
		limit = 100
	}
	return s.listScans(limit)
}

// listScans returns scans newest first. A non-positive limit returns every
// scan, which the cross-scan analytics need.
func (s *Store) listScans(limit int) ([]model.Scan, error) {
	query := `SELECT id, name, status, created_at, started_at, finished_at, options_json, progress_json, error,
		 engagement, tags_json, schedule_id
		 FROM scans ORDER BY created_at DESC`
	var args []any
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}
	rows, err := s.db.Query(query, args...)
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
		engagement string
		tagsJSON   string
		scheduleID string
	)
	err := row.Scan(&sc.ID, &sc.Name, &status, &createdAt, &startedAt, &finishedAt,
		&options, &progress, &errText, &engagement, &tagsJSON, &scheduleID)
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
	sc.Engagement = engagement
	sc.ScheduleID = scheduleID
	if tagsJSON == "" {
		tagsJSON = "[]"
	}
	if err := json.Unmarshal([]byte(tagsJSON), &sc.Tags); err != nil {
		return model.Scan{}, fmt.Errorf("store: decode scan tags: %w", err)
	}
	if err := json.Unmarshal([]byte(options), &sc.Options); err != nil {
		return model.Scan{}, fmt.Errorf("store: decode scan options: %w", err)
	}
	if err := json.Unmarshal([]byte(progress), &sc.Progress); err != nil {
		return model.Scan{}, fmt.Errorf("store: decode scan progress: %w", err)
	}
	return sc, nil
}

func normalizeTags(tags []string) []string {
	if len(tags) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(tags))
	out := make([]string, 0, len(tags))
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		key := strings.ToLower(tag)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, tag)
	}
	return out
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

// GetHost loads one host by id.
func (s *Store) GetHost(id int64) (model.Host, error) {
	row := s.db.QueryRow(
		`SELECT id, scan_id, address, port, state, service_json, updated_at FROM hosts WHERE id = ?`, id)
	var (
		h           model.Host
		port        int
		serviceJSON string
		updatedAt   string
	)
	if err := row.Scan(&h.ID, &h.ScanID, &h.Endpoint.Address, &port, &h.State, &serviceJSON, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.Host{}, fmt.Errorf("store: get host %d: %w", id, ErrNotFound)
		}
		return model.Host{}, fmt.Errorf("store: get host %d: %w", id, err)
	}
	h.Endpoint.Port = uint16(port)
	h.UpdatedAt = parseTime(updatedAt)
	if serviceJSON != "" {
		var svc model.ServiceInfo
		if err := json.Unmarshal([]byte(serviceJSON), &svc); err != nil {
			return model.Host{}, fmt.Errorf("store: decode service info for host %d: %w", id, err)
		}
		h.Service = &svc
	}
	return h, nil
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
	triage := f.TriageStatus
	if triage == "" {
		triage = model.TriageOpen
	}
	res, err := s.db.Exec(
		`INSERT INTO findings (scan_id, host_id, address, port, check_id, title, severity, status,
		 cvss, cve, evidence, remediation, detected_at, triage_status, triage_note, triage_updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ScanID, f.HostID, f.Address, int(f.Port), f.CheckID, f.Title, string(f.Severity),
		string(f.Status), f.CVSS, f.CVE, f.Evidence, f.Remediation, formatTime(f.DetectedAt),
		string(triage), f.TriageNote, formatTimePtr(f.TriageUpdatedAt),
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
		        cvss, cve, evidence, remediation, detected_at,
		        triage_status, triage_note, triage_updated_at
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
		f, err := findingFromRow(rows)
		if err != nil {
			return nil, err
		}
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

// InsertAuthAttempt stores one credential-audit attempt without the secret.
func (s *Store) InsertAuthAttempt(a model.AuthAttempt) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO auth_attempts (scan_id, host_id, address, port, username, domain, outcome, detail, attempted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ScanID, a.HostID, a.Address, int(a.Port), a.Username, a.Domain, a.Outcome, a.Detail,
		formatTime(a.AttemptedAt),
	)
	if err != nil {
		return 0, fmt.Errorf("store: insert auth attempt: %w", err)
	}
	return res.LastInsertId()
}

// ListAuthAttempts returns credential-audit attempts for a scan, oldest first.
func (s *Store) ListAuthAttempts(scanID string) ([]model.AuthAttempt, error) {
	rows, err := s.db.Query(
		`SELECT id, scan_id, host_id, address, port, username, domain, outcome, detail, attempted_at
		 FROM auth_attempts WHERE scan_id = ? ORDER BY attempted_at ASC, id ASC`, scanID)
	if err != nil {
		return nil, fmt.Errorf("store: list auth attempts: %w", err)
	}
	defer rows.Close()
	var out []model.AuthAttempt
	for rows.Next() {
		var (
			a         model.AuthAttempt
			port      int
			attempted string
		)
		if err := rows.Scan(&a.ID, &a.ScanID, &a.HostID, &a.Address, &port, &a.Username,
			&a.Domain, &a.Outcome, &a.Detail, &attempted); err != nil {
			return nil, fmt.Errorf("store: read auth attempt: %w", err)
		}
		a.Port = uint16(port)
		a.AttemptedAt = parseTime(attempted)
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list auth attempts: %w", err)
	}
	return out, nil
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

// GetScreenshot fetches one screenshot by id.
func (s *Store) GetScreenshot(id int64) (model.Screenshot, error) {
	row := s.db.QueryRow(
		`SELECT id, scan_id, host_id, address, port, username, file_path, width, height, captured_at
		 FROM screenshots WHERE id = ?`, id)
	var (
		sc         model.Screenshot
		port       int
		username   sql.NullString
		capturedAt string
	)
	if err := row.Scan(&sc.ID, &sc.ScanID, &sc.HostID, &sc.Address, &port, &username,
		&sc.FilePath, &sc.Width, &sc.Height, &capturedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.Screenshot{}, ErrNotFound
		}
		return model.Screenshot{}, fmt.Errorf("store: get screenshot: %w", err)
	}
	sc.Port = uint16(port)
	sc.Username = username.String
	sc.CapturedAt = parseTime(capturedAt)
	return sc, nil
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
		// Only count child rows that still belong to a scan so interrupted
		// deletes cannot inflate the dashboard TOTAL HOSTS card.
		owned := ` WHERE scan_id IN (SELECT id FROM scans)`
		counts := []struct {
			query string
			dst   *int64
		}{
			{`SELECT COUNT(*) FROM hosts` + owned, &sum.HostsTotal},
			{`SELECT COUNT(*) FROM hosts` + owned + ` AND state = 'open'`, &sum.HostsOpen},
			{`SELECT COUNT(*) FROM findings` + owned, &sum.FindingsTotal},
			{`SELECT COUNT(*) FROM credentials` + owned, &sum.CredsTotal},
			{`SELECT COUNT(*) FROM screenshots` + owned, &sum.ScreensTotal},
		}
		for _, c := range counts {
			if err := s.db.QueryRow(c.query).Scan(c.dst); err != nil {
				return sum, fmt.Errorf("store: aggregate summary: %w", err)
			}
		}
		rows, err := s.db.Query(`SELECT severity, COUNT(*) FROM findings` + owned + ` GROUP BY severity`)
		if err != nil {
			return sum, fmt.Errorf("store: severity distribution: %w", err)
		}
		return finishSummarySeverity(sum, rows)
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
	return finishSummarySeverity(sum, rows)
}

func finishSummarySeverity(sum model.Summary, rows *sql.Rows) (model.Summary, error) {
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

// topRiskHostsLimit bounds the highest-risk host ranking on the reports page.
const topRiskHostsLimit = 10

// tlsExposureLabels fixes the display order of the TLS posture distribution.
var tlsExposureLabels = []string{
	"TLS 1.3",
	"TLS 1.2",
	"TLS 1.1",
	"TLS 1.0",
	"SSL 3.0",
	"RDP Security (no TLS)",
	"Not probed",
}

// legacyTLSVersions lists protocol versions that no longer meet current
// hardening baselines. The standard RDP security layer (empty version) is
// treated as legacy as well.
var legacyTLSVersions = map[string]bool{
	"TLS 1.0": true,
	"TLS 1.1": true,
	"SSL 3.0": true,
	"SSLv3":   true,
}

// statusOrder fixes the display order of finding status counts.
var statusOrder = []string{
	string(model.FindingVulnerable),
	string(model.FindingPotential),
	string(model.FindingInconclusive),
	string(model.FindingNotVulnerable),
}

// hostAgg accumulates the observations of one endpoint while Analytics walks
// every scan. Hosts are deduplicated so repeated scans do not inflate posture
// numbers; the newest scan wins because scans are listed newest first.
type hostAgg struct {
	risk         model.HostRisk
	serviceKnown bool
	certKnown    bool
	certNotAfter time.Time
}

// Analytics aggregates posture statistics across every stored scan.
func (s *Store) Analytics() (model.Analytics, error) {
	scans, err := s.listScans(0)
	if err != nil {
		return model.Analytics{}, err
	}

	var a model.Analytics
	hosts := map[string]*hostAgg{}
	hostOrder := []string{}
	seenFindings := map[string]bool{}
	statusCounts := map[string]int64{}
	tlsCounts := map[string]int64{}
	osCounts := map[string]int64{}
	var cvssSum float64
	var cvssCount int64

	for _, sc := range scans {
		scanHosts, err := s.ListHosts(sc.ID)
		if err != nil {
			return model.Analytics{}, err
		}
		for _, h := range scanHosts {
			key := h.Endpoint.Key()
			if _, ok := hosts[key]; ok {
				continue
			}
			agg := &hostAgg{
				risk: model.HostRisk{
					Address: h.Endpoint.Address,
					Port:    h.Endpoint.Port,
					Open:    h.State == "open",
				},
			}
			if h.Service != nil {
				agg.serviceKnown = true
				agg.risk.NLARequired = h.Service.NLARequired
				agg.risk.TLSVersion = h.Service.TLSVersion
				agg.risk.OSGuess = h.Service.OSGuess
				if h.Service.Certificate != nil {
					agg.certKnown = true
					agg.risk.SelfSigned = h.Service.Certificate.SelfSigned
					agg.certNotAfter = h.Service.Certificate.NotAfter
				}
			}
			hosts[key] = agg
			hostOrder = append(hostOrder, key)
		}

		findings, err := s.ListFindings(sc.ID)
		if err != nil {
			return model.Analytics{}, err
		}
		for _, f := range findings {
			key := f.Address + ":" + strconv.Itoa(int(f.Port)) + "|" + f.CheckID
			if seenFindings[key] {
				continue
			}
			seenFindings[key] = true
			statusCounts[string(f.Status)]++
			if f.Severity == model.SeverityCritical {
				a.CriticalFindings++
			}
			if f.CVSS > 0 {
				cvssSum += f.CVSS
				cvssCount++
			}

			hostKey := f.Address + ":" + strconv.Itoa(int(f.Port))
			agg, ok := hosts[hostKey]
			if !ok {
				// Findings normally reference a stored host; synthesise an
				// entry rather than dropping the finding if one is missing.
				agg = &hostAgg{risk: model.HostRisk{Address: f.Address, Port: f.Port}}
				hosts[hostKey] = agg
				hostOrder = append(hostOrder, hostKey)
			}
			agg.risk.Findings++
			agg.risk.RiskScore += f.CVSS
			if f.Severity.Rank() > agg.risk.MaxSeverity.Rank() {
				agg.risk.MaxSeverity = f.Severity
			}
		}
	}

	for _, key := range hostOrder {
		agg := hosts[key]
		a.HostsScanned++
		if !agg.risk.Open {
			continue
		}
		a.HostsOpen++

		osLabel := agg.risk.OSGuess
		if osLabel == "" {
			osLabel = "Unknown"
		}
		osCounts[osLabel]++

		if !agg.serviceKnown {
			tlsCounts["Not probed"]++
			continue
		}
		tlsLabel := agg.risk.TLSVersion
		if tlsLabel == "" {
			tlsLabel = "RDP Security (no TLS)"
		}
		tlsCounts[tlsLabel]++
		if agg.risk.TLSVersion == "" || legacyTLSVersions[agg.risk.TLSVersion] {
			a.LegacyTLS++
		}
		if !agg.risk.NLARequired {
			a.NLAMissing++
		}
		if agg.certKnown && agg.risk.SelfSigned {
			a.SelfSigned++
		}
		if agg.certKnown && !agg.certNotAfter.IsZero() {
			until := time.Until(agg.certNotAfter)
			if until >= 0 && until <= 30*24*time.Hour {
				a.CertsExpiring30d++
				a.ExpiringCerts = append(a.ExpiringCerts, agg.risk)
			}
		}
	}

	if cvssCount > 0 {
		a.AvgCVSS = cvssSum / float64(cvssCount)
	}

	a.Exposure = orderedCounts(tlsCounts, tlsExposureLabels)
	a.OSTypes = topCounts(osCounts, 8)
	a.Statuses = orderedCounts(statusCounts, statusOrder)

	for _, key := range hostOrder {
		risk := hosts[key].risk
		if risk.Findings == 0 {
			continue
		}
		a.TopHosts = append(a.TopHosts, risk)
	}
	sort.Slice(a.TopHosts, func(i, j int) bool {
		if a.TopHosts[i].RiskScore != a.TopHosts[j].RiskScore {
			return a.TopHosts[i].RiskScore > a.TopHosts[j].RiskScore
		}
		if a.TopHosts[i].Findings != a.TopHosts[j].Findings {
			return a.TopHosts[i].Findings > a.TopHosts[j].Findings
		}
		if a.TopHosts[i].Address != a.TopHosts[j].Address {
			return a.TopHosts[i].Address < a.TopHosts[j].Address
		}
		return a.TopHosts[i].Port < a.TopHosts[j].Port
	})
	if len(a.TopHosts) > topRiskHostsLimit {
		a.TopHosts = a.TopHosts[:topRiskHostsLimit]
	}
	return a, nil
}

// orderedCounts renders a counter map in the supplied label order. Labels that
// are not part of the order are appended alphabetically after the known ones.
func orderedCounts(counts map[string]int64, order []string) []model.LabeledCount {
	out := make([]model.LabeledCount, 0, len(counts))
	seen := make(map[string]bool, len(order))
	for _, label := range order {
		seen[label] = true
		if count, ok := counts[label]; ok {
			out = append(out, model.LabeledCount{Label: label, Count: count})
		}
	}
	extra := make([]string, 0, len(counts))
	for label := range counts {
		if !seen[label] {
			extra = append(extra, label)
		}
	}
	sort.Strings(extra)
	for _, label := range extra {
		out = append(out, model.LabeledCount{Label: label, Count: counts[label]})
	}
	return out
}

// topCounts renders the highest-count buckets, breaking ties by label.
func topCounts(counts map[string]int64, limit int) []model.LabeledCount {
	out := make([]model.LabeledCount, 0, len(counts))
	for label, count := range counts {
		out = append(out, model.LabeledCount{Label: label, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Label < out[j].Label
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}
