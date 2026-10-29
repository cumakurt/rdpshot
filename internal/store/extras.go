package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"rdpshot/internal/model"
)

// ErrNotFound is a generic missing-row sentinel for extras tables.
var ErrNotFound = errors.New("store: not found")

func findingFromRow(row rowScanner) (model.Finding, error) {
	var (
		f              model.Finding
		port           int
		severity       string
		status         string
		cve            sql.NullString
		evidence       sql.NullString
		remediation    sql.NullString
		detectedAt     string
		triageStatus   string
		triageNote     string
		triageUpdated  sql.NullString
	)
	if err := row.Scan(&f.ID, &f.ScanID, &f.HostID, &f.Address, &port, &f.CheckID, &f.Title,
		&severity, &status, &f.CVSS, &cve, &evidence, &remediation, &detectedAt,
		&triageStatus, &triageNote, &triageUpdated); err != nil {
		return model.Finding{}, fmt.Errorf("store: read finding: %w", err)
	}
	f.Port = uint16(port)
	f.Severity = model.Severity(severity)
	f.Status = model.FindingStatus(status)
	f.CVE = cve.String
	f.Evidence = evidence.String
	f.Remediation = remediation.String
	f.DetectedAt = parseTime(detectedAt)
	if triageStatus == "" {
		triageStatus = string(model.TriageOpen)
	}
	f.TriageStatus = model.TriageStatus(triageStatus)
	f.TriageNote = triageNote
	if triageUpdated.Valid && triageUpdated.String != "" {
		t := parseTime(triageUpdated.String)
		f.TriageUpdatedAt = &t
	}
	return f, nil
}

// GetFinding loads one finding by id.
func (s *Store) GetFinding(id int64) (model.Finding, error) {
	row := s.db.QueryRow(
		`SELECT id, scan_id, host_id, address, port, check_id, title, severity, status,
		        cvss, cve, evidence, remediation, detected_at,
		        triage_status, triage_note, triage_updated_at
		 FROM findings WHERE id = ?`, id)
	f, err := findingFromRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Finding{}, fmt.Errorf("store: get finding %d: %w", id, ErrNotFound)
	}
	if err != nil {
		return model.Finding{}, err
	}
	return f, nil
}

// UpdateFindingTriage sets the operator workflow state of a finding.
func (s *Store) UpdateFindingTriage(id int64, status model.TriageStatus, note string) (model.Finding, error) {
	if !status.Valid() {
		return model.Finding{}, fmt.Errorf("store: invalid triage status %q", status)
	}
	now := time.Now().UTC()
	res, err := s.db.Exec(
		`UPDATE findings SET triage_status = ?, triage_note = ?, triage_updated_at = ? WHERE id = ?`,
		string(status), strings.TrimSpace(note), formatTime(now), id,
	)
	if err != nil {
		return model.Finding{}, fmt.Errorf("store: update finding triage %d: %w", id, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return model.Finding{}, fmt.Errorf("store: update finding triage %d: %w", id, err)
	}
	if affected == 0 {
		return model.Finding{}, fmt.Errorf("store: update finding triage %d: %w", id, ErrNotFound)
	}
	return s.GetFinding(id)
}

// UpdateScanMeta updates engagement and tags without touching scan progress.
func (s *Store) UpdateScanMeta(id, engagement string, tags []string) (model.Scan, error) {
	encoded, err := json.Marshal(normalizeTags(tags))
	if err != nil {
		return model.Scan{}, fmt.Errorf("store: encode tags: %w", err)
	}
	res, err := s.db.Exec(
		`UPDATE scans SET engagement = ?, tags_json = ? WHERE id = ?`,
		strings.TrimSpace(engagement), string(encoded), id,
	)
	if err != nil {
		return model.Scan{}, fmt.Errorf("store: update scan meta %q: %w", id, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return model.Scan{}, fmt.Errorf("store: update scan meta %q: %w", id, err)
	}
	if affected == 0 {
		return model.Scan{}, fmt.Errorf("store: update scan meta %q: %w", id, ErrScanNotFound)
	}
	return s.GetScan(id)
}

// ListScansFiltered returns recent scans optionally filtered by engagement or tag.
func (s *Store) ListScansFiltered(limit int, engagement, tag string) ([]model.Scan, error) {
	scans, err := s.ListScans(limit)
	if err != nil {
		return nil, err
	}
	engagement = strings.TrimSpace(engagement)
	tag = strings.TrimSpace(strings.ToLower(tag))
	if engagement == "" && tag == "" {
		return scans, nil
	}
	out := make([]model.Scan, 0, len(scans))
	for _, sc := range scans {
		if engagement != "" && !strings.EqualFold(sc.Engagement, engagement) {
			continue
		}
		if tag != "" {
			found := false
			for _, t := range sc.Tags {
				if strings.EqualFold(t, tag) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		out = append(out, sc)
	}
	return out, nil
}

// Trend returns posture samples for completed scans, optionally scoped by engagement.
func (s *Store) Trend(engagement string, limit int) (model.TrendSeries, error) {
	if limit <= 0 {
		limit = 30
	}
	scans, err := s.listScans(0)
	if err != nil {
		return model.TrendSeries{}, err
	}
	engagement = strings.TrimSpace(engagement)
	series := model.TrendSeries{Engagement: engagement}
	for i := len(scans) - 1; i >= 0; i-- {
		sc := scans[i]
		if sc.Status != model.ScanCompleted {
			continue
		}
		if engagement != "" && !strings.EqualFold(sc.Engagement, engagement) {
			continue
		}
		summary, err := s.Summary(sc.ID)
		if err != nil {
			return model.TrendSeries{}, err
		}
		findings, err := s.ListFindings(sc.ID)
		if err != nil {
			return model.TrendSeries{}, err
		}
		var openTriage int64
		for _, f := range findings {
			if f.TriageStatus == "" || f.TriageStatus == model.TriageOpen {
				openTriage++
			}
		}
		at := sc.CreatedAt
		if sc.FinishedAt != nil {
			at = *sc.FinishedAt
		}
		series.Points = append(series.Points, model.TrendPoint{
			At:            at,
			ScanID:        sc.ID,
			ScanName:      sc.Name,
			HostsOpen:     summary.HostsOpen,
			FindingsTotal: summary.FindingsTotal,
			Critical:      summary.CountBySeverity(model.SeverityCritical),
			High:          summary.CountBySeverity(model.SeverityHigh),
			OpenTriage:    openTriage,
		})
	}
	if len(series.Points) > limit {
		series.Points = series.Points[len(series.Points)-limit:]
	}
	return series, nil
}

// CreateWordlistSet inserts a named wordlist pair.
func (s *Store) CreateWordlistSet(set model.WordlistSet) error {
	_, err := s.db.Exec(
		`INSERT INTO wordlist_sets (id, name, user_path, password_path, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		set.ID, set.Name, set.UserPath, set.PasswordPath, formatTime(set.CreatedAt), formatTime(set.UpdatedAt),
	)
	if err != nil {
		return fmt.Errorf("store: create wordlist set %q: %w", set.ID, err)
	}
	return nil
}

// UpdateWordlistSet replaces a named wordlist pair.
func (s *Store) UpdateWordlistSet(set model.WordlistSet) error {
	res, err := s.db.Exec(
		`UPDATE wordlist_sets SET name = ?, user_path = ?, password_path = ?, updated_at = ? WHERE id = ?`,
		set.Name, set.UserPath, set.PasswordPath, formatTime(set.UpdatedAt), set.ID,
	)
	if err != nil {
		return fmt.Errorf("store: update wordlist set %q: %w", set.ID, err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("store: update wordlist set %q: %w", set.ID, ErrNotFound)
	}
	return nil
}

// ListWordlistSets returns every named set, alphabetically.
func (s *Store) ListWordlistSets() ([]model.WordlistSet, error) {
	rows, err := s.db.Query(
		`SELECT id, name, user_path, password_path, created_at, updated_at
		 FROM wordlist_sets ORDER BY name ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: list wordlist sets: %w", err)
	}
	defer rows.Close()
	var out []model.WordlistSet
	for rows.Next() {
		var set model.WordlistSet
		var created, updated string
		if err := rows.Scan(&set.ID, &set.Name, &set.UserPath, &set.PasswordPath, &created, &updated); err != nil {
			return nil, fmt.Errorf("store: read wordlist set: %w", err)
		}
		set.CreatedAt = parseTime(created)
		set.UpdatedAt = parseTime(updated)
		out = append(out, set)
	}
	return out, rows.Err()
}

// GetWordlistSet loads one set by id.
func (s *Store) GetWordlistSet(id string) (model.WordlistSet, error) {
	row := s.db.QueryRow(
		`SELECT id, name, user_path, password_path, created_at, updated_at FROM wordlist_sets WHERE id = ?`, id)
	var set model.WordlistSet
	var created, updated string
	err := row.Scan(&set.ID, &set.Name, &set.UserPath, &set.PasswordPath, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return model.WordlistSet{}, fmt.Errorf("store: get wordlist set %q: %w", id, ErrNotFound)
	}
	if err != nil {
		return model.WordlistSet{}, fmt.Errorf("store: get wordlist set %q: %w", id, err)
	}
	set.CreatedAt = parseTime(created)
	set.UpdatedAt = parseTime(updated)
	return set, nil
}

// DeleteWordlistSet removes one set.
func (s *Store) DeleteWordlistSet(id string) error {
	res, err := s.db.Exec(`DELETE FROM wordlist_sets WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete wordlist set %q: %w", id, err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("store: delete wordlist set %q: %w", id, ErrNotFound)
	}
	return nil
}

// CreateUser inserts a local portal account.
func (s *Store) CreateUser(u model.User) error {
	_, err := s.db.Exec(
		`INSERT INTO users (id, username, password_hash, role, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		u.ID, u.Username, u.PasswordHash, string(u.Role), formatTime(u.CreatedAt), formatTime(u.UpdatedAt),
	)
	if err != nil {
		return fmt.Errorf("store: create user %q: %w", u.Username, err)
	}
	return nil
}

// UpdateUser replaces role and optionally password hash.
func (s *Store) UpdateUser(u model.User) error {
	res, err := s.db.Exec(
		`UPDATE users SET username = ?, password_hash = ?, role = ?, updated_at = ? WHERE id = ?`,
		u.Username, u.PasswordHash, string(u.Role), formatTime(u.UpdatedAt), u.ID,
	)
	if err != nil {
		return fmt.Errorf("store: update user %q: %w", u.ID, err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("store: update user %q: %w", u.ID, ErrNotFound)
	}
	return nil
}

// GetUserByUsername loads one account.
func (s *Store) GetUserByUsername(username string) (model.User, error) {
	row := s.db.QueryRow(
		`SELECT id, username, password_hash, role, created_at, updated_at FROM users WHERE username = ?`,
		username)
	return scanUser(row)
}

// GetUser loads one account by id.
func (s *Store) GetUser(id string) (model.User, error) {
	row := s.db.QueryRow(
		`SELECT id, username, password_hash, role, created_at, updated_at FROM users WHERE id = ?`, id)
	return scanUser(row)
}

// ListUsers returns every local account.
func (s *Store) ListUsers() ([]model.User, error) {
	rows, err := s.db.Query(`SELECT id, username, password_hash, role, created_at, updated_at FROM users ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("store: list users: %w", err)
	}
	defer rows.Close()
	var out []model.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// DeleteUser removes one account.
func (s *Store) DeleteUser(id string) error {
	res, err := s.db.Exec(`DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete user %q: %w", id, err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("store: delete user %q: %w", id, ErrNotFound)
	}
	return nil
}

// UserCount returns how many local accounts exist.
func (s *Store) UserCount() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func scanUser(row rowScanner) (model.User, error) {
	var (
		u              model.User
		role           string
		created, updated string
	)
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &role, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return model.User{}, fmt.Errorf("store: %w", ErrNotFound)
	}
	if err != nil {
		return model.User{}, fmt.Errorf("store: read user: %w", err)
	}
	u.Role = model.UserRole(role)
	u.CreatedAt = parseTime(created)
	u.UpdatedAt = parseTime(updated)
	return u, nil
}

// AppendAudit writes one audit log row.
func (s *Store) AppendAudit(entry model.AuditEntry) error {
	_, err := s.db.Exec(
		`INSERT INTO audit_log (at, actor, action, target, detail, remote_ip)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		formatTime(entry.At), entry.Actor, entry.Action, entry.Target, entry.Detail, entry.RemoteIP,
	)
	if err != nil {
		return fmt.Errorf("store: append audit: %w", err)
	}
	return nil
}

// ListAudit returns the newest audit entries.
func (s *Store) ListAudit(limit int) ([]model.AuditEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(
		`SELECT id, at, actor, action, target, detail, remote_ip
		 FROM audit_log ORDER BY at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list audit: %w", err)
	}
	defer rows.Close()
	var out []model.AuditEntry
	for rows.Next() {
		var (
			e  model.AuditEntry
			at string
		)
		if err := rows.Scan(&e.ID, &at, &e.Actor, &e.Action, &e.Target, &e.Detail, &e.RemoteIP); err != nil {
			return nil, fmt.Errorf("store: read audit: %w", err)
		}
		e.At = parseTime(at)
		out = append(out, e)
	}
	return out, rows.Err()
}

const brandingSettingsKey = "report_branding"
const policySettingsKey = "hardening_policy"
const siemSettingsKey = "siem_sink"
const alertRulesSettingsKey = "alert_rules"

// GetReportBranding loads report branding settings.
func (s *Store) GetReportBranding() (model.ReportBranding, error) {
	var raw string
	err := s.db.QueryRow(`SELECT value_json FROM settings WHERE key = ?`, brandingSettingsKey).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return model.ReportBranding{}, nil
	}
	if err != nil {
		return model.ReportBranding{}, fmt.Errorf("store: get branding: %w", err)
	}
	var b model.ReportBranding
	if err := json.Unmarshal([]byte(raw), &b); err != nil {
		return model.ReportBranding{}, fmt.Errorf("store: decode branding: %w", err)
	}
	return b, nil
}

// SetReportBranding stores report branding settings.
func (s *Store) SetReportBranding(b model.ReportBranding) error {
	raw, err := json.Marshal(b)
	if err != nil {
		return fmt.Errorf("store: encode branding: %w", err)
	}
	_, err = s.db.Exec(
		`INSERT INTO settings (key, value_json) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json`,
		brandingSettingsKey, string(raw),
	)
	if err != nil {
		return fmt.Errorf("store: set branding: %w", err)
	}
	return nil
}

// GetSettingJSON loads a raw JSON settings document by key.
func (s *Store) GetSettingJSON(key string) (json.RawMessage, error) {
	var raw string
	err := s.db.QueryRow(`SELECT value_json FROM settings WHERE key = ?`, key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: get setting %q: %w", key, err)
	}
	return json.RawMessage(raw), nil
}

// SetSettingJSON stores a JSON settings document by key.
func (s *Store) SetSettingJSON(key string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("store: encode setting %q: %w", key, err)
	}
	_, err = s.db.Exec(
		`INSERT INTO settings (key, value_json) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json`,
		key, string(raw),
	)
	if err != nil {
		return fmt.Errorf("store: set setting %q: %w", key, err)
	}
	return nil
}

// PolicySettingsKey is the settings key for the hardening policy document.
func PolicySettingsKey() string { return policySettingsKey }

// SIEMSettingsKey is the settings key for the SIEM sink configuration.
func SIEMSettingsKey() string { return siemSettingsKey }

// AlertRulesSettingsKey is the settings key for post-scan alert rules.
func AlertRulesSettingsKey() string { return alertRulesSettingsKey }

// GetAlertRules loads alert rule settings.
func (s *Store) GetAlertRules() (model.AlertRules, error) {
	raw, err := s.GetSettingJSON(alertRulesSettingsKey)
	if err != nil {
		return model.AlertRules{}, err
	}
	if len(raw) == 0 {
		return model.AlertRules{}, nil
	}
	var rules model.AlertRules
	if err := json.Unmarshal(raw, &rules); err != nil {
		return model.AlertRules{}, fmt.Errorf("store: decode alert rules: %w", err)
	}
	return rules, nil
}

// SetAlertRules stores alert rule settings.
func (s *Store) SetAlertRules(rules model.AlertRules) error {
	return s.SetSettingJSON(alertRulesSettingsKey, rules)
}

// BulkUpdateFindingTriage applies the same triage state to many findings.
func (s *Store) BulkUpdateFindingTriage(ids []int64, status model.TriageStatus, note string) (int, error) {
	if !status.Valid() {
		return 0, fmt.Errorf("store: invalid triage status %q", status)
	}
	if len(ids) == 0 {
		return 0, nil
	}
	now := formatTime(time.Now().UTC())
	note = strings.TrimSpace(note)
	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("store: begin bulk triage: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.Prepare(
		`UPDATE findings SET triage_status = ?, triage_note = ?, triage_updated_at = ? WHERE id = ?`)
	if err != nil {
		return 0, fmt.Errorf("store: prepare bulk triage: %w", err)
	}
	defer stmt.Close()
	updated := 0
	for _, id := range ids {
		res, err := stmt.Exec(string(status), note, now, id)
		if err != nil {
			return 0, fmt.Errorf("store: bulk triage %d: %w", id, err)
		}
		n, _ := res.RowsAffected()
		updated += int(n)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: commit bulk triage: %w", err)
	}
	return updated, nil
}
