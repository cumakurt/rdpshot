package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"rdpshot/internal/model"
)

// ErrScheduleNotFound is returned when a schedule id does not exist.
var ErrScheduleNotFound = errors.New("store: schedule not found")

const scheduleSelectCols = `id, name, enabled, interval_seconds, cron_expr, options_json,
		notify_webhook, notify_on_complete, notify_on_critical,
		created_at, updated_at, last_run_at, next_run_at, last_scan_id, last_error`

// CreateSchedule inserts a new recurring scan schedule.
func (s *Store) CreateSchedule(sch model.Schedule) error {
	options, err := json.Marshal(sch.Options)
	if err != nil {
		return fmt.Errorf("store: marshal schedule options: %w", err)
	}
	_, err = s.db.Exec(
		`INSERT INTO schedules (
			id, name, enabled, interval_seconds, cron_expr, options_json,
			notify_webhook, notify_on_complete, notify_on_critical,
			created_at, updated_at, last_run_at, next_run_at, last_scan_id, last_error
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sch.ID, sch.Name, boolToInt(sch.Enabled), sch.IntervalSeconds, sch.CronExpr, string(options),
		sch.NotifyWebhook, boolToInt(sch.NotifyOnComplete), boolToInt(sch.NotifyOnCritical),
		formatTime(sch.CreatedAt), formatTime(sch.UpdatedAt),
		formatTimePtr(sch.LastRunAt), formatTimePtr(sch.NextRunAt),
		sch.LastScanID, sch.LastError,
	)
	if err != nil {
		return fmt.Errorf("store: create schedule %q: %w", sch.ID, err)
	}
	return nil
}

// UpdateSchedule replaces the mutable fields of an existing schedule.
func (s *Store) UpdateSchedule(sch model.Schedule) error {
	options, err := json.Marshal(sch.Options)
	if err != nil {
		return fmt.Errorf("store: marshal schedule options: %w", err)
	}
	res, err := s.db.Exec(
		`UPDATE schedules SET
			name = ?, enabled = ?, interval_seconds = ?, cron_expr = ?, options_json = ?,
			notify_webhook = ?, notify_on_complete = ?, notify_on_critical = ?,
			updated_at = ?, last_run_at = ?, next_run_at = ?, last_scan_id = ?, last_error = ?
		 WHERE id = ?`,
		sch.Name, boolToInt(sch.Enabled), sch.IntervalSeconds, sch.CronExpr, string(options),
		sch.NotifyWebhook, boolToInt(sch.NotifyOnComplete), boolToInt(sch.NotifyOnCritical),
		formatTime(sch.UpdatedAt), formatTimePtr(sch.LastRunAt), formatTimePtr(sch.NextRunAt),
		sch.LastScanID, sch.LastError, sch.ID,
	)
	if err != nil {
		return fmt.Errorf("store: update schedule %q: %w", sch.ID, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: update schedule %q: %w", sch.ID, err)
	}
	if affected == 0 {
		return fmt.Errorf("store: update schedule %q: %w", sch.ID, ErrScheduleNotFound)
	}
	return nil
}

// GetSchedule returns one schedule by id.
func (s *Store) GetSchedule(id string) (model.Schedule, error) {
	row := s.db.QueryRow(`SELECT `+scheduleSelectCols+` FROM schedules WHERE id = ?`, id)
	sch, err := scanSchedule(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Schedule{}, fmt.Errorf("store: get schedule %q: %w", id, ErrScheduleNotFound)
	}
	if err != nil {
		return model.Schedule{}, fmt.Errorf("store: get schedule %q: %w", id, err)
	}
	return sch, nil
}

// ListSchedules returns every schedule, soonest next run first.
func (s *Store) ListSchedules() ([]model.Schedule, error) {
	rows, err := s.db.Query(
		`SELECT ` + scheduleSelectCols + `
		 FROM schedules
		 ORDER BY enabled DESC, COALESCE(next_run_at, created_at) ASC, name ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: list schedules: %w", err)
	}
	defer rows.Close()

	var out []model.Schedule
	for rows.Next() {
		sch, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sch)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list schedules: %w", err)
	}
	return out, nil
}

// DueSchedules returns enabled schedules whose next_run_at is at or before now.
func (s *Store) DueSchedules(now time.Time) ([]model.Schedule, error) {
	rows, err := s.db.Query(
		`SELECT `+scheduleSelectCols+`
		 FROM schedules
		 WHERE enabled = 1 AND next_run_at IS NOT NULL AND next_run_at <= ?
		 ORDER BY next_run_at ASC`, formatTime(now))
	if err != nil {
		return nil, fmt.Errorf("store: list due schedules: %w", err)
	}
	defer rows.Close()

	var out []model.Schedule
	for rows.Next() {
		sch, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sch)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list due schedules: %w", err)
	}
	return out, nil
}

// DeleteSchedule removes one schedule.
func (s *Store) DeleteSchedule(id string) error {
	res, err := s.db.Exec(`DELETE FROM schedules WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete schedule %q: %w", id, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: delete schedule %q: %w", id, err)
	}
	if affected == 0 {
		return fmt.Errorf("store: delete schedule %q: %w", id, ErrScheduleNotFound)
	}
	return nil
}

// GetScheduleByLastScan returns the schedule that last queued the given scan.
func (s *Store) GetScheduleByLastScan(scanID string) (model.Schedule, error) {
	row := s.db.QueryRow(`SELECT `+scheduleSelectCols+` FROM schedules WHERE last_scan_id = ? LIMIT 1`, scanID)
	sch, err := scanSchedule(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Schedule{}, fmt.Errorf("store: get schedule by scan %q: %w", scanID, ErrScheduleNotFound)
	}
	if err != nil {
		return model.Schedule{}, fmt.Errorf("store: get schedule by scan %q: %w", scanID, err)
	}
	return sch, nil
}

type scheduleScanner interface {
	Scan(dest ...any) error
}

func scanSchedule(row scheduleScanner) (model.Schedule, error) {
	var (
		sch                   model.Schedule
		enabled               int
		optionsJSON           string
		notifyComplete        int
		notifyCritical        int
		createdAt, updatedAt  string
		lastRunAt, nextRunAt  sql.NullString
		lastScanID, lastError sql.NullString
	)
	if err := row.Scan(
		&sch.ID, &sch.Name, &enabled, &sch.IntervalSeconds, &sch.CronExpr, &optionsJSON,
		&sch.NotifyWebhook, &notifyComplete, &notifyCritical,
		&createdAt, &updatedAt, &lastRunAt, &nextRunAt, &lastScanID, &lastError,
	); err != nil {
		return model.Schedule{}, err
	}
	if err := json.Unmarshal([]byte(optionsJSON), &sch.Options); err != nil {
		return model.Schedule{}, fmt.Errorf("store: decode schedule options: %w", err)
	}
	sch.Enabled = enabled != 0
	sch.NotifyOnComplete = notifyComplete != 0
	sch.NotifyOnCritical = notifyCritical != 0
	sch.CreatedAt = parseTime(createdAt)
	sch.UpdatedAt = parseTime(updatedAt)
	if lastRunAt.Valid && lastRunAt.String != "" {
		t := parseTime(lastRunAt.String)
		sch.LastRunAt = &t
	}
	if nextRunAt.Valid && nextRunAt.String != "" {
		t := parseTime(nextRunAt.String)
		sch.NextRunAt = &t
	}
	if lastScanID.Valid {
		sch.LastScanID = lastScanID.String
	}
	if lastError.Valid {
		sch.LastError = lastError.String
	}
	return sch, nil
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
