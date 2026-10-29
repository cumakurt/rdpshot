package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"rdpshot/internal/model"
)

// UpsertHostNote creates or replaces a host note for an engagement endpoint.
func (s *Store) UpsertHostNote(n model.HostNote) (model.HostNote, error) {
	n.Engagement = strings.TrimSpace(n.Engagement)
	n.Address = strings.TrimSpace(n.Address)
	n.Note = strings.TrimSpace(n.Note)
	n.UpdatedBy = strings.TrimSpace(n.UpdatedBy)
	if n.Address == "" || n.Note == "" {
		return model.HostNote{}, fmt.Errorf("store: host note requires address and note")
	}
	n.UpdatedAt = time.Now().UTC()
	res, err := s.db.Exec(
		`INSERT INTO host_notes (engagement, address, port, note, updated_at, updated_by)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(engagement, address, port) DO UPDATE SET
		   note = excluded.note,
		   updated_at = excluded.updated_at,
		   updated_by = excluded.updated_by`,
		n.Engagement, n.Address, int(n.Port), n.Note, formatTime(n.UpdatedAt), n.UpdatedBy,
	)
	if err != nil {
		return model.HostNote{}, fmt.Errorf("store: upsert host note: %w", err)
	}
	if n.ID == 0 {
		id, _ := res.LastInsertId()
		n.ID = id
	}
	got, err := s.GetHostNote(n.Engagement, n.Address, n.Port)
	if err != nil {
		return n, nil
	}
	return got, nil
}

// GetHostNote loads one note.
func (s *Store) GetHostNote(engagement, address string, port uint16) (model.HostNote, error) {
	row := s.db.QueryRow(
		`SELECT id, engagement, address, port, note, updated_at, updated_by
		 FROM host_notes WHERE engagement = ? AND address = ? AND port = ?`,
		strings.TrimSpace(engagement), strings.TrimSpace(address), int(port),
	)
	var n model.HostNote
	var at string
	var portInt int
	err := row.Scan(&n.ID, &n.Engagement, &n.Address, &portInt, &n.Note, &at, &n.UpdatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return model.HostNote{}, fmt.Errorf("store: host note: %w", ErrNotFound)
	}
	if err != nil {
		return model.HostNote{}, err
	}
	n.Port = uint16(portInt)
	n.UpdatedAt = parseTime(at)
	return n, nil
}

// ListHostNotes returns notes for an engagement (empty engagement = all).
func (s *Store) ListHostNotes(engagement string) ([]model.HostNote, error) {
	engagement = strings.TrimSpace(engagement)
	var rows *sql.Rows
	var err error
	if engagement == "" {
		rows, err = s.db.Query(
			`SELECT id, engagement, address, port, note, updated_at, updated_by
			 FROM host_notes ORDER BY engagement, address, port`)
	} else {
		rows, err = s.db.Query(
			`SELECT id, engagement, address, port, note, updated_at, updated_by
			 FROM host_notes WHERE engagement = ? ORDER BY address, port`, engagement)
	}
	if err != nil {
		return nil, fmt.Errorf("store: list host notes: %w", err)
	}
	defer rows.Close()
	var out []model.HostNote
	for rows.Next() {
		var n model.HostNote
		var at string
		var portInt int
		if err := rows.Scan(&n.ID, &n.Engagement, &n.Address, &portInt, &n.Note, &at, &n.UpdatedBy); err != nil {
			return nil, err
		}
		n.Port = uint16(portInt)
		n.UpdatedAt = parseTime(at)
		out = append(out, n)
	}
	return out, rows.Err()
}

// DeleteHostNote removes one note by id.
func (s *Store) DeleteHostNote(id int64) error {
	res, err := s.db.Exec(`DELETE FROM host_notes WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete host note: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("store: delete host note: %w", ErrNotFound)
	}
	return nil
}
