package store

import (
	"fmt"
	"time"

	"rdpshot/internal/decoy"
)

// InsertDecoyEvent persists a honeypot connection event to the database.
func (s *Store) InsertDecoyEvent(ev decoy.DecoyEvent) error {
	_, err := s.db.Exec(
		`INSERT INTO decoy_events
		 (at, remote_addr, remote_ip, ntlm_username, ntlm_domain, raw)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		ev.At.UTC().Format(time.RFC3339),
		ev.RemoteAddr,
		ev.RemoteIP,
		ev.NTLMUsername,
		ev.NTLMDomain,
		ev.Raw,
	)
	if err != nil {
		return fmt.Errorf("store: insert decoy event: %w", err)
	}
	return nil
}

// ListDecoyEvents returns up to limit decoy events, newest first.
// If since is non-zero only events after that time are returned.
func (s *Store) ListDecoyEvents(limit int, since time.Time) ([]decoy.DecoyEvent, error) {
	if limit <= 0 {
		limit = 200
	}
	q := `SELECT at, remote_addr, remote_ip, ntlm_username, ntlm_domain, raw
	      FROM decoy_events`
	args := []any{}
	if !since.IsZero() {
		q += ` WHERE at > ?`
		args = append(args, since.UTC().Format(time.RFC3339))
	}
	q += ` ORDER BY at DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list decoy events: %w", err)
	}
	defer rows.Close()

	var out []decoy.DecoyEvent
	for rows.Next() {
		var ev decoy.DecoyEvent
		var atStr string
		if err := rows.Scan(&atStr, &ev.RemoteAddr, &ev.RemoteIP,
			&ev.NTLMUsername, &ev.NTLMDomain, &ev.Raw); err != nil {
			continue
		}
		ev.At, _ = time.Parse(time.RFC3339, atStr)
		out = append(out, ev)
	}
	return out, nil
}
