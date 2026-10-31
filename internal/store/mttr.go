package store

import (
	"database/sql"
	"fmt"
	"time"
)

// MTTRStats aggregates mean-time-to-remediate and related security velocity
// metrics for the reports hub.
type MTTRStats struct {
	// AvgDaysToRemediate is the average number of days from detection to
	// remediation for closed findings.
	AvgDaysToRemediate float64 `json:"avg_days_to_remediate"`
	// MedianDaysToRemediate is the median of the same distribution.
	MedianDaysToRemediate float64 `json:"median_days_to_remediate"`
	// RemediatedTotal is the number of findings marked remediated.
	RemediatedTotal int64 `json:"remediated_total"`
	// OpenCritical is the current count of critical findings still in triage=open.
	OpenCritical int64 `json:"open_critical"`
	// OpenHigh is the current count of high findings still in triage=open.
	OpenHigh int64 `json:"open_high"`
	// RemediatedLast30d is the count of findings remediated in the last 30 days.
	RemediatedLast30d int64 `json:"remediated_last_30d"`
	// NewHostsLast7d is the count of distinct open hosts first seen in the last 7 days.
	NewHostsLast7d int64 `json:"new_hosts_last_7d"`
	// RemediationRate is RemediatedLast30d / max(total open 30d ago, 1), as a percentage.
	RemediationRate float64 `json:"remediation_rate"`
	// Period is the requested window label ("30d", "90d", "365d").
	Period string `json:"period"`
	// Engagement is the filtered engagement name (empty = global).
	Engagement string `json:"engagement,omitempty"`
}

// ComputeMTTR calculates MTTR and security velocity stats.
// engagement="" means global (all scans); period is "30d", "90d", or "365d".
func (s *Store) ComputeMTTR(engagement, period string) (MTTRStats, error) {
	stats := MTTRStats{Period: period, Engagement: engagement}
	days := periodDays(period)
	cutoff := time.Now().UTC().AddDate(0, 0, -days).Format(time.RFC3339)

	// Build optional engagement JOIN clause.
	engFilter := ""
	if engagement != "" {
		engFilter = fmt.Sprintf("AND s.engagement = '%s' ", escapeSQLLiteral(engagement))
	}

	// ── remediation times ────────────────────────────────────────────────────
	// Fetch (detected_at, triage_updated_at) for all remediated findings.
	q := fmt.Sprintf(`
		SELECT f.detected_at, f.triage_updated_at
		FROM findings f
		JOIN scans s ON f.scan_id = s.id
		WHERE f.triage_status = 'remediated'
		  AND f.triage_updated_at IS NOT NULL
		  %s
		ORDER BY f.triage_updated_at DESC
	`, engFilter)

	rows, err := s.db.Query(q)
	if err != nil {
		return stats, fmt.Errorf("mttr: query remediation times: %w", err)
	}
	var durations []float64
	var remLast30 int64
	cutoff30 := time.Now().UTC().AddDate(0, 0, -30)
	for rows.Next() {
		var detStr, updStr string
		if err := rows.Scan(&detStr, &updStr); err != nil {
			continue
		}
		det, err1 := time.Parse(time.RFC3339, detStr)
		upd, err2 := time.Parse(time.RFC3339, updStr)
		if err1 != nil || err2 != nil {
			continue
		}
		diff := upd.Sub(det).Hours() / 24.0
		if diff >= 0 {
			durations = append(durations, diff)
		}
		if upd.After(cutoff30) {
			remLast30++
		}
	}
	_ = rows.Close()

	stats.RemediatedTotal = int64(len(durations))
	stats.RemediatedLast30d = remLast30

	if len(durations) > 0 {
		var sum float64
		for _, d := range durations {
			sum += d
		}
		stats.AvgDaysToRemediate = sum / float64(len(durations))
		stats.MedianDaysToRemediate = median(durations)
	}

	// ── open critical / high ─────────────────────────────────────────────────
	q2 := fmt.Sprintf(`
		SELECT f.severity, COUNT(*)
		FROM findings f
		JOIN scans s ON f.scan_id = s.id
		WHERE f.triage_status = 'open'
		  AND f.status IN ('vulnerable', 'potential')
		  AND f.severity IN ('critical', 'high')
		  %s
		GROUP BY f.severity
	`, engFilter)
	rows2, err := s.db.Query(q2)
	if err != nil {
		return stats, fmt.Errorf("mttr: query open findings: %w", err)
	}
	for rows2.Next() {
		var sev string
		var cnt int64
		if err := rows2.Scan(&sev, &cnt); err != nil {
			continue
		}
		switch sev {
		case "critical":
			stats.OpenCritical = cnt
		case "high":
			stats.OpenHigh = cnt
		}
	}
	_ = rows2.Close()

	// ── new hosts in last 7 days ──────────────────────────────────────────────
	cutoff7 := time.Now().UTC().AddDate(0, 0, -7).Format(time.RFC3339)
	q3 := fmt.Sprintf(`
		SELECT COUNT(DISTINCT h.address || ':' || h.port)
		FROM hosts h
		JOIN scans s ON h.scan_id = s.id
		WHERE h.state = 'open'
		  AND h.updated_at >= '%s'
		  %s
	`, cutoff7, engFilter)
	_ = s.db.QueryRow(q3).Scan(&stats.NewHostsLast7d)

	// ── remediation rate ──────────────────────────────────────────────────────
	// Count total findings opened before the cutoff.
	q4 := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM findings f
		JOIN scans s ON f.scan_id = s.id
		WHERE f.detected_at >= '%s'
		  AND f.status IN ('vulnerable', 'potential')
		  %s
	`, cutoff, engFilter)
	var openedInPeriod int64
	_ = s.db.QueryRow(q4).Scan(&openedInPeriod)

	if openedInPeriod > 0 {
		stats.RemediationRate = float64(stats.RemediatedLast30d) / float64(openedInPeriod) * 100.0
	}

	return stats, nil
}

// WeeklyTrendPoint is one bucket in a weekly new-vs-remediated trend series.
type WeeklyTrendPoint struct {
	Week       string  `json:"week"`       // "2026-W43"
	NewFindings int64  `json:"new_findings"`
	Remediated  int64  `json:"remediated"`
	OpenCritical int64 `json:"open_critical"`
}

// WeeklyTrend returns up to numWeeks weekly buckets of finding activity.
func (s *Store) WeeklyTrend(engagement string, numWeeks int) ([]WeeklyTrendPoint, error) {
	if numWeeks <= 0 {
		numWeeks = 12
	}
	if numWeeks > 52 {
		numWeeks = 52
	}

	engFilter := ""
	if engagement != "" {
		engFilter = fmt.Sprintf("AND s.engagement = '%s' ", escapeSQLLiteral(engagement))
	}

	cutoff := time.Now().UTC().AddDate(0, 0, -(numWeeks * 7)).Format(time.RFC3339)

	q := fmt.Sprintf(`
		SELECT
			strftime('%%Y-W%%W', f.detected_at) AS week,
			COUNT(*) AS new_findings,
			SUM(CASE WHEN f.triage_status = 'remediated' THEN 1 ELSE 0 END) AS remediated,
			SUM(CASE WHEN f.severity = 'critical' AND f.triage_status = 'open' THEN 1 ELSE 0 END) AS open_crit
		FROM findings f
		JOIN scans s ON f.scan_id = s.id
		WHERE f.detected_at >= '%s'
		  AND f.status IN ('vulnerable', 'potential')
		  %s
		GROUP BY week
		ORDER BY week ASC
	`, cutoff, engFilter)

	rows, err := s.db.Query(q)
	if err != nil {
		return nil, fmt.Errorf("weekly trend: %w", err)
	}
	defer rows.Close()

	var points []WeeklyTrendPoint
	for rows.Next() {
		var p WeeklyTrendPoint
		var rem, oc sql.NullInt64
		if err := rows.Scan(&p.Week, &p.NewFindings, &rem, &oc); err != nil {
			continue
		}
		p.Remediated = rem.Int64
		p.OpenCritical = oc.Int64
		points = append(points, p)
	}
	return points, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────────────

func periodDays(period string) int {
	switch period {
	case "90d":
		return 90
	case "365d":
		return 365
	default:
		return 30
	}
}

// median returns the median of a sorted or unsorted slice of float64 values.
func median(data []float64) float64 {
	if len(data) == 0 {
		return 0
	}
	// simple insertion sort
	sorted := make([]float64, len(data))
	copy(sorted, data)
	for i := 1; i < len(sorted); i++ {
		key := sorted[i]
		j := i - 1
		for j >= 0 && sorted[j] > key {
			sorted[j+1] = sorted[j]
			j--
		}
		sorted[j+1] = key
	}
	n := len(sorted)
	if n%2 == 0 {
		return (sorted[n/2-1] + sorted[n/2]) / 2.0
	}
	return sorted[n/2]
}

// escapeSQLLiteral is a minimal escape for engagement names used in raw SQL.
// Only single-quotes need to be escaped in SQLite string literals.
func escapeSQLLiteral(s string) string {
	out := make([]byte, 0, len(s)+4)
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' {
			out = append(out, '\'', '\'')
		} else {
			out = append(out, s[i])
		}
	}
	return string(out)
}
