// Package cronexpr evaluates simple five-field cron expressions
// (minute hour day-of-month month day-of-week).
package cronexpr

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Expr is a compiled five-field cron expression.
type Expr struct {
	minute, hour, dom, month, dow field
	raw                           string
}

type field struct {
	any  bool
	vals map[int]struct{}
}

// Parse validates and compiles a five-field cron expression.
func Parse(expr string) (*Expr, error) {
	expr = strings.TrimSpace(expr)
	parts := strings.Fields(expr)
	if len(parts) != 5 {
		return nil, fmt.Errorf("cronexpr: want 5 fields, got %d", len(parts))
	}
	out := &Expr{raw: expr}
	var err error
	if out.minute, err = parseField(parts[0], 0, 59); err != nil {
		return nil, fmt.Errorf("cronexpr: minute: %w", err)
	}
	if out.hour, err = parseField(parts[1], 0, 23); err != nil {
		return nil, fmt.Errorf("cronexpr: hour: %w", err)
	}
	if out.dom, err = parseField(parts[2], 1, 31); err != nil {
		return nil, fmt.Errorf("cronexpr: day-of-month: %w", err)
	}
	if out.month, err = parseField(parts[3], 1, 12); err != nil {
		return nil, fmt.Errorf("cronexpr: month: %w", err)
	}
	if out.dow, err = parseField(parts[4], 0, 6); err != nil {
		return nil, fmt.Errorf("cronexpr: day-of-week: %w", err)
	}
	return out, nil
}

// String returns the original expression text.
func (e *Expr) String() string {
	if e == nil {
		return ""
	}
	return e.raw
}

// Matches reports whether t falls on a scheduled minute.
func (e *Expr) Matches(t time.Time) bool {
	if e == nil {
		return false
	}
	t = t.UTC()
	if !e.minute.match(t.Minute()) || !e.hour.match(t.Hour()) {
		return false
	}
	if !e.month.match(int(t.Month())) {
		return false
	}
	domOK := e.dom.match(t.Day())
	dowOK := e.dow.match(int(t.Weekday())) // Sunday = 0
	if e.dom.any && e.dow.any {
		return true
	}
	if e.dom.any {
		return dowOK
	}
	if e.dow.any {
		return domOK
	}
	// Both constrained: either may match (standard cron OR semantics).
	return domOK || dowOK
}

// Next returns the next time at or after from (truncated to the minute) that
// matches the expression. Searches up to two years ahead.
func (e *Expr) Next(from time.Time) (time.Time, error) {
	if e == nil {
		return time.Time{}, fmt.Errorf("cronexpr: nil expression")
	}
	t := from.UTC().Truncate(time.Minute)
	if t.Before(from.UTC()) || t.Equal(from.UTC()) {
		// Always advance at least one minute so "now" does not re-fire.
		t = t.Add(time.Minute)
	}
	limit := t.Add(730 * 24 * time.Hour)
	for !t.After(limit) {
		if e.Matches(t) {
			return t, nil
		}
		t = t.Add(time.Minute)
	}
	return time.Time{}, fmt.Errorf("cronexpr: no match within two years for %q", e.raw)
}

func (f field) match(v int) bool {
	if f.any {
		return true
	}
	_, ok := f.vals[v]
	return ok
}

func parseField(raw string, min, max int) (field, error) {
	raw = strings.TrimSpace(raw)
	if raw == "*" {
		return field{any: true}, nil
	}
	out := field{vals: make(map[int]struct{})}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return field{}, fmt.Errorf("empty list entry")
		}
		step := 1
		rangePart := part
		if strings.Contains(part, "/") {
			bits := strings.SplitN(part, "/", 2)
			rangePart = bits[0]
			n, err := strconv.Atoi(bits[1])
			if err != nil || n <= 0 {
				return field{}, fmt.Errorf("invalid step in %q", part)
			}
			step = n
		}
		var start, end int
		switch {
		case rangePart == "*":
			start, end = min, max
		case strings.Contains(rangePart, "-"):
			bits := strings.SplitN(rangePart, "-", 2)
			var err error
			start, err = strconv.Atoi(bits[0])
			if err != nil {
				return field{}, fmt.Errorf("invalid range start in %q", part)
			}
			end, err = strconv.Atoi(bits[1])
			if err != nil {
				return field{}, fmt.Errorf("invalid range end in %q", part)
			}
		default:
			n, err := strconv.Atoi(rangePart)
			if err != nil {
				return field{}, fmt.Errorf("invalid value %q", part)
			}
			start, end = n, n
		}
		if start < min || end > max || start > end {
			return field{}, fmt.Errorf("out of range in %q (want %d-%d)", part, min, max)
		}
		for v := start; v <= end; v += step {
			out.vals[v] = struct{}{}
		}
	}
	if len(out.vals) == 0 {
		return field{}, fmt.Errorf("no values in %q", raw)
	}
	return out, nil
}
