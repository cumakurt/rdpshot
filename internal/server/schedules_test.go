package server

import (
	"testing"
	"time"
)

func TestParseScheduleRunAtRFC3339(t *testing.T) {
	now := time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC)
	got, err := parseScheduleRunAt("2026-10-30T12:30:00Z", now)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got == nil || !got.Equal(time.Date(2026, 10, 30, 12, 30, 0, 0, time.UTC)) {
		t.Fatalf("got %v", got)
	}
}

func TestParseScheduleRunAtLocalNaive(t *testing.T) {
	now := time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC)
	got, err := parseScheduleRunAt("2026-10-31T08:15", now)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got == nil {
		t.Fatal("expected time")
	}
	local := time.Date(2026, 10, 31, 8, 15, 0, 0, time.Local).UTC()
	if !got.Equal(local) {
		t.Fatalf("got %v want %v", got, local)
	}
}

func TestParseScheduleRunAtRejectsPast(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	if _, err := parseScheduleRunAt("2026-10-30T10:00:00Z", now); err == nil {
		t.Fatal("expected past rejection")
	}
}

func TestParseScheduleRunAtEmpty(t *testing.T) {
	now := time.Now().UTC()
	got, err := parseScheduleRunAt("  ", now)
	if err != nil || got != nil {
		t.Fatalf("got (%v, %v)", got, err)
	}
}
