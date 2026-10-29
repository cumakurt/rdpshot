package cronexpr

import (
	"testing"
	"time"
)

func TestParseAndNextHourly(t *testing.T) {
	expr, err := Parse("0 * * * *")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	from := time.Date(2026, 10, 29, 14, 30, 0, 0, time.UTC)
	next, err := expr.Next(from)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	want := time.Date(2026, 10, 29, 15, 0, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Fatalf("Next = %v, want %v", next, want)
	}
}

func TestParseRejectsBadFieldCount(t *testing.T) {
	if _, err := Parse("* * *"); err == nil {
		t.Fatal("expected error for short expression")
	}
}

func TestMatchesWeekday(t *testing.T) {
	// Mondays at 02:00 UTC.
	expr, err := Parse("0 2 * * 1")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	mon := time.Date(2026, 10, 26, 2, 0, 0, 0, time.UTC) // Monday
	if !expr.Matches(mon) {
		t.Fatal("expected Monday 02:00 to match")
	}
	tue := time.Date(2026, 10, 27, 2, 0, 0, 0, time.UTC)
	if expr.Matches(tue) {
		t.Fatal("expected Tuesday 02:00 not to match")
	}
}
