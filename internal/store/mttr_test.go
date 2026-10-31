package store_test

import (
	"os"
	"testing"

	"rdpshot/internal/store"
)

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	f, err := os.CreateTemp("", "rdpshot-mttr-*.db")
	if err != nil {
		t.Fatalf("create temp db: %v", err)
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })
	s, err := store.Open(f.Name())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestComputeMTTR_EmptyDatabase(t *testing.T) {
	s := openTestStore(t)
	stats, err := s.ComputeMTTR("", "30d")
	if err != nil {
		t.Fatalf("ComputeMTTR error: %v", err)
	}
	if stats.AvgDaysToRemediate != 0 {
		t.Errorf("expected 0 avg days for empty db, got %f", stats.AvgDaysToRemediate)
	}
	if stats.Period != "30d" {
		t.Errorf("expected period=30d, got %q", stats.Period)
	}
}

func TestComputeMTTR_PeriodDaysValidation(t *testing.T) {
	s := openTestStore(t)
	for _, period := range []string{"30d", "90d", "365d", ""} {
		stats, err := s.ComputeMTTR("", period)
		if err != nil {
			t.Errorf("ComputeMTTR(%q) error: %v", period, err)
		}
		_ = stats
	}
}

func TestWeeklyTrend_EmptyDatabase(t *testing.T) {
	s := openTestStore(t)
	points, err := s.WeeklyTrend("", 4)
	if err != nil {
		t.Fatalf("WeeklyTrend error: %v", err)
	}
	// Empty database should return zero or empty points (not error).
	_ = points
}

func TestWeeklyTrend_CapAt52Weeks(t *testing.T) {
	s := openTestStore(t)
	// Should not error even with large numWeeks.
	_, err := s.WeeklyTrend("", 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
