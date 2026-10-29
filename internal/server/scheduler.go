package server

import (
	"context"
	"fmt"
	"strings"
	"time"

	"rdpshot/internal/cronexpr"
	"rdpshot/internal/model"
	"rdpshot/internal/target"
)

const (
	// scheduleTick is how often the server looks for due schedules.
	scheduleTick = 30 * time.Second
	// minScheduleInterval bounds how aggressive a recurring scan may be.
	minScheduleInterval = 5 * time.Minute
	// maxScheduleInterval bounds how far apart recurring scans may be.
	maxScheduleInterval = 30 * 24 * time.Hour
)

// runScheduler wakes on a short interval and starts any due scheduled scans
// until ctx is cancelled.
func (s *Server) runScheduler(ctx context.Context) {
	ticker := time.NewTicker(scheduleTick)
	defer ticker.Stop()
	s.deps.Logger.Info("schedule runner started", "tick", scheduleTick.String())
	for {
		select {
		case <-ctx.Done():
			s.deps.Logger.Info("schedule runner stopped")
			return
		case <-ticker.C:
			s.fireDueSchedules(ctx)
		}
	}
}

func (s *Server) fireDueSchedules(ctx context.Context) {
	due, err := s.deps.Store.DueSchedules(time.Now().UTC())
	if err != nil {
		s.deps.Logger.Error("list due schedules", "error", err.Error())
		return
	}
	for _, sch := range due {
		if ctx.Err() != nil {
			return
		}
		if err := s.runScheduledScan(ctx, sch); err != nil {
			s.deps.Logger.Error("scheduled scan failed",
				"schedule_id", sch.ID, "error", err.Error())
		}
	}
}

func (s *Server) runScheduledScan(ctx context.Context, sch model.Schedule) error {
	now := time.Now().UTC()
	next, err := nextScheduleRun(sch, now)
	if err != nil {
		sch.LastError = err.Error()
		sch.UpdatedAt = now
		_ = s.deps.Store.UpdateSchedule(sch)
		return err
	}
	sch.LastRunAt = &now
	sch.NextRunAt = &next
	sch.UpdatedAt = now
	sch.LastError = ""

	endpoints, err := s.resolveScheduleEndpoints(ctx, sch.Options)
	if err != nil {
		sch.LastError = err.Error()
		_ = s.deps.Store.UpdateSchedule(sch)
		return err
	}

	scan := model.Scan{
		ID:         model.NewID("scan"),
		Name:       fmt.Sprintf("%s (%s)", sch.Name, now.Format("2006-01-02 15:04")),
		Status:     model.ScanPending,
		CreatedAt:  now,
		Options:    sch.Options,
		ScheduleID: sch.ID,
		Engagement: strings.TrimSpace(sch.Name),
	}
	if err := s.deps.Store.CreateScan(scan); err != nil {
		sch.LastError = err.Error()
		_ = s.deps.Store.UpdateSchedule(sch)
		return fmt.Errorf("create scheduled scan: %w", err)
	}
	sch.LastScanID = scan.ID
	if err := s.deps.Store.UpdateSchedule(sch); err != nil {
		return fmt.Errorf("update schedule after queue: %w", err)
	}
	s.startScan(scan, endpoints)
	s.deps.Logger.Info("scheduled scan queued",
		"schedule_id", sch.ID, "scan_id", scan.ID, "endpoints", len(endpoints))
	return nil
}

func nextScheduleRun(sch model.Schedule, from time.Time) (time.Time, error) {
	if expr := strings.TrimSpace(sch.CronExpr); expr != "" {
		parsed, err := cronexpr.Parse(expr)
		if err != nil {
			return time.Time{}, err
		}
		return parsed.Next(from)
	}
	if sch.IntervalSeconds <= 0 {
		return time.Time{}, fmt.Errorf("schedule has neither cron_expr nor interval_seconds")
	}
	return from.Add(time.Duration(sch.IntervalSeconds) * time.Second), nil
}

func (s *Server) resolveScheduleEndpoints(ctx context.Context, opts model.ScanOptions) ([]model.Endpoint, error) {
	for _, spec := range opts.Targets {
		if len(spec) > 0 && spec[0] == '@' {
			return nil, fmt.Errorf("target file specs are not accepted in schedules")
		}
	}
	res, err := target.Resolve(ctx, target.Options{
		Specs:      opts.Targets,
		Ports:      opts.Ports,
		Blacklist:  opts.Blacklist,
		MaxTargets: s.cfg.MaxTargets,
	})
	if err != nil {
		return nil, err
	}
	if len(res.Endpoints) == 0 {
		return nil, fmt.Errorf("no endpoints resolved from schedule targets")
	}
	return res.Endpoints, nil
}
