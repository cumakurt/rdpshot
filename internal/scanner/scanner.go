// Package scanner orchestrates reconnaissance, vulnerability checks and the
// optional intrusive stages (credential audit, screenshot capture) over a set
// of endpoints with bounded concurrency and paced connection attempts.
package scanner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"rdpshot/internal/brute"
	"rdpshot/internal/events"
	"rdpshot/internal/model"
	"rdpshot/internal/rdp"
	"rdpshot/internal/screenshot"
	"rdpshot/internal/store"
	"rdpshot/internal/vuln"
)

// Dependencies are the collaborators the engine writes to and reads from.
type Dependencies struct {
	// Store persists scan results; required.
	Store *store.Store
	// Hub broadcasts live events; optional.
	Hub *events.Hub
	// Logger receives operational logs; optional.
	Logger *slog.Logger
	// Authenticator performs credential checks; optional and only used when
	// the scan explicitly enabled it.
	Authenticator brute.Authenticator
	// Grabber captures session screenshots; optional.
	Grabber screenshot.Grabber
}

// Engine runs scans.
type Engine struct {
	deps Dependencies
	// gather is swappable for tests.
	gather func(ctx context.Context, ep model.Endpoint, opts rdp.Options) (rdp.GatherResult, error)
	// loadWordlist is swappable for tests.
	loadWordlist func(path string) ([]string, error)
}

// New creates a scan engine.
func New(deps Dependencies) *Engine {
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	return &Engine{
		deps:         deps,
		gather:       rdp.Gather,
		loadWordlist: brute.LoadWordlist,
	}
}

// Run executes one scan to completion (or cancellation) and persists results.
func (e *Engine) Run(ctx context.Context, scan *model.Scan, endpoints []model.Endpoint) {
	logger := e.deps.Logger.With("scan_id", scan.ID)
	now := time.Now().UTC()
	scan.Status = model.ScanRunning
	scan.StartedAt = &now
	scan.Progress = model.Progress{Total: int64(len(endpoints))}
	e.persistScan(*scan)
	e.publish(model.Event{Type: model.EventScanStarted, ScanID: scan.ID, At: now, Payload: scan.Progress})

	var candidates []model.Credential
	if scan.Options.EnableAuth && scan.Options.Acknowledged {
		var err error
		candidates, err = e.loadCandidates(scan.Options)
		if err != nil {
			logger.Warn("credential audit disabled", "reason", err.Error())
			e.log(scan.ID, "warn", "credential audit disabled: "+err.Error())
		}
	}
	screensEnabled := scan.Options.EnableScreens && scan.Options.Acknowledged && e.deps.Grabber != nil
	if screensEnabled {
		if err := e.deps.Grabber.Available(); err != nil {
			logger.Warn("screenshot capture disabled", "reason", err.Error())
			e.log(scan.ID, "warn", "screenshot capture disabled: "+err.Error())
			screensEnabled = false
		}
	}

	var (
		progress    = &scan.Progress
		wg          sync.WaitGroup
		rateLimiter = NewLimiter(scan.Options.RatePerSecond)
	)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan model.Endpoint)
	workers := scan.Options.Concurrency
	if workers <= 0 {
		workers = 64
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ep := range jobs {
				if ctx.Err() != nil {
					atomic.AddInt64(&progress.Done, 1)
					continue
				}
				if err := rateLimiter.Wait(ctx); err != nil {
					atomic.AddInt64(&progress.Done, 1)
					continue
				}
				atomic.AddInt64(&progress.ActiveJobs, 1)
				e.processEndpoint(ctx, scan, ep, progress, candidates, screensEnabled)
				atomic.AddInt64(&progress.ActiveJobs, -1)
				atomic.AddInt64(&progress.Done, 1)
			}
		}()
	}

	// Periodic progress persistence and publication.
	tickerDone := make(chan struct{})
	var tickerWG sync.WaitGroup
	tickerWG.Add(1)
	go func() {
		defer tickerWG.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-tickerDone:
				return
			case <-ticker.C:
				e.publishProgress(scan.ID, progress)
			}
		}
	}()

	for _, ep := range endpoints {
		// Enqueue every endpoint even after cancellation: workers skip
		// cancelled work quickly, which keeps Done == Total so progress
		// accounting stays consistent for the UI and the reports.
		jobs <- ep
	}
	close(jobs)
	wg.Wait()
	close(tickerDone)
	tickerWG.Wait()

	finished := time.Now().UTC()
	scan.FinishedAt = &finished
	if ctx.Err() != nil {
		scan.Status = model.ScanCancelled
	} else {
		scan.Status = model.ScanCompleted
	}
	e.persistScan(*scan)
	e.publishProgress(scan.ID, progress)
	e.publish(model.Event{Type: model.EventScanFinished, ScanID: scan.ID, At: finished, Payload: snapshotProgress(progress)})
	final := snapshotProgress(progress)
	logger.Info("scan finished", "status", scan.Status, "done", final.Done, "open", final.Open,
		"findings", final.Findings, "credentials", final.Creds, "screenshots", final.Screens)
}

// processEndpoint performs recon and the optional stages for a single endpoint.
func (e *Engine) processEndpoint(ctx context.Context, scan *model.Scan, ep model.Endpoint,
	progress *model.Progress, candidates []model.Credential, screensEnabled bool) {

	logger := e.deps.Logger.With("scan_id", scan.ID, "target", ep.Key())
	host := model.Host{
		ScanID:    scan.ID,
		Endpoint:  ep,
		State:     "filtered",
		UpdatedAt: time.Now().UTC(),
	}

	result, err := e.gather(ctx, ep, rdp.Options{
		Timeout:       time.Duration(scan.Options.TimeoutMS) * time.Millisecond,
		ProbeBlueKeep: scan.Options.EnableVuln,
	})
	switch {
	case err == nil:
		host.State = "open"
		svc := result.Service
		host.Service = &svc
		atomic.AddInt64(&progress.Open, 1)
	case errors.Is(err, rdp.ErrTimeout):
		host.State = "filtered"
		atomic.AddInt64(&progress.Closed, 1)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		host.State = "cancelled"
	default:
		host.State = "closed"
		atomic.AddInt64(&progress.Closed, 1)
	}

	hostID, err := e.deps.Store.UpsertHost(host)
	if err != nil {
		logger.Error("persist host", "error", err.Error())
	} else {
		host.ID = hostID
	}
	e.publish(model.Event{Type: model.EventHostDone, ScanID: scan.ID, At: time.Now().UTC(), Payload: host})

	if host.State != "open" {
		return
	}

	if scan.Options.EnableVuln {
		findings := vuln.Evaluate(ep, vuln.Input{Service: host.Service, BlueKeep: result.BlueKeep})
		for _, finding := range findings {
			finding.ScanID = scan.ID
			finding.HostID = hostID
			id, err := e.deps.Store.InsertFinding(finding)
			if err != nil {
				logger.Error("persist finding", "check", finding.CheckID, "error", err.Error())
				continue
			}
			finding.ID = id
			atomic.AddInt64(&progress.Findings, 1)
			e.publish(model.Event{Type: model.EventFinding, ScanID: scan.ID, At: finding.DetectedAt, Payload: finding})
		}
	}

	if len(candidates) == 0 {
		return
	}
	cred, ok := e.auditCredentials(ctx, scan, ep, hostID, candidates, progress, logger)
	if !ok || !screensEnabled {
		return
	}
	e.captureScreenshot(ctx, scan, ep, hostID, cred, progress, logger)
}

// auditCredentials runs the fail-safe credential audit for one endpoint and
// stores any verified credential. It reports whether one was found.
func (e *Engine) auditCredentials(ctx context.Context, scan *model.Scan, ep model.Endpoint,
	hostID int64, candidates []model.Credential, progress *model.Progress, logger *slog.Logger) (model.Credential, bool) {

	if e.deps.Authenticator == nil {
		return model.Credential{}, false
	}
	hooks := brute.Hooks{
		OnSuccess: func(cred model.Credential) {
			e.log(scan.ID, "info", fmt.Sprintf("verified credential on %s for user %q", ep.Key(), cred.Username))
		},
	}
	engine := brute.New(e.deps.Authenticator, brute.Options{
		MaxFailuresPerHost: scan.Options.MaxAuthFailures,
	}, hooks, logger)

	res, err := engine.Run(ctx, ep, hostID, scan.ID, candidates)
	if err != nil && !errors.Is(err, context.Canceled) {
		logger.Warn("credential audit stopped", "reason", err.Error())
	}
	if res.LockedOut {
		e.log(scan.ID, "warn", fmt.Sprintf("account lockout reported by %s; audit stopped for this host", ep.Key()))
	}
	for _, cred := range res.Credentials {
		id, err := e.deps.Store.InsertCredential(cred)
		if err != nil {
			logger.Error("persist credential", "error", err.Error())
			continue
		}
		cred.ID = id
		atomic.AddInt64(&progress.Creds, 1)
		e.publish(model.Event{Type: model.EventCredential, ScanID: scan.ID, At: cred.VerifiedAt, Payload: cred.Masked()})
	}
	if len(res.Credentials) > 0 {
		return res.Credentials[0], true
	}
	return model.Credential{}, false
}

// captureScreenshot stores a session image for a verified credential.
func (e *Engine) captureScreenshot(ctx context.Context, scan *model.Scan, ep model.Endpoint,
	hostID int64, cred model.Credential, progress *model.Progress, logger *slog.Logger) {

	shot, err := e.deps.Grabber.Grab(ctx, ep, cred)
	if err != nil {
		logger.Warn("screenshot capture failed", "error", err.Error())
		e.log(scan.ID, "warn", fmt.Sprintf("screenshot capture failed for %s: %v", ep.Key(), err))
		return
	}
	shot.ScanID = scan.ID
	shot.HostID = hostID
	id, err := e.deps.Store.InsertScreenshot(shot)
	if err != nil {
		logger.Error("persist screenshot", "error", err.Error())
		return
	}
	shot.ID = id
	atomic.AddInt64(&progress.Screens, 1)
	e.publish(model.Event{Type: model.EventScreenshot, ScanID: scan.ID, At: shot.CapturedAt, Payload: shot})
}

func (e *Engine) loadCandidates(opts model.ScanOptions) ([]model.Credential, error) {
	users, err := e.loadWordlist(opts.UserWordlist)
	if err != nil {
		return nil, err
	}
	passwords, err := e.loadWordlist(opts.PasswordWordlist)
	if err != nil {
		return nil, err
	}
	return brute.BuildCandidates(users, passwords)
}

func (e *Engine) persistScan(scan model.Scan) {
	if err := e.deps.Store.UpdateScan(scan); err != nil {
		e.deps.Logger.Error("persist scan", "scan_id", scan.ID, "error", err.Error())
	}
}

func (e *Engine) publishProgress(scanID string, progress *model.Progress) {
	e.publish(model.Event{Type: model.EventScanProgress, ScanID: scanID, At: time.Now().UTC(),
		Payload: snapshotProgress(progress)})
}

// snapshotProgress copies the counters with atomic loads: workers update them
// concurrently with the periodic publisher.
func snapshotProgress(p *model.Progress) model.Progress {
	return model.Progress{
		Total:      atomic.LoadInt64(&p.Total),
		Done:       atomic.LoadInt64(&p.Done),
		Open:       atomic.LoadInt64(&p.Open),
		Closed:     atomic.LoadInt64(&p.Closed),
		Findings:   atomic.LoadInt64(&p.Findings),
		Creds:      atomic.LoadInt64(&p.Creds),
		Screens:    atomic.LoadInt64(&p.Screens),
		ActiveJobs: atomic.LoadInt64(&p.ActiveJobs),
	}
}

func (e *Engine) publish(ev model.Event) {
	if e.deps.Hub != nil {
		e.deps.Hub.Publish(ev)
	}
}

func (e *Engine) log(scanID, level, message string) {
	e.publish(model.Event{
		Type:    model.EventLog,
		ScanID:  scanID,
		At:      time.Now().UTC(),
		Payload: model.LogPayload{Level: level, Message: message},
	})
}
