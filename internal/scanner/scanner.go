// Package scanner orchestrates reconnaissance, vulnerability checks and the
// optional intrusive stages (credential audit, screenshot capture) over a set
// of endpoints with bounded concurrency and paced connection attempts.
package scanner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"rdpshot/internal/auth"
	"rdpshot/internal/brute"
	"rdpshot/internal/discovery"
	"rdpshot/internal/events"
	"rdpshot/internal/kerberos"
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
	e.RunWithControl(ctx, scan, endpoints, nil)
}

// RunWithControl executes one scan with pause/resume support. A nil control is
// equivalent to Run. The control must not be reused for another scan.
func (e *Engine) RunWithControl(ctx context.Context, scan *model.Scan, endpoints []model.Endpoint, control *RunControl) {
	logger := e.deps.Logger.With("scan_id", scan.ID)
	now := time.Now().UTC()
	scan.Status = model.ScanRunning
	scan.StartedAt = &now
	scan.Progress = model.Progress{Total: int64(len(endpoints))}
	e.persistScan(*scan)

	if control == nil {
		control = NewRunControl(nil)
	}
	control.attach(&scan.Progress, func(eventType model.EventType, progress model.Progress) {
		e.publish(model.Event{Type: eventType, ScanID: scan.ID, At: time.Now().UTC(), Payload: progress})
	})
	defer control.finish()

	e.publish(model.Event{Type: model.EventScanStarted, ScanID: scan.ID, At: now, Payload: scan.Progress})

	var candidates []model.Credential
	if scan.Options.EnableAuth && scan.Options.Acknowledged {
		var err error
		candidates, err = e.loadCandidates(scan.Options)
		if err != nil {
			logger.Warn("credential audit disabled", "reason", err.Error())
			e.log(scan.ID, "warn", "credential audit disabled: "+err.Error())
		} else if reuse := e.loadReuseCredentials(scan); len(reuse) > 0 {
			candidates = mergeReuseCredentials(reuse, candidates)
			e.log(scan.ID, "info", fmt.Sprintf("smart credential audit: prepended %d previously verified credential(s)", len(reuse)))
		}
	}
	if scan.Options.BaseScanID != "" {
		endpoints = e.applyDeltaFilter(scan, endpoints, logger)
		scan.Progress.Total = int64(len(endpoints))
		e.persistScan(*scan)
	}
	e.prioritizeEndpoints(scan, endpoints)
	screensEnabled := scan.Options.Acknowledged && e.deps.Grabber != nil &&
		(scan.Options.EnableScreens || scan.Options.AuthModeImpliesScreenshot())
	if screensEnabled {
		if err := e.deps.Grabber.Available(); err != nil {
			logger.Warn("screenshot capture disabled", "reason", err.Error())
			e.log(scan.ID, "warn", "screenshot capture disabled: "+err.Error())
			screensEnabled = false
		} else if scan.Options.AuthModeImpliesScreenshot() {
			e.log(scan.ID, "info", "single/pth auth: screenshot after successful login, then disconnect")
		}
	}

	var (
		progress    = &scan.Progress
		wg          sync.WaitGroup
		rateLimiter = NewLimiter(scan.Options.RatePerSecond)
	)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if scan.Options.MaxRuntimeSec > 0 {
		var runtimeCancel context.CancelFunc
		ctx, runtimeCancel = context.WithTimeout(ctx, time.Duration(scan.Options.MaxRuntimeSec)*time.Second)
		defer runtimeCancel()
	}

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
				// A paused scan keeps its workers parked here so the remaining
				// endpoints stay queued instead of being probed or dropped.
				if err := control.wait(ctx); err != nil {
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
		if scan.Options.EnableDiscovery {
			disc := discovery.Probe(ctx, ep.Address)
			svc.RDWeb = disc.RDWeb
			svc.RDWebURL = disc.RDWebURL
			svc.RDGateway = disc.RDGateway
			svc.RDGatewayAuth = disc.RDGatewayAuth
			svc.UDP3389 = disc.UDP3389
			if svc.Evidence == nil {
				svc.Evidence = map[string]string{}
			}
			if disc.RDWebEvidence != "" {
				svc.Evidence["rd_web"] = disc.RDWebEvidence
			}
			if disc.RDGatewayEvidence != "" {
				svc.Evidence["rd_gateway"] = disc.RDGatewayEvidence
			}
			if disc.RDGatewayAuth != "" {
				svc.Evidence["rd_gateway_auth"] = disc.RDGatewayAuth
			}
			if disc.UDPEvidence != "" {
				svc.Evidence["udp_3389"] = disc.UDPEvidence
			}
		}
		if svc.NLARequired && kerberos.Available() {
			svc.KerberosOffered = true
			if svc.Evidence == nil {
				svc.Evidence = map[string]string{}
			}
			svc.Evidence["kerberos"] = "client offered Kerberos mech (ccache/keytab present)"
		}
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
		findings := vuln.Evaluate(ep, vuln.Input{
			Service: host.Service, BlueKeep: result.BlueKeep, TargetHost: ep.Address,
		})
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
		if errors.Is(err, auth.ErrSmartCardRequired) {
			e.recordSmartCardFinding(scan, ep, hostID, progress)
		}
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

func (e *Engine) recordSmartCardFinding(scan *model.Scan, ep model.Endpoint, hostID int64, progress *model.Progress) {
	if host, err := e.deps.Store.GetHost(hostID); err == nil && host.Service != nil {
		host.Service.SmartCardRequired = true
		if host.Service.Evidence == nil {
			host.Service.Evidence = map[string]string{}
		}
		host.Service.Evidence["smart_card"] = "NTSTATUS indicated smart-card logon"
		_, _ = e.deps.Store.UpsertHost(host)
	}
	finding := model.Finding{
		ScanID: scan.ID, HostID: hostID, Address: ep.Address, Port: ep.Port,
		CheckID: "nla-smartcard-required", Title: "Smart-card logon indicated by NLA",
		Severity: model.SeverityInfo, Status: model.FindingVulnerable,
		Evidence: "CredSSP/NLA reported smart-card logon requirement",
		Remediation: "Document smart-card requirements in the engagement ROE; password sprays will not succeed against these accounts.",
		DetectedAt: time.Now().UTC(),
	}
	id, err := e.deps.Store.InsertFinding(finding)
	if err != nil {
		return
	}
	finding.ID = id
	atomic.AddInt64(&progress.Findings, 1)
	e.publish(model.Event{Type: model.EventFinding, ScanID: scan.ID, At: finding.DetectedAt, Payload: finding})
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
	mode := strings.ToLower(strings.TrimSpace(opts.AuthMode))
	if mode == "" {
		mode = model.AuthModeWordlist
	}
	switch mode {
	case model.AuthModeSingle:
		return brute.BuildSingleCandidate(opts.AuthUsername, opts.AuthDomain, opts.AuthPassword)
	case model.AuthModePTH:
		return brute.BuildPTHCandidate(opts.AuthUsername, opts.AuthDomain, opts.AuthNTHash)
	case model.AuthModeWordlist:
		users, err := e.loadWordlist(opts.UserWordlist)
		if err != nil {
			return nil, err
		}
		passwords, err := e.loadWordlist(opts.PasswordWordlist)
		if err != nil {
			return nil, err
		}
		return brute.BuildCandidates(users, passwords, opts.AuthDomain)
	default:
		return nil, fmt.Errorf("scanner: unknown auth_mode %q (want wordlist|single|pth)", opts.AuthMode)
	}
}

func (e *Engine) loadReuseCredentials(scan *model.Scan) []model.Credential {
	if e.deps.Store == nil {
		return nil
	}
	// Prefer credentials from the base scan; otherwise any prior scan sharing
	// the same engagement label.
	var out []model.Credential
	if scan.Options.BaseScanID != "" {
		creds, err := e.deps.Store.ListCredentials(scan.Options.BaseScanID)
		if err == nil {
			out = append(out, creds...)
		}
	}
	if scan.Engagement == "" {
		return out
	}
	scans, err := e.deps.Store.ListScansFiltered(50, scan.Engagement, "")
	if err != nil {
		return out
	}
	seenScan := map[string]bool{scan.ID: true, scan.Options.BaseScanID: true}
	for _, sc := range scans {
		if seenScan[sc.ID] {
			continue
		}
		seenScan[sc.ID] = true
		creds, err := e.deps.Store.ListCredentials(sc.ID)
		if err != nil {
			continue
		}
		out = append(out, creds...)
		if len(out) >= 64 {
			break
		}
	}
	return out
}

func (e *Engine) applyDeltaFilter(scan *model.Scan, endpoints []model.Endpoint, logger *slog.Logger) []model.Endpoint {
	baseHosts, err := e.deps.Store.ListHosts(scan.Options.BaseScanID)
	if err != nil {
		logger.Warn("delta retest: base hosts unavailable", "base_scan_id", scan.Options.BaseScanID, "error", err.Error())
		return endpoints
	}
	baseFindings, err := e.deps.Store.ListFindings(scan.Options.BaseScanID)
	if err != nil {
		logger.Warn("delta retest: base findings unavailable", "base_scan_id", scan.Options.BaseScanID, "error", err.Error())
		return endpoints
	}
	filtered := FilterDeltaEndpoints(endpoints, baseHosts, baseFindings)
	logger.Info("delta retest filtered endpoints",
		"base_scan_id", scan.Options.BaseScanID,
		"before", len(endpoints), "after", len(filtered))
	e.log(scan.ID, "info", fmt.Sprintf("delta retest: %d of %d endpoints selected", len(filtered), len(endpoints)))
	return filtered
}

func (e *Engine) prioritizeEndpoints(scan *model.Scan, endpoints []model.Endpoint) {
	if e.deps.Store == nil || len(endpoints) == 0 {
		return
	}
	baseID := scan.Options.BaseScanID
	if baseID == "" {
		return
	}
	hosts, err := e.deps.Store.ListHosts(baseID)
	if err != nil {
		return
	}
	findings, err := e.deps.Store.ListFindings(baseID)
	if err != nil {
		return
	}
	PrioritizeEndpoints(endpoints, hosts, findings)
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
