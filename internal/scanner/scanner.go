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
	"rdpshot/internal/notify"
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
	// Grabber captures session screenshots after a verified login; optional.
	Grabber screenshot.Grabber
	// LoginScreen captures the pre-auth Winlogon UI over TLS without credentials.
	LoginScreen screenshot.LoginScreenGrabber
	// OpenEvidence is retained for wiring compatibility; open-host synthetic
	// detection cards are no longer persisted by captureOpenHostEvidence.
	OpenEvidence *screenshot.EvidenceGrabber
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
	// EnableScreens is the sole operator gate for every screenshot path
	// (post-login session, pre-auth Winlogon, evidence). single/pth do not
	// imply capture unless the checkbox/flag is also set.
	screensWanted := scan.Options.Acknowledged && scan.Options.EnableScreens
	screensEnabled := screensWanted && e.deps.Grabber != nil
	if screensEnabled {
		if err := e.deps.Grabber.Available(); err != nil {
			logger.Warn("screenshot capture disabled", "reason", err.Error())
			e.log(scan.ID, "warn", "screenshot capture disabled: "+err.Error())
			screensEnabled = false
		} else if scan.Options.AuthModeImpliesScreenshot() {
			e.log(scan.ID, "info", "single/pth auth: screenshot after successful login, then disconnect")
		}
	}

	ocrSeeds := newOCRUserSeed()
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
				e.processEndpoint(ctx, scan, ep, progress, candidates, screensWanted, screensEnabled, ocrSeeds)
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

	if url := strings.TrimSpace(scan.Options.WebhookURL); url != "" {
		summary, _ := e.deps.Store.Summary(scan.ID)
		crit := summary.CountBySeverity(model.SeverityCritical)
		hi := summary.CountBySeverity(model.SeverityHigh)
		p := notify.Payload{
			Event:      "scan.finished",
			At:         finished,
			ScanID:     scan.ID,
			ScanName:   scan.Name,
			Status:     string(scan.Status),
			Summary:    summary,
			Critical:   crit,
			High:       hi,
			Engagement: scan.Engagement,
			Detail:     fmt.Sprintf("Scan %q finished: %d hosts done, %d findings (Critical: %d, High: %d)", scan.Name, final.Done, final.Findings, crit, hi),
		}
		go func() {
			nctx, ncancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer ncancel()
			_ = notify.Webhook(nctx, url, p)
		}()
	}
}

// processEndpoint performs recon and the optional stages for a single endpoint.
// screensWanted gates every capture path; screensEnabled additionally requires
// a working post-login Grabber.
func (e *Engine) processEndpoint(ctx context.Context, scan *model.Scan, ep model.Endpoint,
	progress *model.Progress, candidates []model.Credential, screensWanted, screensEnabled bool, ocrSeeds *ocrUserSeed) {

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
		if scan.Options.EnableUDP {
			udpRes := rdp.ProbeRDPEUDP(ctx, ep, time.Duration(scan.Options.TimeoutMS)*time.Millisecond)
			if udpRes.Reachable {
				svc.UDP3389 = true
				svc.UDPRDPAcceleration = udpRes.SYNACK || udpRes.DTLSSupport
				svc.UDPEvidence = udpRes.Evidence
				if svc.Evidence == nil {
					svc.Evidence = map[string]string{}
				}
				svc.Evidence["udp_3389"] = udpRes.Evidence
			}
		}
		if svc.NLARequired {
			kst := kerberos.Probe()
			if kst.Available {
				svc.KerberosOffered = true
				if svc.Evidence == nil {
					svc.Evidence = map[string]string{}
				}
				svc.Evidence["kerberos"] = kerberos.SummaryLine(kst)
				svc.Evidence["kerberos_kind"] = kst.Kind
				if kst.Path != "" {
					svc.Evidence["kerberos_source"] = kst.Path
				}
			}
		}
		if scan.Options.EnableVuln && (svc.NegotiatedProtocol == rdp.ProtocolSSL || svc.NegotiatedProtocol == rdp.ProtocolHybrid || svc.NegotiatedProtocol == rdp.ProtocolHybridEx) {
			if prof, err := rdp.ProbeTLSProfile(ctx, ep, time.Duration(scan.Options.TimeoutMS)*time.Millisecond); err == nil && prof != nil {
				svc.SupportedTLSVersions = prof.SupportedVersions
				svc.WeakCiphers = prof.WeakCiphers
			}
			if svc.NegotiatedProtocol == rdp.ProtocolHybrid || svc.NegotiatedProtocol == rdp.ProtocolHybridEx {
				if down, err := rdp.ProbeNLADowngrade(ctx, ep, time.Duration(scan.Options.TimeoutMS)*time.Millisecond); err == nil && down.Vulnerable {
					svc.NLADowngradeVulnerable = true
					svc.NLADowngradeEvidence = down.Evidence
				}
			}
		}
		mfaPAM := rdp.DetectMFAPAM(&svc)
		if mfaPAM.MFAEnforced {
			svc.MFAEnforced = true
			if svc.Evidence == nil {
				svc.Evidence = map[string]string{}
			}
			svc.Evidence["mfa"] = mfaPAM.Evidence
		}
		if mfaPAM.PAMProxyDetected {
			svc.PAMProxy = true
			if svc.Evidence == nil {
				svc.Evidence = map[string]string{}
			}
			svc.Evidence["pam"] = mfaPAM.Evidence
		}
		if mfaPAM.Provider != "" {
			svc.SecurityGateway = string(mfaPAM.Provider)
		}
		honeypot := rdp.DetectHoneypot(&svc)
		if honeypot.IsHoneypot {
			svc.HoneypotDetected = true
			svc.HoneypotReason = honeypot.Reason
			if svc.Evidence == nil {
				svc.Evidence = map[string]string{}
			}
			svc.Evidence["honeypot"] = honeypot.Evidence
		}
		shadow := rdp.EvaluateShadowPosture(&svc)
		svc.ShadowPolicy = shadow.PolicyName
		svc.ShadowUnprompted = shadow.Unprompted
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
			e.maybeNotifyFinding(scan, finding)
		}
	}

	nlaRequired := host.Service != nil && host.Service.NLARequired
	if len(candidates) == 0 {
		if screensWanted {
			e.captureOpenHostEvidence(ctx, scan, ep, hostID, host.Service, progress, logger, ocrSeeds)
		}
		return
	}
	if !nlaRequired {
		// CredSSP password audits require HYBRID/NLA. Capture Winlogon tiles
		// for OCR seeding when screenshots are enabled.
		if screensWanted {
			e.captureOpenHostEvidence(ctx, scan, ep, hostID, host.Service, progress, logger, ocrSeeds)
		}
		e.recordAuthSkipped(scan, ep, hostID, logger)
		return
	}
	hostCandidates := candidates
	if ocrSeeds != nil {
		if seeded := ocrSeeds.List(); len(seeded) > 0 {
			hostCandidates = brute.PrependOCRUsers(candidates, seeded, scan.Options.AuthDomain)
			if len(hostCandidates) > len(candidates) {
				e.log(scan.ID, "info", fmt.Sprintf(
					"OCR wordlist seed: prepended %d username(s) for %s",
					(len(hostCandidates)-len(candidates))/max(passwordCardinality(candidates), 1), ep.Key()))
			}
		}
	}
	cred, ok := e.auditCredentials(ctx, scan, ep, hostID, hostCandidates, progress, logger)
	if ok && screensEnabled {
		e.captureScreenshot(ctx, scan, ep, hostID, cred, progress, logger)
		return
	}
	// Failed or skipped login: try a real pre-auth Winlogon frame only when
	// the operator opted into screenshots.
	if !ok && screensWanted {
		e.captureOpenHostEvidence(ctx, scan, ep, hostID, host.Service, progress, logger, ocrSeeds)
	}
}

func passwordCardinality(candidates []model.Credential) int {
	seen := make(map[string]struct{}, len(candidates))
	for _, c := range candidates {
		seen[c.Secret] = struct{}{}
	}
	return len(seen)
}

// ocrUserSeed collects login-screen usernames for scan-wide wordlist prepend.
type ocrUserSeed struct {
	mu    sync.Mutex
	users []string
	seen  map[string]struct{}
}

func newOCRUserSeed() *ocrUserSeed {
	return &ocrUserSeed{seen: make(map[string]struct{})}
}

func (s *ocrUserSeed) Add(users []string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range users {
		u = strings.TrimSpace(u)
		if u == "" || strings.EqualFold(u, "Other user") {
			continue
		}
		key := strings.ToLower(u)
		if _, ok := s.seen[key]; ok {
			continue
		}
		s.seen[key] = struct{}{}
		s.users = append(s.users, u)
	}
}

func (s *ocrUserSeed) List() []string {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.users))
	copy(out, s.users)
	return out
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
		OnFailure: func(cred model.Credential, err error) {
			e.log(scan.ID, "info", fmt.Sprintf("rejected credential on %s for user %q", ep.Key(), cred.Username))
			_ = err
		},
		OnAttempt: func(cred model.Credential, outcome, detail string) {
			// Timeline UI only surfaces verified logins; rejected/skipped rows
			// stay out of auth_attempts to avoid noise.
			if outcome != model.AuthOutcomeSuccess {
				return
			}
			e.persistAuthAttempt(model.AuthAttempt{
				ScanID: scan.ID, HostID: hostID, Address: ep.Address, Port: ep.Port,
				Username: cred.Username, Domain: cred.Domain, Outcome: outcome, Detail: detail,
				AttemptedAt: time.Now().UTC(),
			}, logger)
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
	e.persistAuthSummary(hostID, res.Attempts, res.Failures, res.StoppedReason, logger)
	e.log(scan.ID, "info", fmt.Sprintf(
		"credential audit on %s: attempts=%d failures=%d stopped=%s",
		ep.Key(), res.Attempts, res.Failures, res.StoppedReason))
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

func (e *Engine) recordAuthSkipped(scan *model.Scan, ep model.Endpoint, hostID int64, logger *slog.Logger) {
	reason := brute.StopReasonNoCredSSP
	e.persistAuthSummary(hostID, 0, 0, reason, logger)
	e.log(scan.ID, "info", fmt.Sprintf("credential audit skipped for %s: %s", ep.Key(), reason))
}

func (e *Engine) persistAuthSummary(hostID int64, attempts, failures int, reason string, logger *slog.Logger) {
	if hostID == 0 || e.deps.Store == nil {
		return
	}
	host, err := e.deps.Store.GetHost(hostID)
	if err != nil {
		logger.Warn("load host for auth summary", "error", err.Error())
		return
	}
	if host.Service == nil {
		host.Service = &model.ServiceInfo{}
	}
	if host.Service.Evidence == nil {
		host.Service.Evidence = map[string]string{}
	}
	host.Service.AuthAttempts = attempts
	host.Service.AuthFailures = failures
	host.Service.AuthStoppedReason = reason
	host.Service.Evidence["auth_attempts"] = fmt.Sprintf("%d", attempts)
	host.Service.Evidence["auth_failures"] = fmt.Sprintf("%d", failures)
	host.Service.Evidence["auth_stopped_reason"] = reason
	if reason == brute.StopReasonNoCredSSP {
		host.Service.Evidence["auth_path"] = "skipped_no_credssp"
	} else if attempts > 0 {
		host.Service.Evidence["auth_path"] = "credssp"
	}
	host.UpdatedAt = time.Now().UTC()
	if _, err := e.deps.Store.UpsertHost(host); err != nil {
		logger.Warn("persist auth summary", "error", err.Error())
	}
}

func (e *Engine) persistAuthAttempt(a model.AuthAttempt, logger *slog.Logger) {
	if e.deps.Store == nil {
		return
	}
	if _, err := e.deps.Store.InsertAuthAttempt(a); err != nil {
		logger.Warn("persist auth attempt", "error", err.Error())
	}
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
		Evidence:    "CredSSP/NLA reported smart-card logon requirement",
		Remediation: "Document smart-card requirements in the engagement ROE; password sprays will not succeed against these accounts.",
		DetectedAt:  time.Now().UTC(),
	}
	id, err := e.deps.Store.InsertFinding(finding)
	if err != nil {
		return
	}
	finding.ID = id
	atomic.AddInt64(&progress.Findings, 1)
	e.publish(model.Event{Type: model.EventFinding, ScanID: scan.ID, At: finding.DetectedAt, Payload: finding})
	e.maybeNotifyFinding(scan, finding)
}

// captureOpenHostEvidence stores a live TLS login-screen capture when Winlogon
// is reachable without credentials. Negotiation may report HYBRID/NLA required
// while FreeRDP /sec:tls can still reach the pre-auth UI on some hosts, so this
// path always tries the grabber and lets it fail fast when Winlogon is blocked.
// Synthetic detection-evidence PNGs are not written.
func (e *Engine) captureOpenHostEvidence(ctx context.Context, scan *model.Scan, ep model.Endpoint,
	hostID int64, svc *model.ServiceInfo, progress *model.Progress, logger *slog.Logger, ocrSeeds *ocrUserSeed) {

	if e.deps.LoginScreen == nil || e.deps.LoginScreen.Available() != nil {
		return
	}
	shot, err := e.deps.LoginScreen.GrabLoginScreen(ctx, ep)
	if err != nil {
		reason := loginScreenSkipReason(err, svc)
		logger.Warn("login-screen capture unavailable; skipping screenshot",
			"error", err.Error(), "reason", reason)
		e.log(scan.ID, "warn", fmt.Sprintf(
			"login-screen capture skipped for %s: %s (%v)", ep.Key(), reason, err))
		e.recordLoginScreenSkip(hostID, reason, logger)
		return
	}
	e.persistScreenshot(scan, hostID, shot, progress, logger)
	e.recordLoginScreenUsers(ctx, scan, ep, hostID, shot.FilePath, progress, logger, ocrSeeds)
}

// loginScreenSkipReason maps grabber failures to a short operator-facing cause.
func loginScreenSkipReason(err error, svc *model.ServiceInfo) string {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "hybrid"), strings.Contains(msg, "credssp/nla"),
		strings.Contains(msg, "nla"):
		return "NLA/CredSSP required: pre-auth Winlogon and account-tile OCR are unreachable"
	case strings.Contains(msg, "blank"):
		return "login-screen frame was blank"
	case svc != nil && svc.NLARequired:
		return "NLA required by negotiation; pre-auth account tiles unavailable"
	default:
		return "pre-auth login UI unreachable"
	}
}

// recordLoginScreenSkip persists why login-screen / login_users evidence is absent.
func (e *Engine) recordLoginScreenSkip(hostID int64, reason string, logger *slog.Logger) {
	host, err := e.deps.Store.GetHost(hostID)
	if err != nil {
		logger.Warn("load host for login-screen skip", "error", err.Error())
		return
	}
	if host.Service == nil {
		host.Service = &model.ServiceInfo{}
	}
	if host.Service.Evidence == nil {
		host.Service.Evidence = map[string]string{}
	}
	host.Service.Evidence["login_screen"] = "skipped"
	host.Service.Evidence["login_screen_skip_reason"] = reason
	host.UpdatedAt = time.Now().UTC()
	if _, err := e.deps.Store.UpsertHost(host); err != nil {
		logger.Warn("persist login-screen skip reason", "error", err.Error())
	}
}

// recordLoginScreenUsers OCRs the Winlogon tile list and persists usernames on
// the host service info plus an informational finding when any are found.
func (e *Engine) recordLoginScreenUsers(ctx context.Context, scan *model.Scan, ep model.Endpoint,
	hostID int64, imagePath string, progress *model.Progress, logger *slog.Logger, ocrSeeds *ocrUserSeed) {

	ocr, err := screenshot.ExtractLoginUsersOCR(ctx, imagePath)
	if err != nil {
		logger.Warn("login-screen OCR failed", "error", err.Error())
		e.log(scan.ID, "warn", fmt.Sprintf("login-screen OCR failed for %s: %v", ep.Key(), err))
		ocr = screenshot.LoginUsersResult{}
	}
	users := ocr.Users
	host, err := e.deps.Store.GetHost(hostID)
	if err != nil {
		logger.Warn("load host for login users", "error", err.Error())
		return
	}
	if host.Service == nil {
		host.Service = &model.ServiceInfo{}
	}
	if host.Service.Evidence == nil {
		host.Service.Evidence = map[string]string{}
	}
	host.Service.Evidence["login_screen"] = "ssl-tls"
	host.Service.Evidence["login_users_quality"] = fmt.Sprintf("%.2f", ocr.Quality)
	if len(users) > 0 {
		host.Service.LoginUsers = users
		host.Service.Evidence["login_users"] = strings.Join(users, ", ")
		ocrSeeds.Add(users)
	}
	host.UpdatedAt = time.Now().UTC()
	if _, err := e.deps.Store.UpsertHost(host); err != nil {
		logger.Warn("persist login users", "error", err.Error())
		return
	}
	if len(users) == 0 {
		return
	}
	finding := model.Finding{
		ScanID: scan.ID, HostID: hostID, Address: ep.Address, Port: ep.Port,
		CheckID: "rdp-login-users-exposed", Title: "Logon screen exposes local account tiles",
		Severity: model.SeverityInfo, Status: model.FindingVulnerable,
		Evidence:    "Winlogon tiles visible without authentication: " + strings.Join(users, ", "),
		Remediation: "Discourage interactive account enumeration on the logon UI where policy allows; prefer credential prompts without listing local users.",
		DetectedAt:  time.Now().UTC(),
	}
	id, err := e.deps.Store.InsertFinding(finding)
	if err != nil {
		logger.Warn("persist login-users finding", "error", err.Error())
		return
	}
	finding.ID = id
	atomic.AddInt64(&progress.Findings, 1)
	e.publish(model.Event{Type: model.EventFinding, ScanID: scan.ID, At: finding.DetectedAt, Payload: finding})
	e.maybeNotifyFinding(scan, finding)
}

// captureScreenshot stores a session image for a verified credential.
func (e *Engine) captureScreenshot(ctx context.Context, scan *model.Scan, ep model.Endpoint,
	hostID int64, cred model.Credential, progress *model.Progress, logger *slog.Logger) {

	if e.deps.Grabber == nil {
		return
	}
	shot, err := e.deps.Grabber.Grab(ctx, ep, cred)
	if err != nil {
		logger.Warn("screenshot capture failed", "error", err.Error())
		e.log(scan.ID, "warn", fmt.Sprintf("screenshot capture failed for %s: %v", ep.Key(), err))
		return
	}
	e.persistScreenshot(scan, hostID, shot, progress, logger)
}

func (e *Engine) persistScreenshot(scan *model.Scan, hostID int64, shot model.Screenshot,
	progress *model.Progress, logger *slog.Logger) {

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
	case model.AuthModeKerberos:
		return brute.BuildKerberosCandidate(opts.AuthUsername, opts.AuthDomain, opts.AuthCCache)
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
		return nil, fmt.Errorf("scanner: unknown auth_mode %q (want wordlist|single|pth|kerberos)", opts.AuthMode)
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

func (e *Engine) maybeNotifyFinding(scan *model.Scan, f model.Finding) {
	url := strings.TrimSpace(scan.Options.WebhookURL)
	if url == "" {
		return
	}
	level := strings.ToLower(strings.TrimSpace(scan.Options.WebhookLevel))
	if level == "" {
		level = "critical"
	}
	shouldNotify := false
	switch level {
	case "all":
		shouldNotify = true
	case "high":
		shouldNotify = (f.Severity == model.SeverityCritical || f.Severity == model.SeverityHigh)
	case "critical":
		shouldNotify = (f.Severity == model.SeverityCritical)
	default:
		shouldNotify = (f.Severity == model.SeverityCritical)
	}
	if shouldNotify {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = notify.NotifyFinding(ctx, url, scan.ID, scan.Name, f)
		}()
	}
}
