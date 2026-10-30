// Package server serves the rdpshot web UI and REST API. It renders the
// embedded templates, exposes read-only screenshot storage and streams live
// scan events over Server-Sent Events.
package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"rdpshot/internal/events"
	"rdpshot/internal/model"
	"rdpshot/internal/scanner"
	"rdpshot/internal/store"
	"rdpshot/web"
)

// Scan creation defaults applied when the request form omits a value.
const (
	defaultConcurrency = 64
	defaultRate        = 10.0
	defaultTimeout     = 5 * time.Second
	// defaultMaxAuthFailures bounds credential attempts per host; the quick
	// scan form has no field for it.
	defaultMaxAuthFailures = 5
	// absoluteMaxScanTargets is the hard ceiling when an operator sets an
	// explicit positive max_targets value. 0 / empty means unlimited.
	absoluteMaxScanTargets = 4000000
	// maxScanTimeout rejects per-connection timeouts that would hold worker
	// slots for unreasonable amounts of time.
	maxScanTimeout = 10 * time.Minute
	// maxFormBytes caps the size of a scan creation request body, including
	// uploaded wordlists.
	maxFormBytes = 6 << 20
	// maxWordlistUploadBytes caps one uploaded wordlist file.
	maxWordlistUploadBytes = 2 << 20
	// maxTargetsUploadBytes caps one uploaded targets list file.
	maxTargetsUploadBytes = 2 << 20
	// maxAuthFailureLimit is the highest finite per-host fail-safe the API
	// accepts (0 remains valid and means unlimited).
	maxAuthFailureLimit = 50
	// recentEventsLimit bounds the in-memory recent event buffer used by the
	// dashboard data.
	recentEventsLimit = 50
	// scanStopGrace bounds how long shutdown waits for in-flight scan workers
	// to unwind after cancellation. It is deliberately short so Ctrl+C stops
	// the process immediately instead of hanging on slow network probes.
	scanStopGrace = 300 * time.Millisecond
)

// Config configures the HTTP server.
type Config struct {
	Addr        string // listen address, e.g. "127.0.0.1:8722"
	Token       string // when non-empty, every route requires Authorization: Bearer <token> or ?token=
	OutputsDir  string // served read-only under /files/ (screenshot images)
	ToolVersion string // shown in reports/footer
	// UserWordlist and PasswordWordlist are the fallbacks used when a scan
	// request enables credential checks without supplying its own wordlists.
	UserWordlist     string
	PasswordWordlist string
	// MaxTargets bounds CIDR/host expansion for one API or schedule request.
	// Zero means unlimited.
	MaxTargets int
	// MaxConcurrentScans bounds how many engine runs execute at once.
	// Zero defaults to 2. Excess scans stay pending until a slot frees.
	MaxConcurrentScans int
}

// Dependencies are the collaborators the server reads from and starts work on.
type Dependencies struct {
	Store  *store.Store
	Hub    *events.Hub
	Engine *scanner.Engine
	Logger *slog.Logger
}

// Server is the HTTP server for the web UI and REST API.
type Server struct {
	cfg  Config
	deps Dependencies
	tpl  *template.Template

	handler http.Handler

	// runs tracks the cancellable context and pause control of every scan
	// started through the API so the lifecycle endpoints can drive it.
	runsMu sync.Mutex
	runs   map[string]*scanRun
	runsWG sync.WaitGroup

	// recent buffers the latest events for the dashboard data source.
	recentMu sync.Mutex
	recent   []model.Event

	// Runtime-editable wordlist defaults. They start from Config and can be
	// updated from the UI without restarting the server.
	wordlistMu       sync.RWMutex
	userWordlist     string
	passwordWordlist string

	// sessions holds short-lived login tokens for local portal users.
	sessionsMu sync.Mutex
	sessions   map[string]*session

	// scanSlots limits concurrent engine runs; waiters stay pending.
	scanSlots chan struct{}
}

// New builds a server from configuration and dependencies.
func New(cfg Config, deps Dependencies) (*Server, error) {
	if deps.Store == nil {
		return nil, errors.New("server: store is required")
	}
	if deps.Engine == nil {
		return nil, errors.New("server: scanner engine is required")
	}
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	tpl, err := parseTemplates(cfg.ToolVersion)
	if err != nil {
		return nil, err
	}
	if cfg.MaxTargets < 0 {
		cfg.MaxTargets = 0
	}
	if cfg.MaxTargets > absoluteMaxScanTargets {
		cfg.MaxTargets = absoluteMaxScanTargets
	}
	maxConc := cfg.MaxConcurrentScans
	if maxConc <= 0 {
		maxConc = 2
	}
	s := &Server{
		cfg:              cfg,
		deps:             deps,
		tpl:              tpl,
		runs:             make(map[string]*scanRun),
		userWordlist:     cfg.UserWordlist,
		passwordWordlist: cfg.PasswordWordlist,
		scanSlots:        make(chan struct{}, maxConc),
	}
	s.handler = s.routes()
	if deps.Hub != nil {
		go s.recordRecentEvents()
	}
	return s, nil
}

// wordlistDefaults returns the current server-side default wordlist paths.
func (s *Server) wordlistDefaults() (userPath, passwordPath string) {
	s.wordlistMu.RLock()
	defer s.wordlistMu.RUnlock()
	return s.userWordlist, s.passwordWordlist
}

// setWordlistDefaults updates the runtime default wordlist paths used when a
// scan enables auth without uploading files.
func (s *Server) setWordlistDefaults(userPath, passwordPath string) {
	s.wordlistMu.Lock()
	defer s.wordlistMu.Unlock()
	s.userWordlist = userPath
	s.passwordWordlist = passwordPath
}

// wordlistPicker builds the shared UI control for one form.
func (s *Server) wordlistPicker(idPrefix string) WordlistPickerData {
	userPath, passwordPath := s.wordlistDefaults()
	return WordlistPickerData{
		IDPrefix:     idPrefix,
		UserPath:     userPath,
		PasswordPath: passwordPath,
	}
}

// Handler returns the HTTP handler for use with custom listeners or tests.
func (s *Server) Handler() http.Handler {
	return s.handler
}

// ListenAndServe serves until ctx is cancelled, then shuts down gracefully and
// cancels any scan still running.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if s.cfg.Addr == "" {
		return errors.New("server: listen address is required")
	}
	srv := &http.Server{
		Addr:              s.cfg.Addr,
		Handler:           s.handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	schedCtx, stopScheduler := context.WithCancel(ctx)
	defer stopScheduler()
	go s.runScheduler(schedCtx)

	errCh := make(chan error, 1)
	go func() {
		s.deps.Logger.Info("http server listening", "addr", s.cfg.Addr)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		stopScheduler()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("server: listen on %s: %w", s.cfg.Addr, err)
	case <-ctx.Done():
		s.deps.Logger.Info("shutdown requested; stopping scans and web server")
		stopScheduler()
		s.cancelAllScans()
		// Close tears down the listener and every active connection (including
		// SSE streams) immediately. Shutdown would wait for idle clients and
		// make Ctrl+C feel unresponsive.
		if err := srv.Close(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("server: close: %w", err)
		}
		// ListenAndServe has returned ErrServerClosed by now; drain it so the
		// goroutine can exit.
		<-errCh
		s.deps.Logger.Info("http server stopped")
		return nil
	}
}

// routes builds the mux with every UI and API route.
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", s.handleDashboard)
	mux.HandleFunc("GET /scans", s.handleScans)
	mux.HandleFunc("GET /scans/{id}", s.handleScanDetail)
	mux.HandleFunc("GET /compare", s.handleCompare)
	mux.HandleFunc("GET /estate", s.handleEstatePage)
	mux.HandleFunc("GET /engagements", s.handleEngagementsPage)
	mux.HandleFunc("GET /schedules", s.handleSchedulesPage)
	mux.HandleFunc("GET /gallery", s.handleGallery)
	mux.HandleFunc("GET /reports", s.handleReports)
	mux.HandleFunc("GET /about", s.handleAbout)
	mux.Handle("GET /static/", http.FileServer(http.FS(web.FS)))
	mux.Handle("GET /files/", s.filesHandler())

	mux.HandleFunc("POST /api/v1/scans", s.handleCreateScan)
	mux.HandleFunc("GET /api/v1/scans", s.handleListScans)
	mux.HandleFunc("GET /api/v1/scans/{id}", s.handleGetScan)
	mux.HandleFunc("PATCH /api/v1/scans/{id}", s.handleRenameScan)
	mux.HandleFunc("DELETE /api/v1/scans/{id}", s.handleDeleteScan)
	mux.HandleFunc("POST /api/v1/scans/{id}/cancel", s.handleCancelScan)
	mux.HandleFunc("POST /api/v1/scans/{id}/pause", s.handlePauseScan)
	mux.HandleFunc("POST /api/v1/scans/{id}/resume", s.handleResumeScan)
	mux.HandleFunc("POST /api/v1/scans/{id}/brute", s.handleBruteForceScan)
	mux.HandleFunc("GET /api/v1/scans/{id}/diff", s.handleScanDiff)
	mux.HandleFunc("GET /api/v1/scans/{id}/findings", s.handleScanFindings)
	mux.HandleFunc("GET /api/v1/scans/{id}/hosts", s.handleScanHosts)
	mux.HandleFunc("GET /api/v1/scans/{id}/screenshots", s.handleScanScreenshots)
	mux.HandleFunc("GET /api/v1/scans/{id}/credentials", s.handleScanCredentials)
	mux.HandleFunc("GET /api/v1/scans/{id}/report", s.handleScanReport)
	mux.HandleFunc("GET /api/v1/schedules", s.handleListSchedules)
	mux.HandleFunc("POST /api/v1/schedules", s.handleCreateSchedule)
	mux.HandleFunc("GET /api/v1/schedules/{id}", s.handleGetSchedule)
	mux.HandleFunc("PATCH /api/v1/schedules/{id}", s.handleUpdateSchedule)
	mux.HandleFunc("DELETE /api/v1/schedules/{id}", s.handleDeleteSchedule)
	mux.HandleFunc("GET /api/v1/summary", s.handleSummary)
	mux.HandleFunc("GET /api/v1/about", s.handleAPIAbout)
	mux.HandleFunc("GET /api/v1/analytics", s.handleAnalytics)
	mux.HandleFunc("GET /api/v1/trend", s.handleTrend)
	mux.HandleFunc("GET /api/v1/settings/wordlists", s.handleGetWordlistSettings)
	mux.HandleFunc("PATCH /api/v1/settings/wordlists", s.handleUpdateWordlistSettings)
	mux.HandleFunc("GET /api/v1/settings/branding", s.handleGetBranding)
	mux.HandleFunc("PUT /api/v1/settings/branding", s.handlePutBranding)
	mux.HandleFunc("GET /api/v1/wordlist-sets", s.handleListWordlistSets)
	mux.HandleFunc("POST /api/v1/wordlist-sets", s.handleCreateWordlistSet)
	mux.HandleFunc("DELETE /api/v1/wordlist-sets/{id}", s.handleDeleteWordlistSet)
	mux.HandleFunc("POST /api/v1/login", s.handleLogin)
	mux.HandleFunc("GET /api/v1/users", s.handleListUsers)
	mux.HandleFunc("POST /api/v1/users", s.handleCreateUser)
	mux.HandleFunc("DELETE /api/v1/users/{id}", s.handleDeleteUser)
	mux.HandleFunc("GET /api/v1/audit", s.handleListAudit)
	mux.HandleFunc("PATCH /api/v1/findings/{fid}/triage", s.handleUpdateFindingTriage)
	mux.HandleFunc("PATCH /api/v1/scans/{id}/meta", s.handleUpdateScanMeta)
	mux.HandleFunc("GET /api/v1/scans/{id}/evidence-pack", s.handleEvidencePack)
	mux.HandleFunc("GET /api/v1/scans/{id}/score", s.handleScanScore)
	mux.HandleFunc("GET /api/v1/scans/{id}/policy", s.handleScanPolicy)
	mux.HandleFunc("GET /api/v1/scans/{id}/reuse", s.handleCredentialReuse)
	mux.HandleFunc("GET /api/v1/estate", s.handleEstate)
	mux.HandleFunc("GET /api/v1/policy", s.handleGetPolicy)
	mux.HandleFunc("PUT /api/v1/policy", s.handlePutPolicy)
	mux.HandleFunc("GET /api/v1/settings/siem", s.handleGetSIEM)
	mux.HandleFunc("PUT /api/v1/settings/siem", s.handlePutSIEM)
	mux.HandleFunc("POST /api/v1/engagements/freeze", s.handleFreezeEngagement)
	mux.HandleFunc("GET /api/v1/engagements/scope", s.handleGetEngagementScope)
	mux.HandleFunc("GET /api/v1/engagements", s.handleListEngagements)
	mux.HandleFunc("GET /api/v1/playbooks", s.handleListPlaybooks)
	mux.HandleFunc("GET /api/v1/playbooks/{check_id}", s.handleGetPlaybook)
	mux.HandleFunc("POST /api/v1/findings/bulk-triage", s.handleBulkTriage)
	mux.HandleFunc("GET /api/v1/host-notes", s.handleListHostNotes)
	mux.HandleFunc("PUT /api/v1/host-notes", s.handleUpsertHostNote)
	mux.HandleFunc("DELETE /api/v1/host-notes/{id}", s.handleDeleteHostNote)
	mux.HandleFunc("GET /api/v1/settings/alerts", s.handleGetAlertRules)
	mux.HandleFunc("PUT /api/v1/settings/alerts", s.handlePutAlertRules)
	mux.HandleFunc("GET /api/v1/events", s.handleEvents)

	// Catch-all: unknown paths render the small HTML error page (or JSON when
	// under /api/), so the UI never falls through to net/http's plain text.
	mux.HandleFunc("/", s.handleNotFound)

	var handler http.Handler = mux
	handler = s.withRequestLogging(handler)
	handler = s.withAuth(handler)
	handler = s.withSecurityHeaders(handler)
	return handler
}

// filesHandler serves captured screenshots read-only from cfg.OutputsDir.
// http.Dir rejects any path that escapes the root, so no traversal is possible.
func (s *Server) filesHandler() http.Handler {
	if s.cfg.OutputsDir == "" {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.writeAPIError(w, http.StatusNotFound, "file storage is not configured")
		})
	}
	return http.StripPrefix("/files", http.FileServer(http.Dir(s.cfg.OutputsDir)))
}

// screenshotURL maps a stored screenshot path to its read-only web URL.
func screenshotURL(path string) string {
	return "/files/screenshots/" + url.PathEscape(filepath.Base(path))
}

// screenshotView returns a copy of the screenshot with FilePath rewritten to
// the web URL used by pages, API responses and exported reports.
func screenshotView(sc model.Screenshot) model.Screenshot {
	sc.FilePath = screenshotURL(sc.FilePath)
	return sc
}

// scanRun tracks the live control surface of one scan started by this server.
type scanRun struct {
	cancel  context.CancelFunc
	control *scanner.RunControl
}

// startScan registers a cancellable run for a freshly created scan and starts
// the scan engine in the background once a concurrency slot is available.
func (s *Server) startScan(scan model.Scan, endpoints []model.Endpoint) {
	ctx, cancel := context.WithCancel(context.Background())
	control := scanner.NewRunControl(func(status model.ScanStatus, progress model.Progress) {
		s.persistScanState(scan.ID, status, progress)
	})
	s.runsMu.Lock()
	s.runs[scan.ID] = &scanRun{cancel: cancel, control: control}
	s.runsMu.Unlock()
	s.runsWG.Add(1)
	go func() {
		defer func() {
			s.runsMu.Lock()
			delete(s.runs, scan.ID)
			s.runsMu.Unlock()
			cancel()
			s.runsWG.Done()
		}()
		select {
		case s.scanSlots <- struct{}{}:
			defer func() { <-s.scanSlots }()
		case <-ctx.Done():
			finished, err := s.deps.Store.GetScan(scan.ID)
			if err == nil && finished.Status == model.ScanPending {
				finished.Status = model.ScanCancelled
				now := time.Now().UTC()
				finished.FinishedAt = &now
				_ = s.deps.Store.UpdateScan(finished)
			}
			return
		}
		running := scan
		s.deps.Engine.RunWithControl(ctx, &running, endpoints, control)
		finished, err := s.deps.Store.GetScan(scan.ID)
		if err == nil {
			s.maybeNotifyScan(finished)
			s.maybeStreamSIEM(finished)
			s.maybeFireAlerts(finished)
		}
	}()
	s.deps.Logger.Info("scan queued", "scan_id", scan.ID, "endpoints", len(endpoints),
		"max_concurrent", cap(s.scanSlots))
}

// persistScanState stores a pause/resume transition and its progress snapshot.
// Live counters only exist in memory while a scan runs, so persisting them here
// keeps the stored record consistent with what the UI shows.
func (s *Server) persistScanState(scanID string, status model.ScanStatus, progress model.Progress) {
	current, err := s.deps.Store.GetScan(scanID)
	if err != nil {
		s.deps.Logger.Error("load scan for state change", "scan_id", scanID, "error", err.Error())
		return
	}
	current.Status = status
	current.Progress = progress
	if err := s.deps.Store.UpdateScan(current); err != nil {
		s.deps.Logger.Error("persist scan state", "scan_id", scanID, "error", err.Error())
	}
}

// scanControl returns the pause control of a scan running on this server.
func (s *Server) scanControl(scanID string) *scanner.RunControl {
	s.runsMu.Lock()
	defer s.runsMu.Unlock()
	run, ok := s.runs[scanID]
	if !ok {
		return nil
	}
	return run.control
}

// cancelScan requests cancellation of a tracked scan run. It reports whether a
// tracked run existed.
func (s *Server) cancelScan(scanID string) bool {
	s.runsMu.Lock()
	run, ok := s.runs[scanID]
	s.runsMu.Unlock()
	if ok {
		run.cancel()
	}
	return ok
}

// waitScanStopped blocks until the scan is no longer tracked in s.runs or the
// timeout elapses. Used before DeleteScan to avoid orphan host rows.
func (s *Server) waitScanStopped(scanID string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		s.runsMu.Lock()
		_, ok := s.runs[scanID]
		s.runsMu.Unlock()
		if !ok {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// cancelAllScans cancels every tracked run and waits briefly for the engines
// to unwind. The wait is bounded by scanStopGrace so shutdown stays snappy.
func (s *Server) cancelAllScans() {
	s.runsMu.Lock()
	for _, run := range s.runs {
		run.cancel()
	}
	s.runsMu.Unlock()
	done := make(chan struct{})
	go func() {
		s.runsWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(scanStopGrace):
	}
}

// recordRecentEvents keeps a bounded buffer of the latest events so the
// dashboard can render a short history without persistent event storage.
func (s *Server) recordRecentEvents() {
	sub := s.deps.Hub.Subscribe("")
	defer sub.Close()
	for ev := range sub.C() {
		s.recentMu.Lock()
		s.recent = append([]model.Event{ev}, s.recent...)
		if len(s.recent) > recentEventsLimit {
			s.recent = s.recent[:recentEventsLimit]
		}
		s.recentMu.Unlock()
	}
}

// recentEvents returns the buffered events, newest first.
func (s *Server) recentEvents() []model.Event {
	s.recentMu.Lock()
	defer s.recentMu.Unlock()
	out := make([]model.Event, len(s.recent))
	copy(out, s.recent)
	return out
}

// withSecurityHeaders hardens every response against common browser attacks.
func (s *Server) withSecurityHeaders(next http.Handler) http.Handler {
	csp := "default-src 'self'; " +
		"script-src 'self' https://cdn.tailwindcss.com https://cdn.jsdelivr.net" + inlineScriptHashes() + "; " +
		"style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; " +
		"img-src 'self' data:; connect-src 'self'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", csp)
		next.ServeHTTP(w, r)
	})
}

// inlineScriptHashes returns CSP source expressions for the executable inline
// <script> blocks of the embedded templates (for example the Tailwind config).
// Pinning them by hash keeps the policy strict instead of allowing
// 'unsafe-inline' for scripts.
//
// The hashes are computed from the template source, which is only valid while
// html/template leaves the block untouched. Inline scripts therefore must not
// contain Go template actions or JavaScript comments: the escaper strips
// comments from script bodies, and any such edit must re-hash the rendered
// output instead. TestInlineScriptHashesMatchRenderedPage guards this.
func inlineScriptHashes() string {
	entries, err := web.FS.ReadDir("templates")
	if err != nil {
		return ""
	}
	sources := []string{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".html") {
			continue
		}
		raw, err := web.FS.ReadFile("templates/" + entry.Name())
		if err != nil {
			continue
		}
		for _, block := range inlineScriptBlocks(string(raw)) {
			sum := sha256.Sum256([]byte(block))
			sources = append(sources, " 'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'")
		}
	}
	return strings.Join(sources, "")
}

// inlineScriptBlocks extracts the bodies of executable inline scripts (no
// external source, no non-JavaScript type attribute).
func inlineScriptBlocks(html string) []string {
	var blocks []string
	rest := html
	for {
		start := strings.Index(rest, "<script")
		if start < 0 {
			return blocks
		}
		openEnd := strings.Index(rest[start:], ">")
		if openEnd < 0 {
			return blocks
		}
		openTag := strings.ToLower(rest[start : start+openEnd])
		bodyStart := start + openEnd + 1
		end := strings.Index(rest[bodyStart:], "</script>")
		if end < 0 {
			return blocks
		}
		body := rest[bodyStart : bodyStart+end]
		rest = rest[bodyStart+end+len("</script>"):]
		if strings.Contains(openTag, "src=") || strings.Contains(openTag, "type=") {
			continue
		}
		blocks = append(blocks, body)
	}
}

// withAuth enforces the configured bearer token and/or a local user session.
// Login itself stays reachable so operators can obtain a session token.
func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/login" && r.Method == http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}
		if s.cfg.Token != "" {
			want := sha256.Sum256([]byte(s.cfg.Token))
			got := tokenFromRequest(r)
			hash := sha256.Sum256([]byte(got))
			if subtle.ConstantTimeCompare(hash[:], want[:]) == 1 {
				next.ServeHTTP(w, r)
				return
			}
		}
		if sess := s.sessionFromRequest(r); sess != nil {
			next.ServeHTTP(w, r)
			return
		}
		n, err := s.deps.Store.UserCount()
		if (err == nil && n > 0) || s.cfg.Token != "" {
			w.Header().Set("WWW-Authenticate", "Bearer")
			s.writeError(w, r, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// tokenFromRequest extracts the bearer token from the Authorization header or
// the ?token= query parameter.
func tokenFromRequest(r *http.Request) string {
	const prefix = "Bearer "
	if auth := r.Header.Get("Authorization"); len(auth) >= len(prefix) &&
		auth[:len(prefix)] == prefix {
		return auth[len(prefix):]
	}
	return r.URL.Query().Get("token")
}

// withRequestLogging records one debug line per request.
func (s *Server) withRequestLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		s.deps.Logger.Debug("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status(),
			"duration", time.Since(start).String(),
		)
	})
}

// statusRecorder captures the response status for logging while keeping the
// optional http.Flusher and http.ResponseController interfaces intact.
type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (w *statusRecorder) WriteHeader(code int) {
	w.code = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusRecorder) Write(b []byte) (int, error) {
	if w.code == 0 {
		w.code = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusRecorder) status() int {
	if w.code == 0 {
		return http.StatusOK
	}
	return w.code
}

// Flush forwards to the underlying writer so SSE streams keep flowing through
// the logging middleware.
func (w *statusRecorder) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap supports http.ResponseController.
func (w *statusRecorder) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// writeJSON encodes a JSON response body.
func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		s.deps.Logger.Error("encode json response", "error", err.Error())
	}
}

// writeAPIError writes the standard JSON error envelope for /api routes.
func (s *Server) writeAPIError(w http.ResponseWriter, status int, message string) {
	s.writeJSON(w, status, map[string]string{"error": message})
}

// writeError writes the error envelope for API requests and a small HTML error
// page for browser requests.
func (s *Server) writeError(w http.ResponseWriter, r *http.Request, status int, message string) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		s.writeAPIError(w, status, message)
		return
	}
	s.writePageError(w, status, message)
}

// writePageError renders the minimal HTML error page.
func (s *Server) writePageError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Error %d</title></head>
<body><h1>%d</h1><p>%s</p></body></html>
`, status, status, template.HTMLEscapeString(message))
}

// handleNotFound is the catch-all for unknown routes.
func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	s.writeError(w, r, http.StatusNotFound, "page not found")
}
