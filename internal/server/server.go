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
	// maxScanTargets bounds target expansion for one API request.
	maxScanTargets = 65536
	// maxScanTimeout rejects per-connection timeouts that would hold worker
	// slots for unreasonable amounts of time.
	maxScanTimeout = 10 * time.Minute
	// maxFormBytes caps the size of a scan creation request body.
	maxFormBytes = 1 << 20
	// recentEventsLimit bounds the in-memory recent event buffer used by the
	// dashboard data.
	recentEventsLimit = 50
	// shutdownGrace bounds how long ListenAndServe waits for running scans
	// after cancellation before giving up on them.
	shutdownGrace = 5 * time.Second
)

// Config configures the HTTP server.
type Config struct {
	Addr        string // listen address, e.g. "127.0.0.1:8722"
	Token       string // when non-empty, every route requires Authorization: Bearer <token> or ?token=
	OutputsDir  string // served read-only under /files/ (screenshot images)
	ToolVersion string // shown in reports/footer
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

	// runs tracks the cancellable context of every scan started through the
	// API so /cancel can stop it.
	runsMu sync.Mutex
	runs   map[string]context.CancelFunc
	runsWG sync.WaitGroup

	// recent buffers the latest events for the dashboard data source.
	recentMu sync.Mutex
	recent   []model.Event
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
	tpl, err := parseTemplates()
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:  cfg,
		deps: deps,
		tpl:  tpl,
		runs: make(map[string]context.CancelFunc),
	}
	s.handler = s.routes()
	if deps.Hub != nil {
		go s.recordRecentEvents()
	}
	return s, nil
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
	errCh := make(chan error, 1)
	go func() {
		s.deps.Logger.Info("http server listening", "addr", s.cfg.Addr)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("server: listen on %s: %w", s.cfg.Addr, err)
	case <-ctx.Done():
		s.cancelAllScans()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("server: shutdown: %w", err)
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
	mux.HandleFunc("GET /gallery", s.handleGallery)
	mux.HandleFunc("GET /reports", s.handleReports)
	mux.Handle("GET /static/", http.FileServer(http.FS(web.FS)))
	mux.Handle("GET /files/", s.filesHandler())

	mux.HandleFunc("POST /api/v1/scans", s.handleCreateScan)
	mux.HandleFunc("GET /api/v1/scans", s.handleListScans)
	mux.HandleFunc("GET /api/v1/scans/{id}", s.handleGetScan)
	mux.HandleFunc("POST /api/v1/scans/{id}/cancel", s.handleCancelScan)
	mux.HandleFunc("GET /api/v1/scans/{id}/findings", s.handleScanFindings)
	mux.HandleFunc("GET /api/v1/scans/{id}/hosts", s.handleScanHosts)
	mux.HandleFunc("GET /api/v1/scans/{id}/screenshots", s.handleScanScreenshots)
	mux.HandleFunc("GET /api/v1/scans/{id}/credentials", s.handleScanCredentials)
	mux.HandleFunc("GET /api/v1/scans/{id}/report", s.handleScanReport)
	mux.HandleFunc("GET /api/v1/summary", s.handleSummary)
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

// startScan registers a cancellable run for a freshly created scan and starts
// the scan engine in the background.
func (s *Server) startScan(scan model.Scan, endpoints []model.Endpoint) {
	ctx, cancel := context.WithCancel(context.Background())
	s.runsMu.Lock()
	s.runs[scan.ID] = cancel
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
		// Run mutates the scan record; hand it a private copy.
		running := scan
		s.deps.Engine.Run(ctx, &running, endpoints)
	}()
	s.deps.Logger.Info("scan queued", "scan_id", scan.ID, "endpoints", len(endpoints))
}

// cancelScan requests cancellation of a tracked scan run. It reports whether a
// tracked run existed.
func (s *Server) cancelScan(scanID string) bool {
	s.runsMu.Lock()
	cancel, ok := s.runs[scanID]
	s.runsMu.Unlock()
	if ok {
		cancel()
	}
	return ok
}

// cancelAllScans cancels every tracked run and waits briefly for the engines.
func (s *Server) cancelAllScans() {
	s.runsMu.Lock()
	for _, cancel := range s.runs {
		cancel()
	}
	s.runsMu.Unlock()
	done := make(chan struct{})
	go func() {
		s.runsWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(shutdownGrace):
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

// withAuth enforces the bearer token when one is configured. The query
// parameter variant exists for clients (EventSource, image tags) that cannot
// set request headers.
func (s *Server) withAuth(next http.Handler) http.Handler {
	if s.cfg.Token == "" {
		return next
	}
	want := sha256.Sum256([]byte(s.cfg.Token))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := tokenFromRequest(r)
		hash := sha256.Sum256([]byte(got))
		if subtle.ConstantTimeCompare(hash[:], want[:]) != 1 {
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
