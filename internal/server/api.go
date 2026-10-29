package server

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"rdpshot/internal/model"
	"rdpshot/internal/reporter"
	"rdpshot/internal/target"
)

// scanCreated is the 201 response body of POST /api/v1/scans.
type scanCreated struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

// handleCreateScan validates the quick-scan form, persists the scan and starts
// the scan engine in the background.
func (s *Server) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		s.writeAPIError(w, http.StatusBadRequest, "invalid form body")
		return
	}
	form := r.PostForm

	specs := splitTargets(form.Get("targets"))
	if len(specs) == 0 {
		s.writeAPIError(w, http.StatusBadRequest, "targets is required")
		return
	}
	for _, spec := range specs {
		if strings.HasPrefix(spec, "@") {
			// "@file" expansion would make the server read arbitrary files;
			// only inline target specs are accepted over HTTP.
			s.writeAPIError(w, http.StatusBadRequest, "target file specs are not accepted via the API")
			return
		}
	}

	enableVuln := formBool(form.Get("enable_vuln"))
	enableAuth := formBool(form.Get("enable_auth"))
	enableScreens := formBool(form.Get("enable_screens"))
	ack := formBool(form.Get("ack_authorized"))
	if (enableAuth || enableScreens) && !ack {
		s.writeAPIError(w, http.StatusBadRequest,
			"credential checks and screenshots require the authorization acknowledgement")
		return
	}

	ports, err := target.ParsePorts(form.Get("ports"))
	if err != nil {
		s.writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	concurrency, err := parseConcurrency(form.Get("concurrency"))
	if err != nil {
		s.writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	rate, err := parseRate(form.Get("rate"))
	if err != nil {
		s.writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	timeout, err := parseTimeout(form.Get("timeout"))
	if err != nil {
		s.writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}

	res, err := target.Resolve(r.Context(), target.Options{
		Specs:      specs,
		Ports:      ports,
		MaxTargets: maxScanTargets,
	})
	if err != nil {
		s.writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(res.Endpoints) == 0 {
		message := "no endpoints resolved from the given targets"
		if len(res.Warnings) > 0 {
			message += ": " + strings.Join(res.Warnings, "; ")
		}
		s.writeAPIError(w, http.StatusBadRequest, message)
		return
	}

	scan := model.Scan{
		ID:        model.NewID("scan"),
		Name:      scanName(specs, form.Get("name")),
		Status:    model.ScanPending,
		CreatedAt: time.Now().UTC(),
		Options: model.ScanOptions{
			Targets:          specs,
			Ports:            ports,
			TimeoutMS:        int(timeout / time.Millisecond),
			Concurrency:      concurrency,
			RatePerSecond:    rate,
			EnableVuln:       enableVuln,
			EnableAuth:       enableAuth,
			EnableScreens:    enableScreens,
			MaxAuthFailures:  defaultMaxAuthFailures,
			UserWordlist:     form.Get("user_wordlist"),
			PasswordWordlist: form.Get("password_wordlist"),
			Acknowledged:     ack,
		},
	}
	if err := s.deps.Store.CreateScan(scan); err != nil {
		s.internalError(w, r, "create scan", err)
		return
	}
	s.startScan(scan, res.Endpoints)

	w.Header().Set("Location", "/scans/"+scan.ID)
	s.writeJSON(w, http.StatusCreated, scanCreated{ID: scan.ID, URL: "/scans/" + scan.ID})
}

// handleListScans returns every scan, newest first.
func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	scans, err := s.deps.Store.ListScans(recentScansLimit)
	if err != nil {
		s.internalError(w, r, "load scans", err)
		return
	}
	if scans == nil {
		scans = []model.Scan{}
	}
	s.writeJSON(w, http.StatusOK, scans)
}

// handleGetScan returns one scan.
func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	scan, ok := s.loadScan(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	s.writeJSON(w, http.StatusOK, scan)
}

// handleCancelScan requests cancellation of a running scan.
func (s *Server) handleCancelScan(w http.ResponseWriter, r *http.Request) {
	scan, ok := s.loadScan(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	switch scan.Status {
	case model.ScanCompleted, model.ScanFailed, model.ScanCancelled:
		s.writeAPIError(w, http.StatusConflict, "scan already finished")
		return
	}
	if !s.cancelScan(scan.ID) {
		// The run finished between the store read and the lookup, or the scan
		// is not managed by this process; nothing can be cancelled.
		s.writeAPIError(w, http.StatusConflict, "scan is not running on this server")
		return
	}
	s.deps.Logger.Info("scan cancel requested", "scan_id", scan.ID)
	s.writeJSON(w, http.StatusAccepted, map[string]string{"status": "cancelling"})
}

// handleScanFindings returns the findings of one scan.
func (s *Server) handleScanFindings(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.loadScan(w, r, id); !ok {
		return
	}
	findings, err := s.deps.Store.ListFindings(id)
	if err != nil {
		s.internalError(w, r, "load findings", err)
		return
	}
	if findings == nil {
		findings = []model.Finding{}
	}
	s.writeJSON(w, http.StatusOK, findings)
}

// handleScanHosts returns the probed hosts of one scan.
func (s *Server) handleScanHosts(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.loadScan(w, r, id); !ok {
		return
	}
	hosts, err := s.deps.Store.ListHosts(id)
	if err != nil {
		s.internalError(w, r, "load hosts", err)
		return
	}
	if hosts == nil {
		hosts = []model.Host{}
	}
	s.writeJSON(w, http.StatusOK, hosts)
}

// handleScanScreenshots returns screenshot metadata with web URLs.
func (s *Server) handleScanScreenshots(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.loadScan(w, r, id); !ok {
		return
	}
	screens, err := s.deps.Store.ListScreenshots(id)
	if err != nil {
		s.internalError(w, r, "load screenshots", err)
		return
	}
	views := screenshotViews(screens)
	if views == nil {
		views = []model.Screenshot{}
	}
	s.writeJSON(w, http.StatusOK, views)
}

// handleScanCredentials returns credentials of one scan with masked secrets.
func (s *Server) handleScanCredentials(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.loadScan(w, r, id); !ok {
		return
	}
	creds, err := s.deps.Store.ListCredentials(id)
	if err != nil {
		s.internalError(w, r, "load credentials", err)
		return
	}
	masked := maskCredentials(creds)
	if masked == nil {
		masked = []model.Credential{}
	}
	s.writeJSON(w, http.StatusOK, masked)
}

// handleSummary returns the global aggregate counters.
func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	summary, err := s.deps.Store.Summary("")
	if err != nil {
		s.internalError(w, r, "load summary", err)
		return
	}
	s.writeJSON(w, http.StatusOK, summary)
}

// handleScanReport streams one report of a scan as a file download.
func (s *Server) handleScanReport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	scan, ok := s.loadScan(w, r, id)
	if !ok {
		return
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))

	data, err := s.reportData(scan)
	if err != nil {
		s.internalError(w, r, "load report data", err)
		return
	}

	// Generate into a buffer first so generator failures can still produce a
	// proper error status instead of a truncated download.
	var buf bytes.Buffer
	var contentType string
	switch format {
	case "html":
		contentType = "text/html; charset=utf-8"
		err = reporter.HTML(&buf, data)
	case "csv":
		contentType = "text/csv"
		err = reporter.CSV(&buf, data)
	case "pdf":
		contentType = "application/pdf"
		err = reporter.PDF(&buf, data)
	default:
		s.writeAPIError(w, http.StatusBadRequest, fmt.Sprintf("unknown report format %q", format))
		return
	}
	if err != nil {
		s.internalError(w, r, "render report", err)
		return
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="rdpshot-%s.%s"`, id, format))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(buf.Bytes()); err != nil {
		s.deps.Logger.Error("write report", "scan_id", id, "error", err.Error())
	}
}

// reportData assembles the self-contained report payload. Credentials are
// masked and screenshot paths are rewritten to web URLs before they reach the
// generator.
func (s *Server) reportData(scan model.Scan) (reporter.Data, error) {
	summary, err := s.deps.Store.Summary(scan.ID)
	if err != nil {
		return reporter.Data{}, err
	}
	hosts, err := s.deps.Store.ListHosts(scan.ID)
	if err != nil {
		return reporter.Data{}, err
	}
	findings, err := s.deps.Store.ListFindings(scan.ID)
	if err != nil {
		return reporter.Data{}, err
	}
	creds, err := s.deps.Store.ListCredentials(scan.ID)
	if err != nil {
		return reporter.Data{}, err
	}
	screens, err := s.deps.Store.ListScreenshots(scan.ID)
	if err != nil {
		return reporter.Data{}, err
	}
	cveStats, err := s.deps.Store.CVEStats(scan.ID)
	if err != nil {
		return reporter.Data{}, err
	}
	return reporter.Data{
		Scan:        scan,
		Summary:     summary,
		Hosts:       hosts,
		Findings:    findings,
		Credentials: maskCredentials(creds),
		Screens:     screenshotViews(screens),
		CVEStats:    cveStats,
		GeneratedAt: time.Now().UTC(),
		ToolVersion: s.cfg.ToolVersion,
	}, nil
}

// splitTargets breaks the form target field on commas and whitespace.
func splitTargets(field string) []string {
	return strings.FieldsFunc(field, func(r rune) bool {
		return unicode.IsSpace(r) || r == ','
	})
}

// formBool recognizes the checkbox values browsers and API clients send.
func formBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "on", "true", "1":
		return true
	}
	return false
}

// scanName derives the display name of a scan from the form or the first
// target plus the creation timestamp.
func scanName(specs []string, formName string) string {
	if name := strings.TrimSpace(formName); name != "" {
		return truncateRunes(name, 200)
	}
	return truncateRunes(specs[0], 100) + " " + time.Now().UTC().Format("2006-01-02 15:04 UTC")
}

// truncateRunes bounds a display string without splitting a multi-byte rune.
func truncateRunes(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max])
}

// parseConcurrency validates the concurrency field (default 64).
func parseConcurrency(v string) (int, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return defaultConcurrency, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 4096 {
		return 0, fmt.Errorf("invalid concurrency %q: must be between 1 and 4096", v)
	}
	return n, nil
}

// parseRate validates the rate field in requests per second (default 10).
func parseRate(v string) (float64, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return defaultRate, nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f <= 0 {
		return 0, fmt.Errorf("invalid rate %q: must be a positive number", v)
	}
	return f, nil
}

// parseTimeout validates the per-connection timeout field (default 5s).
func parseTimeout(v string) (time.Duration, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return defaultTimeout, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid timeout %q: must be a positive duration", v)
	}
	if d > maxScanTimeout {
		return 0, fmt.Errorf("invalid timeout %q: must not exceed %s", v, maxScanTimeout)
	}
	return d, nil
}
