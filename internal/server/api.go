package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"rdpshot/internal/about"
	"rdpshot/internal/model"
	"rdpshot/internal/reporter"
	"rdpshot/internal/score"
	"rdpshot/internal/target"
)

// scanCreated is the 201 response body of POST /api/v1/scans.
type scanCreated struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

// handleCreateScan validates the quick-scan form, persists the scan and starts
// the scan engine in the background. Any number of scans may run at once; each
// one gets its own worker pool and pause control.
func (s *Server) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	if !s.requireWrite(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if !s.parseScanForm(w, r) {
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	form := r.PostForm

	fromFile, err := readTargetsUpload(formFile(r, "targets_file"))
	if err != nil {
		s.writeAPIError(w, http.StatusBadRequest, "targets file: "+err.Error())
		return
	}
	specs := mergeTargetSpecs(splitTargets(form.Get("targets")), fromFile)
	if len(specs) == 0 {
		s.writeAPIError(w, http.StatusBadRequest, "targets is required")
		return
	}
	for _, spec := range specs {
		if strings.HasPrefix(spec, "@") {
			// "@file" expansion would make the server read arbitrary files;
			// only inline target specs (and uploaded target lists) are accepted.
			s.writeAPIError(w, http.StatusBadRequest, "target file specs are not accepted via the API")
			return
		}
	}

	enableVuln := formBool(form.Get("enable_vuln"))
	enableAuth := formBool(form.Get("enable_auth"))
	enableScreens := formBool(form.Get("enable_screens"))
	enableDiscovery := formBool(form.Get("enable_discovery"))
	ack := formBool(form.Get("ack_authorized"))
	if (enableAuth || enableScreens) && !ack {
		s.writeAPIError(w, http.StatusBadRequest,
			"credential checks and screenshots require the authorization acknowledgement")
		return
	}
	if (enableAuth || enableScreens) && !s.requireIntrusive(w, r) {
		return
	}
	pathLabel := strings.ToLower(strings.TrimSpace(form.Get("path")))
	switch pathLabel {
	case "", "internal", "external":
	default:
		s.writeAPIError(w, http.StatusBadRequest, "path must be internal, external, or empty")
		return
	}
	maxRuntimeSec := 0
	if raw := strings.TrimSpace(form.Get("max_runtime_sec")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			s.writeAPIError(w, http.StatusBadRequest, "max_runtime_sec must be a non-negative integer")
			return
		}
		maxRuntimeSec = n
	}
	baseScanID := strings.TrimSpace(form.Get("base_scan_id"))
	if baseScanID != "" {
		if _, err := s.deps.Store.GetScan(baseScanID); err != nil {
			s.writeAPIError(w, http.StatusBadRequest, "base_scan_id not found")
			return
		}
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

	maxTargets, err := s.parseMaxTargets(form.Get("max_targets"))
	if err != nil {
		s.writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := target.Resolve(r.Context(), target.Options{
		Specs:      specs,
		Ports:      ports,
		MaxTargets: maxTargets,
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

	scanID := model.NewID("scan")
	uploadsComplete := false
	defer func() {
		if !uploadsComplete {
			s.removeScanUploads(scanID)
		}
	}()

	userWordlist, err := s.saveWordlistUpload(scanID, "user_wordlist", formFile(r, "user_wordlist_file"))
	if err != nil {
		s.writeAPIError(w, http.StatusBadRequest, "user wordlist upload: "+err.Error())
		return
	}
	passwordWordlist, err := s.saveWordlistUpload(scanID, "password_wordlist", formFile(r, "password_wordlist_file"))
	if err != nil {
		s.writeAPIError(w, http.StatusBadRequest, "password wordlist upload: "+err.Error())
		return
	}
	if userWordlist == "" {
		userWordlist = strings.TrimSpace(form.Get("user_wordlist"))
	}
	if passwordWordlist == "" {
		passwordWordlist = strings.TrimSpace(form.Get("password_wordlist"))
	}

	scan := model.Scan{
		ID:         scanID,
		Name:       scanName(specs, form.Get("name")),
		Status:     model.ScanPending,
		CreatedAt:  time.Now().UTC(),
		Engagement: strings.TrimSpace(form.Get("engagement")),
		Tags:       splitTags(form.Get("tags")),
		Options: model.ScanOptions{
			Targets:          specs,
			Ports:            ports,
			TimeoutMS:        int(timeout / time.Millisecond),
			Concurrency:      concurrency,
			RatePerSecond:    rate,
			EnableVuln:       enableVuln,
			EnableAuth:       enableAuth,
			EnableScreens:    enableScreens,
			EnableDiscovery:  enableDiscovery,
			MaxAuthFailures:  defaultMaxAuthFailures,
			UserWordlist:     userWordlist,
			PasswordWordlist: passwordWordlist,
			BaseScanID:       baseScanID,
			Path:             pathLabel,
			MaxRuntimeSec:    maxRuntimeSec,
			Acknowledged:     ack,
		},
	}
	if err := applyAuthOptions(&scan.Options, form.Get); err != nil {
		s.writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	if scan.Options.EnableAuth && !ack {
		s.writeAPIError(w, http.StatusBadRequest,
			"credential checks and screenshots require the authorization acknowledgement")
		return
	}
	if scan.Options.EnableAuth && !s.requireIntrusive(w, r) {
		return
	}
	if scan.Options.EnableAuth && scan.Options.AuthMode == model.AuthModeWordlist {
		defaultUser, defaultPassword := s.wordlistDefaults()
		if scan.Options.UserWordlist == "" {
			scan.Options.UserWordlist = defaultUser
		}
		if scan.Options.PasswordWordlist == "" {
			scan.Options.PasswordWordlist = defaultPassword
		}
	}
	if err := s.deps.Store.CreateScan(scan); err != nil {
		s.internalError(w, r, "create scan", err)
		return
	}
	uploadsComplete = true
	s.startScan(scan, res.Endpoints)
	s.audit(r, "scan.create", scan.ID, scan.Name)

	w.Header().Set("Location", "/scans/"+scan.ID)
	s.writeJSON(w, http.StatusCreated, scanCreated{ID: scan.ID, URL: "/scans/" + scan.ID})
}

// handleListScans returns every scan, newest first.
func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	scans, err := s.deps.Store.ListScansFiltered(recentScansLimit,
		r.URL.Query().Get("engagement"), r.URL.Query().Get("tag"))
	if err != nil {
		s.internalError(w, r, "load scans", err)
		return
	}
	if scans == nil {
		scans = []model.Scan{}
	}
	s.writeJSON(w, http.StatusOK, redactScans(scans))
}

// handleGetScan returns one scan.
func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	scan, ok := s.loadScan(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	s.writeJSON(w, http.StatusOK, redactScan(scan))
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

// handlePauseScan parks a running scan. Completed work is kept and the queued
// endpoints resume from the same point.
func (s *Server) handlePauseScan(w http.ResponseWriter, r *http.Request) {
	scan, ok := s.loadScan(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	if scan.Status != model.ScanRunning {
		s.writeAPIError(w, http.StatusConflict, "only a running scan can be paused")
		return
	}
	control := s.scanControl(scan.ID)
	if control == nil || !control.Pause() {
		s.writeAPIError(w, http.StatusConflict, "scan is not running on this server")
		return
	}
	s.deps.Logger.Info("scan paused", "scan_id", scan.ID)
	s.writeJSON(w, http.StatusAccepted, map[string]string{"status": "paused"})
}

// handleResumeScan reopens a paused scan.
func (s *Server) handleResumeScan(w http.ResponseWriter, r *http.Request) {
	scan, ok := s.loadScan(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	if scan.Status != model.ScanPaused {
		s.writeAPIError(w, http.StatusConflict, "only a paused scan can be resumed")
		return
	}
	control := s.scanControl(scan.ID)
	if control == nil || !control.Resume() {
		s.writeAPIError(w, http.StatusConflict, "scan is not running on this server")
		return
	}
	s.deps.Logger.Info("scan resumed", "scan_id", scan.ID)
	s.writeJSON(w, http.StatusAccepted, map[string]string{"status": "running"})
}

// handleDeleteScan removes a scan and the artifacts it owns. Active runs are
// cancelled first so paused/running scans can be deleted from the list UI.
func (s *Server) handleDeleteScan(w http.ResponseWriter, r *http.Request) {
	if !s.requireIntrusive(w, r) {
		return
	}
	scan, ok := s.loadScan(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	if s.cancelScan(scan.ID) || !scan.Status.Terminal() {
		scan.Status = model.ScanCancelled
		_ = s.deps.Store.UpdateScan(scan)
	}
	screens, err := s.deps.Store.ListScreenshots(scan.ID)
	if err != nil {
		s.internalError(w, r, "load scan screenshots", err)
		return
	}
	if err := s.deps.Store.DeleteScan(scan.ID); err != nil {
		s.internalError(w, r, "delete scan", err)
		return
	}
	paths := make([]string, 0, len(screens))
	for _, screen := range screens {
		paths = append(paths, screen.FilePath)
	}
	s.removeScanUploads(scan.ID)
	s.removeScanScreenshots(paths)
	s.audit(r, "scan.delete", scan.ID, string(scan.Status))
	s.deps.Logger.Info("scan deleted", "scan_id", scan.ID)
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": scan.ID})
}

// renameScanRequest is the JSON body of PATCH /api/v1/scans/{id}.
type renameScanRequest struct {
	Name string `json:"name"`
}

// handleRenameScan changes the display name of a scan.
func (s *Server) handleRenameScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	scan, ok := s.loadScan(w, r, id)
	if !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	name := ""
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var payload renameScanRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			s.writeAPIError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		name = payload.Name
	} else {
		if err := r.ParseForm(); err != nil {
			s.writeAPIError(w, http.StatusBadRequest, "invalid form body")
			return
		}
		name = r.PostForm.Get("name")
	}

	name = strings.TrimSpace(name)
	if name == "" {
		s.writeAPIError(w, http.StatusBadRequest, "name is required")
		return
	}
	if utf8.RuneCountInString(name) > 200 {
		s.writeAPIError(w, http.StatusBadRequest, "name must be at most 200 characters")
		return
	}
	if err := s.deps.Store.RenameScan(id, name); err != nil {
		s.internalError(w, r, "rename scan", err)
		return
	}
	scan.Name = name
	s.writeJSON(w, http.StatusOK, redactScan(scan))
}

// handleBruteForceScan starts a credential-only scan against hosts discovered
// by an earlier scan. Reconnaissance runs again (it is required for the
// authentication handshake) but vulnerability checks and screenshots are off.
func (s *Server) handleBruteForceScan(w http.ResponseWriter, r *http.Request) {
	if !s.requireIntrusive(w, r) {
		return
	}
	parent, ok := s.loadScan(w, r, r.PathValue("id"))
	if !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if !s.parseScanForm(w, r) {
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	form := r.PostForm

	if !formBool(form.Get("ack_authorized")) {
		s.writeAPIError(w, http.StatusBadRequest,
			"credential checks require the authorization acknowledgement")
		return
	}

	endpoints, err := parseEndpointList(form["hosts"])
	if err != nil {
		s.writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(endpoints) == 0 {
		s.writeAPIError(w, http.StatusBadRequest, "select at least one host")
		return
	}

	// Only endpoints that the parent scan actually discovered may be targeted,
	// so the endpoint cannot be used to probe arbitrary addresses.
	hosts, err := s.deps.Store.ListHosts(parent.ID)
	if err != nil {
		s.internalError(w, r, "load parent hosts", err)
		return
	}
	known := make(map[string]bool, len(hosts))
	for _, host := range hosts {
		known[host.Endpoint.Key()] = true
	}
	for _, ep := range endpoints {
		if !known[ep.Key()] {
			s.writeAPIError(w, http.StatusBadRequest,
				fmt.Sprintf("%s was not discovered by scan %s", ep.Key(), parent.ID))
			return
		}
	}

	maxAuthFailures, err := parseMaxAuthFailures(form.Get("max_auth_failures"))
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

	scanID := model.NewID("scan")
	uploadsComplete := false
	defer func() {
		if !uploadsComplete {
			s.removeScanUploads(scanID)
		}
	}()

	userWordlist, err := s.saveWordlistUpload(scanID, "user_wordlist", formFile(r, "user_wordlist_file"))
	if err != nil {
		s.writeAPIError(w, http.StatusBadRequest, "user wordlist upload: "+err.Error())
		return
	}
	passwordWordlist, err := s.saveWordlistUpload(scanID, "password_wordlist", formFile(r, "password_wordlist_file"))
	if err != nil {
		s.writeAPIError(w, http.StatusBadRequest, "password wordlist upload: "+err.Error())
		return
	}
	if userWordlist == "" {
		userWordlist = strings.TrimSpace(form.Get("user_wordlist"))
	}
	if passwordWordlist == "" {
		passwordWordlist = strings.TrimSpace(form.Get("password_wordlist"))
	}

	targets := make([]string, len(endpoints))
	ports := make([]uint16, 0, len(endpoints))
	seenPorts := map[uint16]bool{}
	for i, ep := range endpoints {
		targets[i] = ep.Key()
		if !seenPorts[ep.Port] {
			seenPorts[ep.Port] = true
			ports = append(ports, ep.Port)
		}
	}

	name := strings.TrimSpace(form.Get("name"))
	if name == "" {
		name = fmt.Sprintf("Credential audit: %s (%d hosts)", parent.Name, len(endpoints))
	}

	scan := model.Scan{
		ID:        scanID,
		Name:      truncateRunes(name, 200),
		Status:    model.ScanPending,
		CreatedAt: time.Now().UTC(),
		Options: model.ScanOptions{
			Targets:          targets,
			Ports:            ports,
			TimeoutMS:        int(timeout / time.Millisecond),
			Concurrency:      concurrency,
			RatePerSecond:    rate,
			EnableVuln:       false,
			EnableAuth:       true,
			EnableScreens:    false,
			MaxAuthFailures:  maxAuthFailures,
			UserWordlist:     userWordlist,
			PasswordWordlist: passwordWordlist,
			Acknowledged:     true,
		},
	}
	if err := applyAuthOptions(&scan.Options, form.Get); err != nil {
		s.writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	if scan.Options.AuthMode == model.AuthModeWordlist {
		defaultUser, defaultPassword := s.wordlistDefaults()
		if scan.Options.UserWordlist == "" {
			scan.Options.UserWordlist = defaultUser
		}
		if scan.Options.PasswordWordlist == "" {
			scan.Options.PasswordWordlist = defaultPassword
		}
	}
	if err := s.deps.Store.CreateScan(scan); err != nil {
		s.internalError(w, r, "create credential audit", err)
		return
	}
	uploadsComplete = true
	s.startScan(scan, endpoints)

	w.Header().Set("Location", "/scans/"+scan.ID)
	s.writeJSON(w, http.StatusCreated, scanCreated{ID: scan.ID, URL: "/scans/" + scan.ID})
}

// parseScanForm accepts either multipart/form-data (wordlist uploads) or the
// classic application/x-www-form-urlencoded body used by the dashboard.
func (s *Server) parseScanForm(w http.ResponseWriter, r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	var err error
	if strings.HasPrefix(ct, "multipart/form-data") {
		err = r.ParseMultipartForm(maxWordlistUploadBytes)
	} else {
		err = r.ParseForm()
	}
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			s.writeAPIError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return false
		}
		s.writeAPIError(w, http.StatusBadRequest, "invalid form body")
		return false
	}
	return true
}

// handleAnalytics returns the cross-scan posture summary.
func (s *Server) handleAnalytics(w http.ResponseWriter, r *http.Request) {
	analytics, err := s.deps.Store.Analytics()
	if err != nil {
		s.internalError(w, r, "load analytics", err)
		return
	}
	s.writeJSON(w, http.StatusOK, analytics)
}

// parseMaxAuthFailures validates the per-host attempt limit.
func parseMaxAuthFailures(value string) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return defaultMaxAuthFailures, nil
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 1 || n > maxAuthFailureLimit {
		return 0, fmt.Errorf("invalid max_auth_failures %q: must be between 1 and %d", value, maxAuthFailureLimit)
	}
	return n, nil
}

// parseEndpointList parses repeated address:port fields into unique endpoints.
func parseEndpointList(values []string) ([]model.Endpoint, error) {
	seen := map[string]bool{}
	var endpoints []model.Endpoint
	for _, value := range values {
		for _, spec := range strings.FieldsFunc(value, func(r rune) bool {
			return unicode.IsSpace(r) || r == ','
		}) {
			host, portText, err := net.SplitHostPort(spec)
			if err != nil {
				return nil, fmt.Errorf("invalid host %q: expected address:port", spec)
			}
			port, err := strconv.Atoi(portText)
			if err != nil || port < 1 || port > 65535 {
				return nil, fmt.Errorf("invalid port in %q", spec)
			}
			key := net.JoinHostPort(host, strconv.Itoa(port))
			if seen[key] {
				continue
			}
			seen[key] = true
			endpoints = append(endpoints, model.Endpoint{Address: host, Port: uint16(port)})
		}
	}
	return endpoints, nil
}

// handleScanDiff compares one scan against another (?against=id).
func (s *Server) handleScanDiff(w http.ResponseWriter, r *http.Request) {
	baseID := r.PathValue("id")
	againstID := strings.TrimSpace(r.URL.Query().Get("against"))
	if againstID == "" {
		s.writeAPIError(w, http.StatusBadRequest, "against query parameter is required")
		return
	}
	if baseID == againstID {
		s.writeAPIError(w, http.StatusBadRequest, "cannot diff a scan against itself")
		return
	}
	if _, ok := s.loadScan(w, r, baseID); !ok {
		return
	}
	if _, ok := s.loadScan(w, r, againstID); !ok {
		return
	}
	diff, err := s.deps.Store.DiffScans(baseID, againstID)
	if err != nil {
		s.internalError(w, r, "diff scans", err)
		return
	}
	s.writeJSON(w, http.StatusOK, diff)
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
func (s *Server) handleAPIAbout(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, about.Snapshot(s.cfg.ToolVersion))
}

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
	branding, err := s.deps.Store.GetReportBranding()
	if err != nil {
		return reporter.Data{}, err
	}
	if branding.Engagement == "" {
		branding.Engagement = scan.Engagement
	}
	sc := score.EvaluateScan(scan.ID, hosts, findings)
	return reporter.Data{
		Scan:           scan,
		Summary:        summary,
		Hosts:          hosts,
		Findings:       findings,
		Credentials:    maskCredentials(creds),
		Screens:        screenshotViews(screens),
		CVEStats:       cveStats,
		GeneratedAt:    time.Now().UTC(),
		ToolVersion:    s.cfg.ToolVersion,
		Branding:       branding,
		HardeningScore: sc.Score,
		HardeningGrade: sc.Grade,
	}, nil
}

// splitTargets breaks the form target field on commas and whitespace.
func splitTargets(field string) []string {
	return strings.FieldsFunc(field, func(r rune) bool {
		return unicode.IsSpace(r) || r == ','
	})
}

// splitTags breaks a comma/whitespace separated tag list.
func splitTags(field string) []string {
	return splitTargets(field)
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

// parseMaxTargets validates an optional per-scan expansion budget. Empty (or
// 0) means unlimited unless the server was started with a positive ceiling.
func (s *Server) parseMaxTargets(v string) (int, error) {
	ceiling := s.cfg.MaxTargets // 0 = unlimited at server level
	if ceiling > absoluteMaxScanTargets {
		ceiling = absoluteMaxScanTargets
	}
	v = strings.TrimSpace(v)
	if v == "" || v == "0" {
		return ceiling, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid max_targets %q: must be 0 (unlimited) or a positive integer", v)
	}
	if ceiling > 0 && n > ceiling {
		return 0, fmt.Errorf("invalid max_targets %q: must not exceed server limit %d", v, ceiling)
	}
	if n > absoluteMaxScanTargets {
		return 0, fmt.Errorf("invalid max_targets %q: must not exceed %d", v, absoluteMaxScanTargets)
	}
	return n, nil
}
