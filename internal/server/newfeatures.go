// newfeatures.go wires up all the new Phase 1–8 HTTP handlers.
// The route registrations are added to routes() in server.go via the
// addNewRoutes helper called from routes().
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"rdpshot/internal/aisummary"
	"rdpshot/internal/decoy"
	"rdpshot/internal/dsl"
	"rdpshot/internal/mitre"
	"rdpshot/internal/model"
	"rdpshot/internal/sarif"
)

// ─────────────────────────────────────────────────────────────────────────────
// Phase 2: Smart Spray — simple status endpoint (engine lives in scanner)
// ─────────────────────────────────────────────────────────────────────────────

// handleSmartSprayStatus returns per-account lockout counters for the last
// spray operation stored in the settings table.
func (s *Server) handleSmartSprayStatus(w http.ResponseWriter, r *http.Request) {
	scanID := r.PathValue("id")
	raw, err := s.deps.Store.GetSettingJSON("spray_status/" + scanID)
	if err != nil {
		s.internalError(w, r, "spray status", err)
		return
	}
	if raw == nil {
		s.writeJSON(w, http.StatusOK, map[string]any{"scan_id": scanID, "status": "no_data"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 3: MITRE ATT&CK Heatmap
// ─────────────────────────────────────────────────────────────────────────────

// handleMITREHeatmap returns the ATT&CK technique heatmap for one scan.
//
//	GET /api/v1/scans/{id}/mitre
func (s *Server) handleMITREHeatmap(w http.ResponseWriter, r *http.Request) {
	scan, ok := s.loadScan(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	hosts, err := s.deps.Store.ListHosts(scan.ID)
	if err != nil {
		s.internalError(w, r, "mitre: list hosts", err)
		return
	}
	findings, err := s.deps.Store.ListFindings(scan.ID)
	if err != nil {
		s.internalError(w, r, "mitre: list findings", err)
		return
	}
	creds, err := s.deps.Store.ListCredentials(scan.ID)
	if err != nil {
		s.internalError(w, r, "mitre: list credentials", err)
		return
	}
	hm := mitre.BuildHeatmap(scan.ID, scan.Engagement, hosts, findings, creds)
	s.writeJSON(w, http.StatusOK, hm)
}

// handleMITREEngagement returns the ATT&CK heatmap across an engagement.
//
//	GET /api/v1/mitre?engagement=X
func (s *Server) handleMITREEngagement(w http.ResponseWriter, r *http.Request) {
	engagementName := strings.TrimSpace(r.URL.Query().Get("engagement"))
	scans, err := s.deps.Store.ListScansFiltered(recentScansLimit, engagementName, "")
	if err != nil {
		s.internalError(w, r, "mitre engagement: list scans", err)
		return
	}
	var allHosts []model.Host
	var allFindings []model.Finding
	var allCreds []model.Credential
	for _, sc := range scans {
		if h, err := s.deps.Store.ListHosts(sc.ID); err == nil {
			allHosts = append(allHosts, h...)
		}
		if f, err := s.deps.Store.ListFindings(sc.ID); err == nil {
			allFindings = append(allFindings, f...)
		}
		if c, err := s.deps.Store.ListCredentials(sc.ID); err == nil {
			allCreds = append(allCreds, c...)
		}
	}
	hm := mitre.BuildHeatmap("", engagementName, allHosts, allFindings, allCreds)
	s.writeJSON(w, http.StatusOK, hm)
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 4: AI Executive Summary
// ─────────────────────────────────────────────────────────────────────────────

const aiConfigKey = "settings/ai_config"

// handleGetAIConfig returns the LLM configuration (API key redacted).
//
//	GET /api/v1/settings/ai
func (s *Server) handleGetAIConfig(w http.ResponseWriter, r *http.Request) {
	raw, err := s.deps.Store.GetSettingJSON(aiConfigKey)
	if err != nil {
		s.internalError(w, r, "get ai config", err)
		return
	}
	if raw == nil {
		s.writeJSON(w, http.StatusOK, aisummary.LLMConfig{Provider: aisummary.ProviderNone})
		return
	}
	var cfg aisummary.LLMConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		s.internalError(w, r, "parse ai config", err)
		return
	}
	s.writeJSON(w, http.StatusOK, cfg.Redacted())
}

// handlePutAIConfig saves the LLM configuration.
//
//	PUT /api/v1/settings/ai
func (s *Server) handlePutAIConfig(w http.ResponseWriter, r *http.Request) {
	if !s.requireWrite(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	var cfg aisummary.LLMConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		s.writeAPIError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := s.deps.Store.SetSettingJSON(aiConfigKey, cfg); err != nil {
		s.internalError(w, r, "save ai config", err)
		return
	}
	s.audit(r, "ai.config.update", string(cfg.Provider), "")
	s.writeJSON(w, http.StatusOK, cfg.Redacted())
}

// handleGenerateAISummary generates or retrieves the executive summary.
//
//	POST /api/v1/scans/{id}/ai-summary
func (s *Server) handleGenerateAISummary(w http.ResponseWriter, r *http.Request) {
	if !s.requireWrite(w, r) {
		return
	}
	scan, ok := s.loadScan(w, r, r.PathValue("id"))
	if !ok {
		return
	}

	// Load LLM config.
	raw, _ := s.deps.Store.GetSettingJSON(aiConfigKey)
	var cfg aisummary.LLMConfig
	if raw != nil {
		_ = json.Unmarshal(raw, &cfg)
	}

	// Build the summary input from scan data.
	hosts, _ := s.deps.Store.ListHosts(scan.ID)
	findings, _ := s.deps.Store.ListFindings(scan.ID)
	creds, _ := s.deps.Store.ListCredentials(scan.ID)

	inp := buildSummaryInput(scan, hosts, findings, creds)
	summary, err := aisummary.Generate(r.Context(), cfg, inp)
	if err != nil {
		s.internalError(w, r, "generate ai summary", err)
		return
	}

	// Cache in settings.
	cacheKey := "ai_summary/" + scan.ID
	_ = s.deps.Store.SetSettingJSON(cacheKey, map[string]string{
		"summary":    summary,
		"created_at": time.Now().UTC().Format(time.RFC3339),
	})

	s.audit(r, "ai.summary.generate", scan.ID, string(cfg.Provider))
	s.writeJSON(w, http.StatusOK, map[string]string{
		"scan_id": scan.ID,
		"summary": summary,
	})
}

// handleGetAISummary retrieves a cached executive summary.
//
//	GET /api/v1/scans/{id}/ai-summary
func (s *Server) handleGetAISummary(w http.ResponseWriter, r *http.Request) {
	scan, ok := s.loadScan(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	raw, err := s.deps.Store.GetSettingJSON("ai_summary/" + scan.ID)
	if err != nil {
		s.internalError(w, r, "get ai summary", err)
		return
	}
	if raw == nil {
		s.writeAPIError(w, http.StatusNotFound, "no summary generated yet; POST to generate one")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

// buildSummaryInput assembles SummaryInput from scan data.
func buildSummaryInput(scan model.Scan, hosts []model.Host, findings []model.Finding, creds []model.Credential) aisummary.SummaryInput {
	inp := aisummary.SummaryInput{
		ScanName:   scan.Name,
		Engagement: scan.Engagement,
		ScannedAt:  scan.CreatedAt.UTC().Format("2006-01-02"),
		ValidCreds: len(creds),
	}
	for _, h := range hosts {
		inp.HostsTotal++
		if h.State == "open" {
			inp.HostsOpen++
		}
	}
	seenCVEs := map[string]bool{}
	for _, f := range findings {
		if f.Status != model.FindingVulnerable && f.Status != model.FindingPotential {
			continue
		}
		switch f.Severity {
		case model.SeverityCritical:
			inp.CriticalCount++
		case model.SeverityHigh:
			inp.HighCount++
		case model.SeverityMedium:
			inp.MediumCount++
		case model.SeverityLow:
			inp.LowCount++
		}
		if f.CVE != "" && !seenCVEs[f.CVE] {
			seenCVEs[f.CVE] = true
			inp.CVEs = append(inp.CVEs, f.CVE)
		}
		if f.Severity == model.SeverityCritical && len(inp.KeyFindings) < 5 {
			inp.KeyFindings = append(inp.KeyFindings, f.Title)
		}
	}
	return inp
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 5: SARIF Export
// ─────────────────────────────────────────────────────────────────────────────

// handleSARIFExport generates a SARIF 2.1.0 file for one scan.
//
//	GET /api/v1/scans/{id}/sarif
//	  ?fail_on_critical=true  → HTTP 422 if any critical finding exists
func (s *Server) handleSARIFExport(w http.ResponseWriter, r *http.Request) {
	scan, ok := s.loadScan(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	hosts, err := s.deps.Store.ListHosts(scan.ID)
	if err != nil {
		s.internalError(w, r, "sarif: list hosts", err)
		return
	}
	findings, err := s.deps.Store.ListFindings(scan.ID)
	if err != nil {
		s.internalError(w, r, "sarif: list findings", err)
		return
	}

	sarifLog := sarif.BuildSARIF(scan, hosts, findings)
	b, err := sarifLog.JSON()
	if err != nil {
		s.internalError(w, r, "sarif: marshal", err)
		return
	}

	// CI/CD gate: fail-on-critical.
	failOnCritical := strings.ToLower(r.URL.Query().Get("fail_on_critical")) == "true"
	if failOnCritical && sarifLog.HasCritical() {
		w.Header().Set("Content-Type", "application/sarif+json")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="rdpshot-%s.sarif"`, scan.ID))
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write(b)
		return
	}

	w.Header().Set("Content-Type", "application/sarif+json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="rdpshot-%s.sarif"`, scan.ID))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 6: DSL Query — extends existing hosts endpoint
// ─────────────────────────────────────────────────────────────────────────────

// handleDSLHosts filters hosts using the DSL query language.
//
//	GET /api/v1/scans/{id}/hosts/search?q=nla:false+tls:1.0
func (s *Server) handleDSLHosts(w http.ResponseWriter, r *http.Request) {
	scan, ok := s.loadScan(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	f, err := dsl.Parse(query)
	if err != nil {
		s.writeAPIError(w, http.StatusBadRequest, "invalid DSL query: "+err.Error())
		return
	}

	hosts, err := s.deps.Store.ListHosts(scan.ID)
	if err != nil {
		s.internalError(w, r, "dsl hosts: list hosts", err)
		return
	}
	findings, err := s.deps.Store.ListFindings(scan.ID)
	if err != nil {
		s.internalError(w, r, "dsl hosts: list findings", err)
		return
	}
	creds, err := s.deps.Store.ListCredentials(scan.ID)
	if err != nil {
		s.internalError(w, r, "dsl hosts: list creds", err)
		return
	}
	credAddrs := map[string]bool{}
	for _, c := range creds {
		credAddrs[fmt.Sprintf("%s:%d", c.Address, c.Port)] = true
	}

	filtered := dsl.ApplyToHosts(f, hosts, findings, credAddrs)
	s.writeJSON(w, http.StatusOK, map[string]any{
		"scan_id": scan.ID,
		"query":   query,
		"count":   len(filtered),
		"hosts":   filtered,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 7: MTTR & Weekly Trend
// ─────────────────────────────────────────────────────────────────────────────

// handleMTTR returns Mean-Time-to-Remediate statistics.
//
//	GET /api/v1/mttr?engagement=X&period=30d
func (s *Server) handleMTTR(w http.ResponseWriter, r *http.Request) {
	engagement := strings.TrimSpace(r.URL.Query().Get("engagement"))
	period := strings.TrimSpace(r.URL.Query().Get("period"))
	if period == "" {
		period = "30d"
	}
	stats, err := s.deps.Store.ComputeMTTR(engagement, period)
	if err != nil {
		s.internalError(w, r, "mttr", err)
		return
	}
	s.writeJSON(w, http.StatusOK, stats)
}

// handleWeeklyTrend returns weekly new-vs-remediated finding buckets.
//
//	GET /api/v1/trend/weekly?engagement=X&weeks=12
func (s *Server) handleWeeklyTrend(w http.ResponseWriter, r *http.Request) {
	engagement := strings.TrimSpace(r.URL.Query().Get("engagement"))
	weeks := 12
	if wStr := r.URL.Query().Get("weeks"); wStr != "" {
		n := 0
		for _, c := range wStr {
			if c >= '0' && c <= '9' {
				n = n*10 + int(c-'0')
			}
		}
		if n > 0 {
			weeks = n
		}
	}
	points, err := s.deps.Store.WeeklyTrend(engagement, weeks)
	if err != nil {
		s.internalError(w, r, "weekly trend", err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"engagement": engagement,
		"weeks":      weeks,
		"points":     points,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 8: Decoy / Honeypot Listener
// ─────────────────────────────────────────────────────────────────────────────

// decoyState holds a single server-level decoy listener instance.
// Two separate mutexes are used to avoid deadlocks:
//   - ctrlMu guards listener start/stop control flow
//   - eventMu guards the in-memory event ring buffer
//
// OnEvent callbacks arrive from connection-handler goroutines and must NOT
// hold ctrlMu (Stop() → wg.Wait() would deadlock if the goroutine it's
// waiting on tries to acquire ctrlMu via the callback).
type decoyState struct {
	ctrlMu  sync.Mutex   // guards listener field
	eventMu sync.Mutex   // guards events slice
	listener  *decoy.Listener
	events    []decoy.DecoyEvent
	maxEvents int
}

var globalDecoy = &decoyState{maxEvents: 500}

const decoyConfigKey = "settings/decoy_config"

type decoyConfig struct {
	BindAddr      string             `json:"bind_addr"`
	NotifyWebhook string             `json:"notify_webhook,omitempty"`
	Profile       decoy.DecoyProfile `json:"profile,omitempty"`
}

// handleDecoyStart starts the decoy listener.
//
//	POST /api/v1/decoy/start
func (s *Server) handleDecoyStart(w http.ResponseWriter, r *http.Request) {
	if !s.requireWrite(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	var cfg decoyConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		// Fall back to stored config when body is empty or invalid JSON.
		raw, _ := s.deps.Store.GetSettingJSON(decoyConfigKey)
		if raw != nil {
			_ = json.Unmarshal(raw, &cfg)
		}
	}
	if cfg.BindAddr == "" {
		cfg.BindAddr = "0.0.0.0:13389"
	}

	// Persist config before starting.
	_ = s.deps.Store.SetSettingJSON(decoyConfigKey, cfg)

	globalDecoy.ctrlMu.Lock()
	defer globalDecoy.ctrlMu.Unlock()

	if globalDecoy.listener != nil && globalDecoy.listener.IsRunning() {
		s.writeAPIError(w, http.StatusConflict, "decoy listener is already running")
		return
	}

	// Capture cfg for the closure — avoids referencing the outer variable
	// after the handler returns.
	evCfg := cfg

	globalDecoy.listener = decoy.New(decoy.Options{
		BindAddr: cfg.BindAddr,
		Profile:  cfg.Profile,
		Logger:   s.deps.Logger,
		OnEvent: func(ev decoy.DecoyEvent) {
			// IMPORTANT: do NOT acquire ctrlMu here.
			// eventMu is safe to acquire from connection goroutines.
			globalDecoy.eventMu.Lock()
			globalDecoy.events = append(globalDecoy.events, ev)
			if len(globalDecoy.events) > globalDecoy.maxEvents {
				globalDecoy.events = globalDecoy.events[len(globalDecoy.events)-globalDecoy.maxEvents:]
			}
			globalDecoy.eventMu.Unlock()

			// All store/audit/webhook calls are safe to make without any mutex.
			_ = s.deps.Store.InsertDecoyEvent(ev)
			_ = s.deps.Store.AppendAudit(model.AuditEntry{
				At:       ev.At,
				Actor:    "decoy",
				Action:   "decoy.connection",
				Target:   ev.RemoteIP,
				Detail:   "NTLM user=" + ev.NTLMUsername + " domain=" + ev.NTLMDomain,
				RemoteIP: ev.RemoteIP,
			})
			s.maybeSendDecoyAlert(ev, evCfg)
		},
	})

	if err := globalDecoy.listener.Start(context.Background()); err != nil {
		// Clear the listener so future start attempts are not blocked.
		globalDecoy.listener = nil
		s.internalError(w, r, "decoy start: "+err.Error(), err)
		return
	}

	s.audit(r, "decoy.start", cfg.BindAddr, "")
	s.writeJSON(w, http.StatusOK, map[string]any{
		"running":   true,
		"bind_addr": cfg.BindAddr,
	})
}

// handleDecoyStop stops the decoy listener.
//
//	POST /api/v1/decoy/stop
func (s *Server) handleDecoyStop(w http.ResponseWriter, r *http.Request) {
	if !s.requireWrite(w, r) {
		return
	}

	globalDecoy.ctrlMu.Lock()
	lst := globalDecoy.listener
	globalDecoy.ctrlMu.Unlock()

	if lst == nil || !lst.IsRunning() {
		s.writeAPIError(w, http.StatusConflict, "decoy listener is not running")
		return
	}

	// Stop() is called OUTSIDE ctrlMu to avoid deadlock:
	// Stop() → wg.Wait() blocks until connection goroutines finish.
	// Those goroutines call OnEvent → eventMu (safe, not ctrlMu).
	lst.Stop()

	s.audit(r, "decoy.stop", "", "")
	s.writeJSON(w, http.StatusOK, map[string]any{"running": false})
}

// handleDecoyGetProfile returns the stored decoy profile.
//
//	GET /api/v1/decoy/profile
func (s *Server) handleDecoyGetProfile(w http.ResponseWriter, r *http.Request) {
	raw, _ := s.deps.Store.GetSettingJSON(decoyConfigKey)
	var cfg decoyConfig
	if raw != nil {
		_ = json.Unmarshal(raw, &cfg)
	}
	if cfg.BindAddr == "" {
		cfg.BindAddr = "0.0.0.0:13389"
	}
	if cfg.Profile.HostName == "" {
		cfg.Profile.HostName = "WIN-RDPSHOT01"
		cfg.Profile.Organization = "Microsoft Corporation"
		cfg.Profile.WindowsVersion = "2019"
		cfg.Profile.Domain = "WORKGROUP"
		cfg.Profile.DesktopWidth = 1024
		cfg.Profile.DesktopHeight = 768
		cfg.Profile.WallpaperColor = "#1a3a5c"
		cfg.Profile.LoginMessage = "This computer is for authorized use only."
	}
	s.writeJSON(w, http.StatusOK, cfg)
}

// handleDecoyPutProfile saves the decoy configuration and profile.
//
//	PUT /api/v1/decoy/profile
func (s *Server) handleDecoyPutProfile(w http.ResponseWriter, r *http.Request) {
	if !s.requireWrite(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	var cfg decoyConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		s.writeAPIError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if cfg.BindAddr == "" {
		cfg.BindAddr = "0.0.0.0:13389"
	}
	if err := s.deps.Store.SetSettingJSON(decoyConfigKey, cfg); err != nil {
		s.internalError(w, r, "save decoy profile", err)
		return
	}
	s.audit(r, "decoy.profile.update", cfg.BindAddr, "")
	s.writeJSON(w, http.StatusOK, cfg)
}

// handleDecoyStatus returns the current listener status.
//
//	GET /api/v1/decoy/status
func (s *Server) handleDecoyStatus(w http.ResponseWriter, r *http.Request) {
	globalDecoy.ctrlMu.Lock()
	running := globalDecoy.listener != nil && globalDecoy.listener.IsRunning()
	globalDecoy.ctrlMu.Unlock()

	globalDecoy.eventMu.Lock()
	evCount := len(globalDecoy.events)
	globalDecoy.eventMu.Unlock()

	raw, _ := s.deps.Store.GetSettingJSON(decoyConfigKey)
	var cfg decoyConfig
	if raw != nil {
		_ = json.Unmarshal(raw, &cfg)
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"running":     running,
		"bind_addr":   cfg.BindAddr,
		"event_count": evCount,
	})
}

// handleDecoyEvents returns the list of captured attacker connections.
//
//	GET /api/v1/decoy/events
func (s *Server) handleDecoyEvents(w http.ResponseWriter, r *http.Request) {
	globalDecoy.eventMu.Lock()
	snapshot := make([]decoy.DecoyEvent, len(globalDecoy.events))
	copy(snapshot, globalDecoy.events)
	globalDecoy.eventMu.Unlock()

	// Reverse so newest is first.
	for i, j := 0, len(snapshot)-1; i < j; i, j = i+1, j-1 {
		snapshot[i], snapshot[j] = snapshot[j], snapshot[i]
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"count":  len(snapshot),
		"events": snapshot,
	})
}

// maybeSendDecoyAlert fires a webhook alert when a decoy connection is recorded.
func (s *Server) maybeSendDecoyAlert(ev decoy.DecoyEvent, cfg decoyConfig) {
	if cfg.NotifyWebhook == "" {
		return
	}
	payload := map[string]any{
		"type":        "decoy.attacker_detected",
		"at":          ev.At.Format(time.RFC3339),
		"remote_ip":   ev.RemoteIP,
		"ntlm_user":   ev.NTLMUsername,
		"ntlm_domain": ev.NTLMDomain,
		"severity":    "critical",
		"message":     fmt.Sprintf("DECOY ALERT: Attacker %s connected to RDP honeypot", ev.RemoteIP),
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, err := newDecoyRequest(ctx, cfg.NotifyWebhook, b)
		if err != nil {
			return
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return
		}
		resp.Body.Close()
	}()
}

func newDecoyRequest(ctx context.Context, url string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "rdpshot-decoy/1.0")
	return req, nil
}
