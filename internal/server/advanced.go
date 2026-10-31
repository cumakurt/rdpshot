package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"rdpshot/internal/engagement"
	"rdpshot/internal/estate"
	"rdpshot/internal/model"
	"rdpshot/internal/policy"
	"rdpshot/internal/score"
	"rdpshot/internal/siem"
	"rdpshot/internal/store"
)

// SIEMConfig is the persisted SIEM sink configuration.
type SIEMConfig struct {
	WebhookURL string      `json:"webhook_url"`
	Format     siem.Format `json:"format"`
	Enabled    bool        `json:"enabled"`
}

// CredentialReuseEntry summarises one account seen on multiple hosts.
type CredentialReuseEntry struct {
	Username string   `json:"username"`
	Domain   string   `json:"domain,omitempty"`
	Hosts    []string `json:"hosts"`
	Count    int      `json:"count"`
}

func (s *Server) handleScanScore(w http.ResponseWriter, r *http.Request) {
	scan, ok := s.loadScan(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	hosts, err := s.deps.Store.ListHosts(scan.ID)
	if err != nil {
		s.internalError(w, r, "list hosts for score", err)
		return
	}
	findings, err := s.deps.Store.ListFindings(scan.ID)
	if err != nil {
		s.internalError(w, r, "list findings for score", err)
		return
	}
	s.writeJSON(w, http.StatusOK, score.EvaluateScan(scan.ID, hosts, findings))
}

func (s *Server) handleScanPolicy(w http.ResponseWriter, r *http.Request) {
	scan, ok := s.loadScan(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	doc, err := s.loadPolicyDocument()
	if err != nil {
		s.internalError(w, r, "load policy", err)
		return
	}
	hosts, err := s.deps.Store.ListHosts(scan.ID)
	if err != nil {
		s.internalError(w, r, "list hosts for policy", err)
		return
	}
	findings, err := s.deps.Store.ListFindings(scan.ID)
	if err != nil {
		s.internalError(w, r, "list findings for policy", err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"policy": doc,
		"result": policy.Evaluate(doc, hosts, findings),
	})
}

func (s *Server) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	doc, err := s.loadPolicyDocument()
	if err != nil {
		s.internalError(w, r, "load policy", err)
		return
	}
	s.writeJSON(w, http.StatusOK, doc)
}

func (s *Server) handlePutPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.requireWrite(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var doc policy.Document
	if err := json.NewDecoder(r.Body).Decode(&doc); err != nil {
		s.writeAPIError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := s.deps.Store.SetSettingJSON(store.PolicySettingsKey(), doc); err != nil {
		s.internalError(w, r, "save policy", err)
		return
	}
	s.audit(r, "policy.update", "hardening", "")
	s.writeJSON(w, http.StatusOK, doc)
}

func (s *Server) handleEstate(w http.ResponseWriter, r *http.Request) {
	engagementName := strings.TrimSpace(r.URL.Query().Get("engagement"))
	scanID := strings.TrimSpace(r.URL.Query().Get("scan_id"))
	var hosts []model.Host
	var findings []model.Finding
	if scanID != "" {
		scan, ok := s.loadScan(w, r, scanID)
		if !ok {
			return
		}
		if engagementName == "" {
			engagementName = scan.Engagement
		}
		var err error
		hosts, err = s.deps.Store.ListHosts(scan.ID)
		if err != nil {
			s.internalError(w, r, "list hosts for estate", err)
			return
		}
		findings, err = s.deps.Store.ListFindings(scan.ID)
		if err != nil {
			s.internalError(w, r, "list findings for estate", err)
			return
		}
	} else {
		scans, err := s.deps.Store.ListScansFiltered(recentScansLimit, engagementName, "")
		if err != nil {
			s.internalError(w, r, "list scans for estate", err)
			return
		}
		for _, sc := range scans {
			h, err := s.deps.Store.ListHosts(sc.ID)
			if err != nil {
				s.internalError(w, r, "list hosts for estate", err)
				return
			}
			f, err := s.deps.Store.ListFindings(sc.ID)
			if err != nil {
				s.internalError(w, r, "list findings for estate", err)
				return
			}
			hosts = append(hosts, h...)
			findings = append(findings, f...)
		}
	}
	s.writeJSON(w, http.StatusOK, estate.Build(engagementName, hosts, findings))
}

func (s *Server) handleEstateBlastRadius(w http.ResponseWriter, r *http.Request) {
	engagementName := strings.TrimSpace(r.URL.Query().Get("engagement"))
	scanID := strings.TrimSpace(r.URL.Query().Get("scan"))
	var hosts []model.Host
	var findings []model.Finding
	var creds []model.Credential

	if scanID != "" {
		h, err := s.deps.Store.ListHosts(scanID)
		if err != nil {
			s.internalError(w, r, "list hosts for blast radius", err)
			return
		}
		hosts = h
		f, err := s.deps.Store.ListFindings(scanID)
		if err != nil {
			s.internalError(w, r, "list findings for blast radius", err)
			return
		}
		findings = f
		c, err := s.deps.Store.ListCredentials(scanID)
		if err != nil {
			s.internalError(w, r, "list credentials for blast radius", err)
			return
		}
		creds = c
	} else {
		scans, err := s.deps.Store.ListScansFiltered(recentScansLimit, engagementName, "")
		if err != nil {
			s.internalError(w, r, "list scans for blast radius", err)
			return
		}
		for _, sc := range scans {
			h, err := s.deps.Store.ListHosts(sc.ID)
			if err == nil {
				hosts = append(hosts, h...)
			}
			f, err := s.deps.Store.ListFindings(sc.ID)
			if err == nil {
				findings = append(findings, f...)
			}
			c, err := s.deps.Store.ListCredentials(sc.ID)
			if err == nil {
				creds = append(creds, c...)
			}
		}
	}
	s.writeJSON(w, http.StatusOK, estate.BuildBlastRadius(engagementName, hosts, creds, findings))
}

func (s *Server) handleScanCompliancePosture(w http.ResponseWriter, r *http.Request) {
	scanID := r.PathValue("id")
	var hosts []model.Host
	var findings []model.Finding
	var err error

	if scanID == "all" || scanID == "" {
		scans, err := s.deps.Store.ListScans(recentScansLimit)
		if err != nil {
			s.internalError(w, r, "list scans for compliance posture", err)
			return
		}
		for _, sc := range scans {
			h, err := s.deps.Store.ListHosts(sc.ID)
			if err == nil {
				hosts = append(hosts, h...)
			}
			f, err := s.deps.Store.ListFindings(sc.ID)
			if err == nil {
				findings = append(findings, f...)
			}
		}
		s.writeJSON(w, http.StatusOK, score.EvaluateCompliancePosture("all", hosts, findings))
		return
	}

	scan, ok := s.loadScan(w, r, scanID)
	if !ok {
		return
	}
	hosts, err = s.deps.Store.ListHosts(scan.ID)
	if err != nil {
		s.internalError(w, r, "list hosts for compliance posture", err)
		return
	}
	findings, err = s.deps.Store.ListFindings(scan.ID)
	if err != nil {
		s.internalError(w, r, "list findings for compliance posture", err)
		return
	}
	s.writeJSON(w, http.StatusOK, score.EvaluateCompliancePosture(scan.ID, hosts, findings))
}

func (s *Server) handleCredentialReuse(w http.ResponseWriter, r *http.Request) {
	scan, ok := s.loadScan(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	creds, err := s.deps.Store.ListCredentials(scan.ID)
	if err != nil {
		s.internalError(w, r, "list credentials for reuse", err)
		return
	}
	type key struct{ domain, user string }
	groups := map[key]map[string]bool{}
	for _, c := range creds {
		k := key{domain: c.Domain, user: c.Username}
		if groups[k] == nil {
			groups[k] = map[string]bool{}
		}
		groups[k][model.Endpoint{Address: c.Address, Port: c.Port}.Key()] = true
	}
	var out []CredentialReuseEntry
	for k, hosts := range groups {
		entry := CredentialReuseEntry{Username: k.user, Domain: k.domain, Count: len(hosts)}
		for h := range hosts {
			entry.Hosts = append(entry.Hosts, h)
		}
		if entry.Count >= 1 {
			out = append(out, entry)
		}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"scan_id": scan.ID, "reuse": out})
}

func (s *Server) handleGetSIEM(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.loadSIEMConfig()
	if err != nil {
		s.internalError(w, r, "load siem config", err)
		return
	}
	s.writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) handlePutSIEM(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	var cfg SIEMConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		s.writeAPIError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	cfg.WebhookURL = strings.TrimSpace(cfg.WebhookURL)
	if cfg.Format != siem.FormatCEF && cfg.Format != siem.FormatJSON {
		cfg.Format = siem.FormatJSON
	}
	if err := s.deps.Store.SetSettingJSON(store.SIEMSettingsKey(), cfg); err != nil {
		s.internalError(w, r, "save siem config", err)
		return
	}
	s.audit(r, "siem.update", "sink", string(cfg.Format))
	s.writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) handleFreezeEngagement(w http.ResponseWriter, r *http.Request) {
	if !s.requireWrite(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var payload engagement.FreezeScope
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		s.writeAPIError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	payload.Engagement = strings.TrimSpace(payload.Engagement)
	if payload.Engagement == "" {
		s.writeAPIError(w, http.StatusBadRequest, "engagement is required")
		return
	}
	payload.FrozenAt = time.Now().UTC()
	if err := s.deps.Store.SetSettingJSON(engagement.ScopeKey(payload.Engagement), payload); err != nil {
		s.internalError(w, r, "freeze engagement", err)
		return
	}
	s.audit(r, "engagement.freeze", payload.Engagement, payload.ScanID)
	s.writeJSON(w, http.StatusOK, payload)
}

func (s *Server) handleGetEngagementScope(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("engagement"))
	if name == "" {
		s.writeAPIError(w, http.StatusBadRequest, "engagement query parameter is required")
		return
	}
	raw, err := s.deps.Store.GetSettingJSON(engagement.ScopeKey(name))
	if err != nil {
		s.internalError(w, r, "load engagement scope", err)
		return
	}
	if raw == nil {
		s.writeAPIError(w, http.StatusNotFound, "engagement scope not found")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func (s *Server) loadPolicyDocument() (policy.Document, error) {
	raw, err := s.deps.Store.GetSettingJSON(store.PolicySettingsKey())
	if err != nil {
		return policy.Document{}, err
	}
	if raw == nil {
		return policy.Default(), nil
	}
	var doc policy.Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return policy.Document{}, err
	}
	return doc, nil
}

func (s *Server) loadSIEMConfig() (SIEMConfig, error) {
	raw, err := s.deps.Store.GetSettingJSON(store.SIEMSettingsKey())
	if err != nil {
		return SIEMConfig{}, err
	}
	if raw == nil {
		return SIEMConfig{Format: siem.FormatJSON}, nil
	}
	var cfg SIEMConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return SIEMConfig{}, err
	}
	if cfg.Format == "" {
		cfg.Format = siem.FormatJSON
	}
	return cfg, nil
}

func (s *Server) maybeStreamSIEM(scan model.Scan) {
	cfg, err := s.loadSIEMConfig()
	if err != nil || !cfg.Enabled || strings.TrimSpace(cfg.WebhookURL) == "" {
		return
	}
	hosts, err := s.deps.Store.ListHosts(scan.ID)
	if err != nil {
		return
	}
	findings, err := s.deps.Store.ListFindings(scan.ID)
	if err != nil {
		return
	}
	sc := score.EvaluateScan(scan.ID, hosts, findings)
	events := []siem.Event{siem.FromScanFinished(scan, sc.Score)}
	for _, f := range findings {
		if f.Status == model.FindingVulnerable || f.Status == model.FindingPotential {
			events = append(events, siem.FromFinding(scan, f))
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := siem.Deliver(ctx, cfg.WebhookURL, cfg.Format, events); err != nil {
		s.deps.Logger.Error("siem deliver failed", "scan_id", scan.ID, "error", err.Error())
	}
}
