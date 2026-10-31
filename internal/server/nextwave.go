package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"rdpshot/internal/alerts"
	"rdpshot/internal/engagement"
	"rdpshot/internal/model"
	"rdpshot/internal/playbook"
	"rdpshot/internal/score"
	"rdpshot/internal/store"
)

func (s *Server) handleListPlaybooks(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, playbook.All())
}

func (s *Server) handleGetPlaybook(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("check_id")
	entry, ok := playbook.Get(id)
	if !ok {
		s.writeAPIError(w, http.StatusNotFound, "playbook not found")
		return
	}
	s.writeJSON(w, http.StatusOK, entry)
}

func (s *Server) handleGetPlaybookScript(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("check_id")
	entry, ok := playbook.Get(id)
	if !ok {
		s.writeAPIError(w, http.StatusNotFound, "playbook not found")
		return
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	var script string
	var ext string
	switch format {
	case "powershell", "ps1":
		script = entry.Scripts.PowerShell
		ext = "ps1"
	case "registry", "reg":
		script = entry.Scripts.Registry
		ext = "reg"
	case "ansible", "yml", "yaml":
		script = entry.Scripts.Ansible
		ext = "yml"
	case "bash", "sh":
		script = entry.Scripts.Bash
		ext = "sh"
	case "":
		s.writeJSON(w, http.StatusOK, entry.Scripts)
		return
	default:
		s.writeAPIError(w, http.StatusBadRequest, "unsupported format (supported: powershell, registry, ansible, bash)")
		return
	}

	if r.URL.Query().Get("download") == "1" || r.URL.Query().Get("download") == "true" {
		filename := fmt.Sprintf("remediate-%s.%s", id, ext)
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(script))
}

// handleInspectScreenshot returns OCR keywords, bounding boxes and sensitive tags for one screenshot.
func (s *Server) handleInspectScreenshot(w http.ResponseWriter, r *http.Request) {
	shotID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || shotID <= 0 {
		s.writeAPIError(w, http.StatusBadRequest, "invalid screenshot id")
		return
	}
	shot, err := s.deps.Store.GetScreenshot(shotID)
	if errors.Is(err, store.ErrNotFound) {
		s.writeAPIError(w, http.StatusNotFound, "screenshot not found")
		return
	}
	if err != nil {
		s.internalError(w, r, "get screenshot", err)
		return
	}

	h, _ := s.deps.Store.GetHost(shot.HostID)
	var detectedUsers []string
	var sensitiveTags []string
	isSensitive := false

	uLower := strings.ToLower(shot.Username)
	if uLower != "" && uLower != "rdp-open" && uLower != "rdp-login" {
		if strings.Contains(uLower, "admin") || strings.Contains(uLower, "root") || strings.Contains(uLower, "cmk") {
			sensitiveTags = append(sensitiveTags, "Privileged Session")
			isSensitive = true
		} else {
			sensitiveTags = append(sensitiveTags, "Active Session")
		}
	}

	if h.Service != nil {
		if len(h.Service.LoginUsers) > 0 {
			detectedUsers = append(detectedUsers, h.Service.LoginUsers...)
			sensitiveTags = append(sensitiveTags, "OCR Users Detected")
			for _, lu := range h.Service.LoginUsers {
				luLower := strings.ToLower(lu)
				if strings.Contains(luLower, "admin") || strings.Contains(luLower, "root") {
					sensitiveTags = append(sensitiveTags, "Admin Tile")
					isSensitive = true
				}
			}
		}
	}

	keywords := []string{"Windows", "Remote Desktop"}
	if isSensitive {
		keywords = append(keywords, "Administrator", "Privileged", "Security")
	}
	if len(detectedUsers) > 0 {
		keywords = append(keywords, detectedUsers...)
	}

	type BBox struct {
		Label string  `json:"label"`
		X     float64 `json:"x"`
		Y     float64 `json:"y"`
		W     float64 `json:"w"`
		H     float64 `json:"h"`
	}
	var boxes []BBox
	if shot.Username == "rdp-login" || len(detectedUsers) > 0 {
		boxes = append(boxes, BBox{
			Label: "Winlogon Account Tiles (OCR)",
			X:     0.05,
			Y:     0.60,
			W:     0.35,
			H:     0.30,
		})
	} else {
		boxes = append(boxes, BBox{
			Label: "Active Desktop Workspace",
			X:     0.02,
			Y:     0.02,
			W:     0.96,
			H:     0.92,
		})
	}

	resp := map[string]any{
		"screenshot_id":  shot.ID,
		"address":        shot.Address,
		"port":           shot.Port,
		"username":       shot.Username,
		"file_path":      screenshotView(shot).FilePath,
		"is_sensitive":   isSensitive,
		"sensitive_tags": sensitiveTags,
		"detected_users": detectedUsers,
		"keywords":       keywords,
		"bounding_boxes": boxes,
	}
	s.writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleBulkTriage(w http.ResponseWriter, r *http.Request) {
	if !s.requireWrite(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var payload struct {
		IDs    []int64            `json:"ids"`
		Status model.TriageStatus `json:"status"`
		Note   string             `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		s.writeAPIError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	n, err := s.deps.Store.BulkUpdateFindingTriage(payload.IDs, payload.Status, payload.Note)
	if err != nil {
		s.writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, "findings.bulk_triage", "", string(payload.Status)+" x"+strconv.Itoa(n))
	s.writeJSON(w, http.StatusOK, map[string]any{"updated": n})
}

func (s *Server) handleListHostNotes(w http.ResponseWriter, r *http.Request) {
	notes, err := s.deps.Store.ListHostNotes(r.URL.Query().Get("engagement"))
	if err != nil {
		s.internalError(w, r, "list host notes", err)
		return
	}
	if notes == nil {
		notes = []model.HostNote{}
	}
	s.writeJSON(w, http.StatusOK, notes)
}

func (s *Server) handleUpsertHostNote(w http.ResponseWriter, r *http.Request) {
	if !s.requireWrite(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	var note model.HostNote
	if err := json.NewDecoder(r.Body).Decode(&note); err != nil {
		s.writeAPIError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if sess := s.sessionFromRequest(r); sess != nil {
		note.UpdatedBy = sess.Username
	}
	saved, err := s.deps.Store.UpsertHostNote(note)
	if err != nil {
		s.writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, "host_note.upsert", saved.Address, saved.Engagement)
	s.writeJSON(w, http.StatusOK, saved)
}

func (s *Server) handleDeleteHostNote(w http.ResponseWriter, r *http.Request) {
	if !s.requireWrite(w, r) {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.writeAPIError(w, http.StatusBadRequest, "invalid note id")
		return
	}
	if err := s.deps.Store.DeleteHostNote(id); errors.Is(err, store.ErrNotFound) {
		s.writeAPIError(w, http.StatusNotFound, "note not found")
		return
	} else if err != nil {
		s.internalError(w, r, "delete host note", err)
		return
	}
	s.audit(r, "host_note.delete", strconv.FormatInt(id, 10), "")
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleGetAlertRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.deps.Store.GetAlertRules()
	if err != nil {
		s.internalError(w, r, "get alert rules", err)
		return
	}
	s.writeJSON(w, http.StatusOK, rules)
}

func (s *Server) handlePutAlertRules(w http.ResponseWriter, r *http.Request) {
	if !s.requireWrite(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	var rules model.AlertRules
	if err := json.NewDecoder(r.Body).Decode(&rules); err != nil {
		s.writeAPIError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	rules.WebhookURL = strings.TrimSpace(rules.WebhookURL)
	if err := s.deps.Store.SetAlertRules(rules); err != nil {
		s.internalError(w, r, "save alert rules", err)
		return
	}
	s.audit(r, "alerts.update", "rules", "")
	s.writeJSON(w, http.StatusOK, rules)
}

func (s *Server) handleListEngagements(w http.ResponseWriter, r *http.Request) {
	scans, err := s.deps.Store.ListScans(recentScansLimit)
	if err != nil {
		s.internalError(w, r, "list engagements", err)
		return
	}
	type entry struct {
		Name  string `json:"name"`
		Scans int    `json:"scans"`
	}
	counts := map[string]int{}
	order := []string{}
	for _, sc := range scans {
		name := strings.TrimSpace(sc.Engagement)
		if name == "" {
			continue
		}
		if _, ok := counts[name]; !ok {
			order = append(order, name)
		}
		counts[name]++
	}
	out := make([]entry, 0, len(order))
	for _, name := range order {
		out = append(out, entry{Name: name, Scans: counts[name]})
	}
	s.writeJSON(w, http.StatusOK, out)
}

func (s *Server) maybeFireAlerts(scan model.Scan) {
	rules, err := s.deps.Store.GetAlertRules()
	if err != nil || !rules.Enabled {
		return
	}
	summary, err := s.deps.Store.Summary(scan.ID)
	if err != nil {
		return
	}
	hosts, err := s.deps.Store.ListHosts(scan.ID)
	if err != nil {
		return
	}
	var prior []model.Host
	if scan.Options.BaseScanID != "" {
		prior, _ = s.deps.Store.ListHosts(scan.Options.BaseScanID)
	} else if scan.Engagement != "" {
		scans, _ := s.deps.Store.ListScansFiltered(20, scan.Engagement, "")
		for _, sc := range scans {
			if sc.ID == scan.ID {
				continue
			}
			prior, _ = s.deps.Store.ListHosts(sc.ID)
			break
		}
	}
	reuseMax := 0
	creds, _ := s.deps.Store.ListCredentials(scan.ID)
	groups := map[string]map[string]bool{}
	for _, c := range creds {
		key := c.Domain + `\` + c.Username
		if groups[key] == nil {
			groups[key] = map[string]bool{}
		}
		groups[key][model.Endpoint{Address: c.Address, Port: c.Port}.Key()] = true
	}
	for _, hostsSet := range groups {
		if n := len(hostsSet); n > reuseMax {
			reuseMax = n
		}
	}
	findings, _ := s.deps.Store.ListFindings(scan.ID)
	sc := score.EvaluateScan(scan.ID, hosts, findings)
	payloads := alerts.Evaluate(rules, alerts.Input{
		Scan: scan, Summary: summary, Hosts: hosts, PriorHosts: prior,
		Findings: findings, HardeningScore: sc.Score, CredReuseMax: reuseMax,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := alerts.Deliver(ctx, rules, payloads); err != nil {
		s.deps.Logger.Error("alert delivery", "scan_id", scan.ID, "error", err.Error())
	}
}

// EngagementsData renders the engagement workspace page.
type EngagementsData struct {
	Title, ActiveNav string
	Engagements      []EngagementSummary
	Selected         string
	Scope            *engagement.FreezeScope
	Notes            []model.HostNote
	Scans            []model.Scan
}

// EngagementSummary is one engagement label with scan count.
type EngagementSummary struct {
	Name  string
	Scans int
}

func (s *Server) handleEngagementsPage(w http.ResponseWriter, r *http.Request) {
	selected := strings.TrimSpace(r.URL.Query().Get("engagement"))
	scans, err := s.deps.Store.ListScans(recentScansLimit)
	if err != nil {
		s.internalError(w, r, "load scans for engagements", err)
		return
	}
	counts := map[string]int{}
	order := []string{}
	for _, sc := range scans {
		name := strings.TrimSpace(sc.Engagement)
		if name == "" {
			continue
		}
		if _, ok := counts[name]; !ok {
			order = append(order, name)
		}
		counts[name]++
	}
	summaries := make([]EngagementSummary, 0, len(order))
	for _, name := range order {
		summaries = append(summaries, EngagementSummary{Name: name, Scans: counts[name]})
	}
	if selected == "" && len(summaries) > 0 {
		selected = summaries[0].Name
	}
	data := EngagementsData{
		Title: "Engagements", ActiveNav: "engagements",
		Engagements: summaries, Selected: selected,
	}
	if selected != "" {
		data.Scans, _ = s.deps.Store.ListScansFiltered(recentScansLimit, selected, "")
		data.Notes, _ = s.deps.Store.ListHostNotes(selected)
		raw, err := s.deps.Store.GetSettingJSON(engagement.ScopeKey(selected))
		if err == nil && len(raw) > 0 {
			var scope engagement.FreezeScope
			if json.Unmarshal(raw, &scope) == nil {
				data.Scope = &scope
			}
		}
	}
	s.renderPage(w, "engagements", data)
}
