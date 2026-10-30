package server

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"

	"rdpshot/internal/about"
	"rdpshot/internal/model"
	"rdpshot/internal/score"
	"rdpshot/internal/screenshot"
	"rdpshot/internal/store"
	"rdpshot/web"
)

// Page data structures. Each is passed to one page template define together
// with the shared "head"/"nav"/"footer" partials.

// WordlistPickerData drives the shared wordlist upload / default-path control.
type WordlistPickerData struct {
	IDPrefix     string
	UserPath     string
	PasswordPath string
}

// DashboardData renders the command center page.
type DashboardData struct {
	Title        string
	ActiveNav    string
	Summary      model.Summary
	RecentScans  []model.Scan
	ActiveScan   *model.Scan // nil when no scan is running
	RecentEvents []model.Event
	Wordlists    WordlistPickerData
}

// ScansDashboardStats aggregates lifecycle and result counters for the scans hub.
type ScansDashboardStats struct {
	Total       int
	Active      int // pending + running + paused
	Pending     int
	Running     int
	Paused      int
	Completed   int
	Failed      int
	Cancelled   int
	Findings    int64
	Creds       int64
	Screens     int64
	Engagements int
}

// ScansData renders the scans dashboard (KPIs + active jobs + inventory).
type ScansData struct {
	Title, ActiveNav string
	Scans            []model.Scan
	ActiveScans      []model.Scan
	Stats            ScansDashboardStats
}

// ScanDetailData renders one scan with all of its results.
type ScanDetailData struct {
	Title, ActiveNav string
	Scan             model.Scan
	Hosts            []model.Host
	Findings         []model.Finding
	Creds            []model.Credential
	AuthAttempts     []model.AuthAttempt
	Screens          []model.Screenshot
	Summary          model.Summary
	Score            score.ScanScore
	Wordlists        WordlistPickerData
}

// EstateData renders the attack-surface risk map page.
type EstateData struct {
	Title, ActiveNav string
	Engagement       string
	Scans            []model.Scan
}

// GalleryItem is one gallery card with its owning scan label.
type GalleryItem struct {
	model.Screenshot
	ScanName string
}

// GalleryData renders the screenshot gallery page.
type GalleryData struct {
	Title, ActiveNav string
	Items            []GalleryItem
	Scans            []model.Scan
	SelectedScanID   string
}

// ReportsData renders the vulnerability and reporting hub.
type ReportsData struct {
	Title, ActiveNav string
	Summary          model.Summary
	Analytics        model.Analytics
	CVEStats         []model.CVEStat
	LatestScan       *model.Scan
	Scans            []model.Scan
}

// CompareData renders the scan-to-scan diff page.
type CompareData struct {
	Title, ActiveNav string
	Scans            []model.Scan
	BaseID           string
	AgainstID        string
	Diff             *model.ScanDiff
	Error            string
}

// SchedulesData renders the recurring scan manager.
type SchedulesData struct {
	Title, ActiveNav string
	Schedules        []model.Schedule
	Wordlists        WordlistPickerData
}

// AboutData renders the developer / project identity page.
type AboutData struct {
	Title, ActiveNav string
	Info             about.Info
}

// parseTemplates parses every template file from the embedded filesystem into
// one set. Pages execute by their define name ("dashboard", "scans", ...).
// toolVersion is exposed to shared partials through template functions.
func parseTemplates(toolVersion string) (*template.Template, error) {
	info := about.Snapshot(toolVersion)
	funcs := template.FuncMap{
		"appInfo": func() about.Info { return info },
	}
	tpl, err := template.New("").Funcs(funcs).ParseFS(web.FS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("server: parse templates: %w", err)
	}
	return tpl, nil
}

// renderPage executes one page template into the response.
func (s *Server) renderPage(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tpl.ExecuteTemplate(w, name, data); err != nil {
		// The status may already be committed; log loudly regardless.
		s.deps.Logger.Error("render template", "template", name, "error", err.Error())
	}
}

// handleDashboard renders the overview page.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	summary, err := s.deps.Store.Summary("")
	if err != nil {
		s.internalError(w, r, "load summary", err)
		return
	}
	scans, err := s.deps.Store.ListScans(recentScansLimit)
	if err != nil {
		s.internalError(w, r, "load recent scans", err)
		return
	}
	var active *model.Scan
	for i := range scans {
		if scans[i].Status == model.ScanRunning || scans[i].Status == model.ScanPending {
			active = &scans[i]
			break
		}
	}
	s.renderPage(w, "dashboard", DashboardData{
		Title:        "Dashboard",
		ActiveNav:    "dashboard",
		Summary:      summary,
		RecentScans:  scans,
		ActiveScan:   active,
		RecentEvents: s.recentEvents(),
		Wordlists:    s.wordlistPicker("scan"),
	})
}

// recentScansLimit bounds the dashboard and scans tables.
const recentScansLimit = 100

// handleScans renders the scans dashboard.
func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	scans, err := s.deps.Store.ListScans(recentScansLimit)
	if err != nil {
		s.internalError(w, r, "load scans", err)
		return
	}
	stats, active := buildScansDashboard(scans)
	s.renderPage(w, "scans", ScansData{
		Title:       "Scans Dashboard",
		ActiveNav:   "scans",
		Scans:       scans,
		ActiveScans: active,
		Stats:       stats,
	})
}

// buildScansDashboard derives KPI counters and the active-job subset from a
// scan inventory. Counts are over the provided slice (recent window), not the
// entire historical database when the list is truncated.
func buildScansDashboard(scans []model.Scan) (ScansDashboardStats, []model.Scan) {
	stats := ScansDashboardStats{Total: len(scans)}
	engagements := make(map[string]struct{})
	active := make([]model.Scan, 0)
	for _, sc := range scans {
		stats.Findings += sc.Progress.Findings
		stats.Creds += sc.Progress.Creds
		stats.Screens += sc.Progress.Screens
		if name := strings.TrimSpace(sc.Engagement); name != "" {
			engagements[name] = struct{}{}
		}
		switch sc.Status {
		case model.ScanPending:
			stats.Pending++
			stats.Active++
			active = append(active, sc)
		case model.ScanRunning:
			stats.Running++
			stats.Active++
			active = append(active, sc)
		case model.ScanPaused:
			stats.Paused++
			stats.Active++
			active = append(active, sc)
		case model.ScanCompleted:
			stats.Completed++
		case model.ScanFailed:
			stats.Failed++
		case model.ScanCancelled:
			stats.Cancelled++
		}
	}
	stats.Engagements = len(engagements)
	return stats, active
}

// handleScanDetail renders one scan with its hosts, findings, credentials and
// screenshots. Credential secrets are always masked.
func (s *Server) handleScanDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	scan, ok := s.loadScan(w, r, id)
	if !ok {
		return
	}
	hosts, err := s.deps.Store.ListHosts(id)
	if err != nil {
		s.internalError(w, r, "load hosts", err)
		return
	}
	findings, err := s.deps.Store.ListFindings(id)
	if err != nil {
		s.internalError(w, r, "load findings", err)
		return
	}
	creds, err := s.deps.Store.ListCredentials(id)
	if err != nil {
		s.internalError(w, r, "load credentials", err)
		return
	}
	screens, err := s.deps.Store.ListScreenshots(id)
	if err != nil {
		s.internalError(w, r, "load screenshots", err)
		return
	}
	authAttempts, err := s.deps.Store.ListAuthAttempts(id)
	if err != nil {
		s.internalError(w, r, "load auth attempts", err)
		return
	}
	summary, err := s.deps.Store.Summary(id)
	if err != nil {
		s.internalError(w, r, "load scan summary", err)
		return
	}
	s.renderPage(w, "scan_detail", ScanDetailData{
		Title:        "Scan " + scan.Name,
		ActiveNav:    "scans",
		Scan:         scan,
		Hosts:        openHostsOnly(hosts),
		Findings:     findings,
		Creds:        maskCredentials(creds),
		AuthAttempts: successfulAuthAttempts(authAttempts),
		Screens:      screenshotViews(screens),
		Summary:      summary,
		Score:        score.EvaluateScan(scan.ID, hosts, findings),
		Wordlists:    s.wordlistPicker("brute"),
	})
}

// successfulAuthAttempts keeps verified logins for the Auth Attempts panel.
func successfulAuthAttempts(attempts []model.AuthAttempt) []model.AuthAttempt {
	out := make([]model.AuthAttempt, 0, len(attempts))
	for _, a := range attempts {
		if a.Outcome == model.AuthOutcomeSuccess {
			out = append(out, a)
		}
	}
	return out
}

// openHostsOnly keeps endpoints where RDP was actually discovered.
func openHostsOnly(hosts []model.Host) []model.Host {
	out := make([]model.Host, 0, len(hosts))
	for _, h := range hosts {
		if h.State == "open" {
			out = append(out, h)
		}
	}
	return out
}

// handleEstatePage renders the estate risk map.
func (s *Server) handleEstatePage(w http.ResponseWriter, r *http.Request) {
	engagement := strings.TrimSpace(r.URL.Query().Get("engagement"))
	scans, err := s.deps.Store.ListScansFiltered(recentScansLimit, engagement, "")
	if err != nil {
		s.internalError(w, r, "load scans for estate", err)
		return
	}
	s.renderPage(w, "estate", EstateData{
		Title:      "Estate",
		ActiveNav:  "estate",
		Engagement: engagement,
		Scans:      scans,
	})
}

// handleGallery renders captured screenshots across scans. Optional query
// param scan=<id> limits the vault to one audit; omit it to show every frame.
func (s *Server) handleGallery(w http.ResponseWriter, r *http.Request) {
	scans, err := s.deps.Store.ListScans(recentScansLimit)
	if err != nil {
		s.internalError(w, r, "load scans", err)
		return
	}
	selected := strings.TrimSpace(r.URL.Query().Get("scan"))
	items, err := s.galleryItems(scans, selected)
	if err != nil {
		s.internalError(w, r, "load screenshots", err)
		return
	}
	// Dropdown only lists scans that actually have gallery-worthy frames.
	scanOptions, err := s.scansWithScreenshots(scans)
	if err != nil {
		s.internalError(w, r, "load gallery scans", err)
		return
	}
	if selected != "" {
		found := false
		for _, sc := range scanOptions {
			if sc.ID == selected {
				found = true
				break
			}
		}
		if !found {
			selected = ""
		}
	}
	s.renderPage(w, "gallery", GalleryData{
		Title:          "Gallery",
		ActiveNav:      "gallery",
		Items:          items,
		Scans:          scanOptions,
		SelectedScanID: selected,
	})
}

// handleCompare renders the scan diff page. Optional query params base and
// against select the two audits to compare.
func (s *Server) handleCompare(w http.ResponseWriter, r *http.Request) {
	scans, err := s.deps.Store.ListScans(recentScansLimit)
	if err != nil {
		s.internalError(w, r, "load scans", err)
		return
	}
	baseID := strings.TrimSpace(r.URL.Query().Get("base"))
	againstID := strings.TrimSpace(r.URL.Query().Get("against"))
	data := CompareData{
		Title:     "Compare",
		ActiveNav: "compare",
		Scans:     scans,
		BaseID:    baseID,
		AgainstID: againstID,
	}
	if baseID != "" && againstID != "" {
		if baseID == againstID {
			data.Error = "Select two different scans to compare."
		} else {
			diff, err := s.deps.Store.DiffScans(baseID, againstID)
			if err != nil {
				data.Error = err.Error()
			} else {
				data.Diff = &diff
			}
		}
	}
	s.renderPage(w, "compare", data)
}

// handleSchedulesPage renders the recurring scan manager.
func (s *Server) handleSchedulesPage(w http.ResponseWriter, r *http.Request) {
	items, err := s.deps.Store.ListSchedules()
	if err != nil {
		s.internalError(w, r, "load schedules", err)
		return
	}
	s.renderPage(w, "schedules", SchedulesData{
		Title:     "Schedules",
		ActiveNav: "schedules",
		Schedules: items,
		Wordlists: s.wordlistPicker("sched"),
	})
}

// handleReports renders the vulnerability and reporting hub.
func (s *Server) handleReports(w http.ResponseWriter, r *http.Request) {
	summary, err := s.deps.Store.Summary("")
	if err != nil {
		s.internalError(w, r, "load summary", err)
		return
	}
	analytics, err := s.deps.Store.Analytics()
	if err != nil {
		s.internalError(w, r, "load analytics", err)
		return
	}
	cveStats, err := s.deps.Store.CVEStats("")
	if err != nil {
		s.internalError(w, r, "load cve statistics", err)
		return
	}
	scans, err := s.deps.Store.ListScans(recentScansLimit)
	if err != nil {
		s.internalError(w, r, "load scans", err)
		return
	}
	var latest *model.Scan
	if len(scans) > 0 {
		latest = &scans[0]
	}
	s.renderPage(w, "reports", ReportsData{
		Title:      "Reports",
		ActiveNav:  "reports",
		Summary:    summary,
		Analytics:  analytics,
		CVEStats:   cveStats,
		LatestScan: latest,
		Scans:      scans,
	})
}

// handleAbout renders the developer and project identity page.
func (s *Server) handleAbout(w http.ResponseWriter, r *http.Request) {
	s.renderPage(w, "about", AboutData{
		Title:     "About",
		ActiveNav: "about",
		Info:      about.Snapshot(s.cfg.ToolVersion),
	})
}

// loadScan fetches one scan, writing a 404 page when it does not exist.
func (s *Server) loadScan(w http.ResponseWriter, r *http.Request, id string) (model.Scan, bool) {
	scan, err := s.deps.Store.GetScan(id)
	if errors.Is(err, store.ErrScanNotFound) {
		s.writeError(w, r, http.StatusNotFound, "scan not found")
		return model.Scan{}, false
	}
	if err != nil {
		s.internalError(w, r, "load scan", err)
		return model.Scan{}, false
	}
	return scan, true
}

// galleryItems builds gallery cards for every scan, or one selected scan.
func (s *Server) galleryItems(scans []model.Scan, selectedScanID string) ([]GalleryItem, error) {
	names := make(map[string]string, len(scans))
	for _, sc := range scans {
		names[sc.ID] = sc.Name
	}
	var items []GalleryItem
	for _, sc := range scans {
		if selectedScanID != "" && sc.ID != selectedScanID {
			continue
		}
		shots, err := s.deps.Store.ListScreenshots(sc.ID)
		if err != nil {
			return nil, err
		}
		for _, shot := range screenshotViews(shots) {
			items = append(items, GalleryItem{
				Screenshot: shot,
				ScanName:   names[sc.ID],
			})
		}
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].CapturedAt.After(items[j].CapturedAt)
	})
	return items, nil
}

// scansWithScreenshots returns scans that own at least one gallery frame.
func (s *Server) scansWithScreenshots(scans []model.Scan) ([]model.Scan, error) {
	out := make([]model.Scan, 0, len(scans))
	for _, sc := range scans {
		shots, err := s.deps.Store.ListScreenshots(sc.ID)
		if err != nil {
			return nil, err
		}
		if len(screenshotViews(shots)) > 0 {
			out = append(out, sc)
		}
	}
	return out, nil
}

// maskCredentials hides every secret before display or serialization.
func maskCredentials(creds []model.Credential) []model.Credential {
	out := make([]model.Credential, len(creds))
	for i, c := range creds {
		out[i] = c.Masked()
	}
	return out
}

// screenshotViews rewrites file paths to their read-only web URLs and drops
// synthetic open-host detection cards (legacy rdp-open rows).
func screenshotViews(screens []model.Screenshot) []model.Screenshot {
	out := make([]model.Screenshot, 0, len(screens))
	for _, sc := range screens {
		if sc.Username == screenshot.OpenHostLabel {
			continue
		}
		out = append(out, screenshotView(sc))
	}
	return out
}

// internalError logs a server-side failure and renders the error page.
func (s *Server) internalError(w http.ResponseWriter, r *http.Request, what string, err error) {
	s.deps.Logger.Error(what, "error", err.Error())
	s.writeError(w, r, http.StatusInternalServerError, "internal server error")
}
