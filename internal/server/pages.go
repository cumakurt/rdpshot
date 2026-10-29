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

// ScansData renders the scan list page.
type ScansData struct {
	Title, ActiveNav string
	Scans            []model.Scan
}

// ScanDetailData renders one scan with all of its results.
type ScanDetailData struct {
	Title, ActiveNav string
	Scan             model.Scan
	Hosts            []model.Host
	Findings         []model.Finding
	Creds            []model.Credential
	Screens          []model.Screenshot
	Summary          model.Summary
	Wordlists        WordlistPickerData
}

// GalleryData renders the screenshot gallery page.
type GalleryData struct {
	Title, ActiveNav string
	Items            []model.Screenshot
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

// handleScans renders the scan list page.
func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	scans, err := s.deps.Store.ListScans(recentScansLimit)
	if err != nil {
		s.internalError(w, r, "load scans", err)
		return
	}
	s.renderPage(w, "scans", ScansData{
		Title:     "Scans",
		ActiveNav: "scans",
		Scans:     scans,
	})
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
	summary, err := s.deps.Store.Summary(id)
	if err != nil {
		s.internalError(w, r, "load scan summary", err)
		return
	}
	s.renderPage(w, "scan_detail", ScanDetailData{
		Title:     "Scan " + scan.Name,
		ActiveNav: "scans",
		Scan:      scan,
		Hosts:     hosts,
		Findings:  findings,
		Creds:     maskCredentials(creds),
		Screens:   screenshotViews(screens),
		Summary:   summary,
		Wordlists: s.wordlistPicker("brute"),
	})
}

// handleGallery renders every captured screenshot across all scans.
func (s *Server) handleGallery(w http.ResponseWriter, r *http.Request) {
	items, err := s.allScreenshots()
	if err != nil {
		s.internalError(w, r, "load screenshots", err)
		return
	}
	s.renderPage(w, "gallery", GalleryData{
		Title:     "Gallery",
		ActiveNav: "gallery",
		Items:     items,
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

// allScreenshots collects screenshots of every scan, newest first. The store
// exposes screenshots per scan, so the scan list is the index.
func (s *Server) allScreenshots() ([]model.Screenshot, error) {
	scans, err := s.deps.Store.ListScans(recentScansLimit)
	if err != nil {
		return nil, err
	}
	var items []model.Screenshot
	for _, sc := range scans {
		shots, err := s.deps.Store.ListScreenshots(sc.ID)
		if err != nil {
			return nil, err
		}
		items = append(items, shots...)
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].CapturedAt.After(items[j].CapturedAt)
	})
	return items, nil
}

// maskCredentials hides every secret before display or serialization.
func maskCredentials(creds []model.Credential) []model.Credential {
	out := make([]model.Credential, len(creds))
	for i, c := range creds {
		out[i] = c.Masked()
	}
	return out
}

// screenshotViews rewrites file paths to their read-only web URLs.
func screenshotViews(screens []model.Screenshot) []model.Screenshot {
	out := make([]model.Screenshot, len(screens))
	for i, sc := range screens {
		out[i] = screenshotView(sc)
	}
	return out
}

// internalError logs a server-side failure and renders the error page.
func (s *Server) internalError(w http.ResponseWriter, r *http.Request, what string, err error) {
	s.deps.Logger.Error(what, "error", err.Error())
	s.writeError(w, r, http.StatusInternalServerError, "internal server error")
}
