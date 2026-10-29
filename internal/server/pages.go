package server

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"sort"

	"rdpshot/internal/model"
	"rdpshot/internal/store"
	"rdpshot/web"
)

// Page data structures. Each is passed to one page template define together
// with the shared "head"/"nav"/"footer" partials.

// DashboardData renders the command center page.
type DashboardData struct {
	Title        string
	ActiveNav    string
	Summary      model.Summary
	RecentScans  []model.Scan
	ActiveScan   *model.Scan // nil when no scan is running
	RecentEvents []model.Event
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
	CVEStats         []model.CVEStat
	LatestScan       *model.Scan
	Scans            []model.Scan
}

// parseTemplates parses every template file from the embedded filesystem into
// one set. Pages execute by their define name ("dashboard", "scans", ...).
func parseTemplates() (*template.Template, error) {
	tpl, err := template.New("").ParseFS(web.FS, "templates/*.html")
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

// handleReports renders the vulnerability and reporting hub.
func (s *Server) handleReports(w http.ResponseWriter, r *http.Request) {
	summary, err := s.deps.Store.Summary("")
	if err != nil {
		s.internalError(w, r, "load summary", err)
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
		CVEStats:   cveStats,
		LatestScan: latest,
		Scans:      scans,
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
