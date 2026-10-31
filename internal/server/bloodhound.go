package server

import (
	"fmt"
	"net/http"
	"strings"

	"rdpshot/internal/bloodhound"
	"rdpshot/internal/model"
)

// handleBloodHoundExport serves a BloodHound CE v5 JSON file built from the
// requested engagement or scan's hosts, credentials, and findings.
//
//	GET /api/v1/estate/bloodhound.json?engagement=CORP
//	GET /api/v1/estate/bloodhound.json?scan_id=scan-abc
//
// The file is streamed with Content-Disposition: attachment so browsers
// download it immediately.
func (s *Server) handleBloodHoundExport(w http.ResponseWriter, r *http.Request) {
	engagementName := strings.TrimSpace(r.URL.Query().Get("engagement"))
	scanID := strings.TrimSpace(r.URL.Query().Get("scan_id"))

	var hosts []model.Host
	var creds []model.Credential
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
			s.internalError(w, r, "bloodhound: list hosts", err)
			return
		}
		findings, err = s.deps.Store.ListFindings(scan.ID)
		if err != nil {
			s.internalError(w, r, "bloodhound: list findings", err)
			return
		}
		creds, err = s.deps.Store.ListCredentials(scan.ID)
		if err != nil {
			s.internalError(w, r, "bloodhound: list credentials", err)
			return
		}
	} else {
		// Aggregate the most recent scans for this engagement.
		scans, err := s.deps.Store.ListScansFiltered(recentScansLimit, engagementName, "")
		if err != nil {
			s.internalError(w, r, "bloodhound: list scans", err)
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

	export := bloodhound.BuildExport(engagementName, hosts, creds, findings)
	b, err := export.JSON()
	if err != nil {
		s.internalError(w, r, "bloodhound: marshal json", err)
		return
	}

	filename := "bloodhound-export.json"
	if engagementName != "" {
		safe := strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
				return r
			}
			return '-'
		}, engagementName)
		filename = fmt.Sprintf("bloodhound-%s.json", safe)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)

	s.audit(r, "bloodhound.export", engagementName, scanID)
}
