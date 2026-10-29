package server

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"

	"rdpshot/internal/engagement"
	"rdpshot/internal/model"
	"rdpshot/internal/notify"
	"rdpshot/internal/reporter"
	"rdpshot/internal/store"
)

// handleUpdateFindingTriage patches the workflow state of one finding.
func (s *Server) handleUpdateFindingTriage(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("fid"), 10, 64)
	if err != nil || id <= 0 {
		s.writeAPIError(w, http.StatusBadRequest, "invalid finding id")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	var payload struct {
		Status model.TriageStatus `json:"triage_status"`
		Note   string             `json:"triage_note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		s.writeAPIError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if !payload.Status.Valid() {
		s.writeAPIError(w, http.StatusBadRequest, "invalid triage_status")
		return
	}
	finding, err := s.deps.Store.UpdateFindingTriage(id, payload.Status, payload.Note)
	if errors.Is(err, store.ErrNotFound) {
		s.writeAPIError(w, http.StatusNotFound, "finding not found")
		return
	}
	if err != nil {
		s.internalError(w, r, "update finding triage", err)
		return
	}
	s.audit(r, "finding.triage", fmt.Sprintf("%d", id), string(payload.Status))
	s.writeJSON(w, http.StatusOK, finding)
}

// handleUpdateScanMeta patches engagement/tags for a scan.
func (s *Server) handleUpdateScanMeta(w http.ResponseWriter, r *http.Request) {
	scan, ok := s.loadScan(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	var payload struct {
		Engagement *string  `json:"engagement"`
		Tags       []string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		s.writeAPIError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	engagement := scan.Engagement
	if payload.Engagement != nil {
		engagement = strings.TrimSpace(*payload.Engagement)
		if utf8.RuneCountInString(engagement) > 120 {
			s.writeAPIError(w, http.StatusBadRequest, "engagement must be at most 120 characters")
			return
		}
	}
	tags := scan.Tags
	if payload.Tags != nil {
		tags = payload.Tags
	}
	updated, err := s.deps.Store.UpdateScanMeta(scan.ID, engagement, tags)
	if err != nil {
		s.internalError(w, r, "update scan meta", err)
		return
	}
	s.audit(r, "scan.meta", scan.ID, engagement)
	s.writeJSON(w, http.StatusOK, updated)
}

// handleTrend returns posture samples for the reports hub.
func (s *Server) handleTrend(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	series, err := s.deps.Store.Trend(r.URL.Query().Get("engagement"), limit)
	if err != nil {
		s.internalError(w, r, "load trend", err)
		return
	}
	if series.Points == nil {
		series.Points = []model.TrendPoint{}
	}
	s.writeJSON(w, http.StatusOK, series)
}

// handleEvidencePack streams a ZIP of reports + screenshots for one scan.
func (s *Server) handleEvidencePack(w http.ResponseWriter, r *http.Request) {
	scan, ok := s.loadScan(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	data, err := s.reportData(scan)
	if err != nil {
		s.internalError(w, r, "build evidence pack", err)
		return
	}
	shots, err := s.deps.Store.ListScreenshots(scan.ID)
	if err != nil {
		s.internalError(w, r, "list screenshots for pack", err)
		return
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	writeString := func(name, body string) error {
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = io.WriteString(w, body)
		return err
	}
	writeBytes := func(name string, body []byte) error {
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = w.Write(body)
		return err
	}

	packFiles := map[string][]byte{}

	meta, _ := json.MarshalIndent(map[string]any{
		"scan":      scan,
		"generated": time.Now().UTC(),
		"branding":  data.Branding,
		"tool":      data.ToolVersion,
		"score":     data.HardeningScore,
		"grade":     data.HardeningGrade,
	}, "", "  ")
	packFiles["meta.json"] = meta
	if err := writeBytes("meta.json", meta); err != nil {
		s.internalError(w, r, "write meta", err)
		return
	}

	var htmlBuf bytes.Buffer
	if err := reporter.HTML(&htmlBuf, data); err != nil {
		s.internalError(w, r, "render html pack", err)
		return
	}
	packFiles["report.html"] = htmlBuf.Bytes()
	_ = writeBytes("report.html", htmlBuf.Bytes())

	var csvBuf bytes.Buffer
	if err := reporter.CSV(&csvBuf, data); err != nil {
		s.internalError(w, r, "render csv pack", err)
		return
	}
	packFiles["findings.csv"] = csvBuf.Bytes()
	_ = writeBytes("findings.csv", csvBuf.Bytes())

	var pdfBuf bytes.Buffer
	if err := reporter.PDF(&pdfBuf, data); err == nil {
		packFiles["report.pdf"] = pdfBuf.Bytes()
		_ = writeBytes("report.pdf", pdfBuf.Bytes())
	}

	for i, shot := range shots {
		path := shot.FilePath
		raw, err := os.ReadFile(path)
		if err != nil {
			_ = writeString(fmt.Sprintf("screenshots/missing-%d.txt", i+1), err.Error())
			continue
		}
		name := filepath.Base(path)
		if name == "." || name == "/" || name == "" {
			name = fmt.Sprintf("shot-%d.png", i+1)
		}
		packFiles["screenshots/"+name] = raw
		_ = writeBytes("screenshots/"+name, raw)
	}

	manifest, err := engagement.BuildManifest(scan, packFiles)
	if err == nil {
		raw, _ := json.MarshalIndent(manifest, "", "  ")
		_ = writeBytes("manifest.json", raw)
	}

	if err := zw.Close(); err != nil {
		s.internalError(w, r, "close evidence zip", err)
		return
	}

	filename := "rdpshot-" + scan.ID + "-evidence.zip"
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
	s.audit(r, "scan.evidence_pack", scan.ID, filename)
}

// handleListWordlistSets returns named wordlist sets.
func (s *Server) handleListWordlistSets(w http.ResponseWriter, r *http.Request) {
	items, err := s.deps.Store.ListWordlistSets()
	if err != nil {
		s.internalError(w, r, "list wordlist sets", err)
		return
	}
	if items == nil {
		items = []model.WordlistSet{}
	}
	s.writeJSON(w, http.StatusOK, items)
}

// handleCreateWordlistSet registers a named wordlist pair.
func (s *Server) handleCreateWordlistSet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	var payload struct {
		Name         string `json:"name"`
		UserPath     string `json:"user_path"`
		PasswordPath string `json:"password_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		s.writeAPIError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	name := strings.TrimSpace(payload.Name)
	userPath := strings.TrimSpace(payload.UserPath)
	passPath := strings.TrimSpace(payload.PasswordPath)
	if name == "" || userPath == "" || passPath == "" {
		s.writeAPIError(w, http.StatusBadRequest, "name, user_path and password_path are required")
		return
	}
	now := time.Now().UTC()
	set := model.WordlistSet{
		ID: model.NewID("wset"), Name: name, UserPath: userPath, PasswordPath: passPath,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := s.deps.Store.CreateWordlistSet(set); err != nil {
		s.writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, "wordlist_set.create", set.ID, set.Name)
	s.writeJSON(w, http.StatusCreated, set)
}

// handleDeleteWordlistSet removes a named set.
func (s *Server) handleDeleteWordlistSet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.deps.Store.DeleteWordlistSet(id); errors.Is(err, store.ErrNotFound) {
		s.writeAPIError(w, http.StatusNotFound, "wordlist set not found")
		return
	} else if err != nil {
		s.internalError(w, r, "delete wordlist set", err)
		return
	}
	s.audit(r, "wordlist_set.delete", id, "")
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": id})
}

// handleGetBranding returns report branding settings.
func (s *Server) handleGetBranding(w http.ResponseWriter, r *http.Request) {
	b, err := s.deps.Store.GetReportBranding()
	if err != nil {
		s.internalError(w, r, "get branding", err)
		return
	}
	s.writeJSON(w, http.StatusOK, b)
}

// handlePutBranding updates report branding settings.
func (s *Server) handlePutBranding(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	var b model.ReportBranding
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		s.writeAPIError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	b.Organization = strings.TrimSpace(b.Organization)
	b.Engagement = strings.TrimSpace(b.Engagement)
	b.PreparedBy = strings.TrimSpace(b.PreparedBy)
	b.FooterNote = strings.TrimSpace(b.FooterNote)
	b.LogoDataURI = strings.TrimSpace(b.LogoDataURI)
	if b.LogoDataURI != "" && !strings.HasPrefix(b.LogoDataURI, "data:image/") {
		s.writeAPIError(w, http.StatusBadRequest, "logo_data_uri must be a data:image/... URI")
		return
	}
	if err := s.deps.Store.SetReportBranding(b); err != nil {
		s.internalError(w, r, "set branding", err)
		return
	}
	s.audit(r, "branding.update", "report", b.Organization)
	s.writeJSON(w, http.StatusOK, b)
}

// handleListUsers returns local portal accounts (password hashes omitted).
func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	items, err := s.deps.Store.ListUsers()
	if err != nil {
		s.internalError(w, r, "list users", err)
		return
	}
	if items == nil {
		items = []model.User{}
	}
	s.writeJSON(w, http.StatusOK, items)
}

// handleCreateUser creates a local portal account.
func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	var payload struct {
		Username string         `json:"username"`
		Password string         `json:"password"`
		Role     model.UserRole `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		s.writeAPIError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	username := strings.TrimSpace(payload.Username)
	if username == "" || len(payload.Password) < 8 {
		s.writeAPIError(w, http.StatusBadRequest, "username and password (min 8 chars) are required")
		return
	}
	if !payload.Role.Valid() {
		payload.Role = model.RoleOperator
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)
	if err != nil {
		s.internalError(w, r, "hash password", err)
		return
	}
	now := time.Now().UTC()
	user := model.User{
		ID: model.NewID("user"), Username: username, PasswordHash: string(hash),
		Role: payload.Role, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.deps.Store.CreateUser(user); err != nil {
		s.writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, "user.create", user.ID, user.Username)
	s.writeJSON(w, http.StatusCreated, user)
}

// handleDeleteUser removes a local portal account.
func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := s.deps.Store.DeleteUser(id); errors.Is(err, store.ErrNotFound) {
		s.writeAPIError(w, http.StatusNotFound, "user not found")
		return
	} else if err != nil {
		s.internalError(w, r, "delete user", err)
		return
	}
	s.revokeSessionsForUser(id)
	s.audit(r, "user.delete", id, "")
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": id})
}

// handleLogin authenticates a local user and returns a session token.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	var payload struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		s.writeAPIError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	user, err := s.deps.Store.GetUserByUsername(strings.TrimSpace(payload.Username))
	if err != nil {
		s.writeAPIError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(payload.Password)) != nil {
		s.writeAPIError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	token := s.createSession(user)
	s.audit(r, "user.login", user.ID, user.Username)
	s.writeJSON(w, http.StatusOK, map[string]any{
		"token":    token,
		"username": user.Username,
		"role":     user.Role,
	})
}

// handleListAudit returns recent audit entries.
func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := s.deps.Store.ListAudit(limit)
	if err != nil {
		s.internalError(w, r, "list audit", err)
		return
	}
	if items == nil {
		items = []model.AuditEntry{}
	}
	s.writeJSON(w, http.StatusOK, items)
}

func (s *Server) audit(r *http.Request, action, target, detail string) {
	actor := "anonymous"
	if sess := s.sessionFromRequest(r); sess != nil {
		actor = sess.Username
	} else if tokenFromRequest(r) != "" && s.cfg.Token != "" {
		actor = "token"
	}
	_ = s.deps.Store.AppendAudit(model.AuditEntry{
		At:       time.Now().UTC(),
		Actor:    actor,
		Action:   action,
		Target:   target,
		Detail:   detail,
		RemoteIP: r.RemoteAddr,
	})
}

func (s *Server) maybeNotifyScan(scan model.Scan) {
	if scan.ScheduleID == "" {
		sch, err := s.deps.Store.GetScheduleByLastScan(scan.ID)
		if err != nil {
			return
		}
		scan.ScheduleID = sch.ID
		s.deliverScheduleNotification(sch, scan)
		return
	}
	sch, err := s.deps.Store.GetSchedule(scan.ScheduleID)
	if err != nil {
		return
	}
	s.deliverScheduleNotification(sch, scan)
}

func (s *Server) deliverScheduleNotification(sch model.Schedule, scan model.Scan) {
	if strings.TrimSpace(sch.NotifyWebhook) == "" {
		return
	}
	summary, err := s.deps.Store.Summary(scan.ID)
	if err != nil {
		s.deps.Logger.Error("notify summary", "scan_id", scan.ID, "error", err.Error())
		return
	}
	critical := summary.CountBySeverity(model.SeverityCritical)
	high := summary.CountBySeverity(model.SeverityHigh)
	should := sch.NotifyOnComplete || (sch.NotifyOnCritical && critical > 0)
	if !should {
		return
	}
	event := "scan.completed"
	if critical > 0 {
		event = "scan.critical"
	}
	payload := notify.Payload{
		Event: event, At: time.Now().UTC(), ScheduleID: sch.ID,
		ScanID: scan.ID, ScanName: scan.Name, Status: string(scan.Status),
		Summary: summary, Critical: critical, High: high, Engagement: scan.Engagement,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if err := notify.Webhook(ctx, sch.NotifyWebhook, payload); err != nil {
		s.deps.Logger.Error("webhook notify failed",
			"schedule_id", sch.ID, "scan_id", scan.ID, "error", err.Error())
	}
}
