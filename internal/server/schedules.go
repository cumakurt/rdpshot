package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"rdpshot/internal/cronexpr"
	"rdpshot/internal/model"
	"rdpshot/internal/store"
	"rdpshot/internal/target"
)

// handleListSchedules returns every recurring scan definition.
func (s *Server) handleListSchedules(w http.ResponseWriter, r *http.Request) {
	items, err := s.deps.Store.ListSchedules()
	if err != nil {
		s.internalError(w, r, "load schedules", err)
		return
	}
	if items == nil {
		items = []model.Schedule{}
	}
	s.writeJSON(w, http.StatusOK, redactSchedules(items))
}

// handleGetSchedule returns one schedule.
func (s *Server) handleGetSchedule(w http.ResponseWriter, r *http.Request) {
	sch, ok := s.loadSchedule(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	s.writeJSON(w, http.StatusOK, redactSchedule(sch))
}

// handleCreateSchedule registers a new recurring scan.
func (s *Server) handleCreateSchedule(w http.ResponseWriter, r *http.Request) {
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
	opts, interval, name, err := s.parseScheduleForm(form, fromFile)
	if err != nil {
		s.writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	cronExpr := strings.TrimSpace(form.Get("cron_expr"))
	if cronExpr != "" {
		if _, err := cronexpr.Parse(cronExpr); err != nil {
			s.writeAPIError(w, http.StatusBadRequest, "invalid cron_expr: "+err.Error())
			return
		}
		interval = 0
	} else if err := validateScheduleInterval(interval); err != nil {
		s.writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.resolveScheduleEndpoints(r.Context(), opts); err != nil {
		s.writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}

	now := time.Now().UTC()
	sch := model.Schedule{
		ID:               model.NewID("sched"),
		Name:             name,
		Enabled:          true,
		IntervalSeconds:  interval,
		CronExpr:         cronExpr,
		Options:          opts,
		NotifyWebhook:    strings.TrimSpace(form.Get("notify_webhook")),
		NotifyOnComplete: formBool(form.Get("notify_on_complete")),
		NotifyOnCritical: formBool(form.Get("notify_on_critical")),
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	runAt, err := parseScheduleRunAt(form.Get("run_at"), now)
	if err != nil {
		s.writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	switch {
	case formBool(form.Get("run_immediately")):
		sch.NextRunAt = &now
	case runAt != nil:
		sch.NextRunAt = runAt
	default:
		next, err := nextScheduleRun(sch, now)
		if err != nil {
			s.writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		sch.NextRunAt = &next
	}
	if err := s.deps.Store.CreateSchedule(sch); err != nil {
		s.internalError(w, r, "create schedule", err)
		return
	}
	s.writeJSON(w, http.StatusCreated, redactSchedule(sch))
}

// handleUpdateSchedule patches enabled/name/interval fields of a schedule.
func (s *Server) handleUpdateSchedule(w http.ResponseWriter, r *http.Request) {
	sch, ok := s.loadSchedule(w, r, r.PathValue("id"))
	if !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	var payload struct {
		Name             *string `json:"name"`
		Enabled          *bool   `json:"enabled"`
		IntervalSeconds  *int    `json:"interval_seconds"`
		CronExpr         *string `json:"cron_expr"`
		NotifyWebhook    *string `json:"notify_webhook"`
		NotifyOnComplete *bool   `json:"notify_on_complete"`
		NotifyOnCritical *bool   `json:"notify_on_critical"`
		RunAt            *string `json:"run_at"`
		RunImmediately   bool    `json:"run_immediately"`
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			s.writeAPIError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
	} else {
		if err := r.ParseForm(); err != nil {
			s.writeAPIError(w, http.StatusBadRequest, "invalid form body")
			return
		}
		if v := strings.TrimSpace(r.PostForm.Get("name")); v != "" {
			payload.Name = &v
		}
		if r.PostForm.Has("enabled") {
			v := formBool(r.PostForm.Get("enabled"))
			payload.Enabled = &v
		}
		if v := strings.TrimSpace(r.PostForm.Get("interval_seconds")); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				s.writeAPIError(w, http.StatusBadRequest, "invalid interval_seconds")
				return
			}
			payload.IntervalSeconds = &n
		}
		if v := strings.TrimSpace(r.PostForm.Get("run_at")); v != "" {
			payload.RunAt = &v
		}
		payload.RunImmediately = formBool(r.PostForm.Get("run_immediately"))
	}

	if payload.Name != nil {
		name := strings.TrimSpace(*payload.Name)
		if name == "" || utf8.RuneCountInString(name) > 200 {
			s.writeAPIError(w, http.StatusBadRequest, "name must be 1-200 characters")
			return
		}
		sch.Name = name
	}
	if payload.Enabled != nil {
		sch.Enabled = *payload.Enabled
	}
	if payload.IntervalSeconds != nil {
		sch.IntervalSeconds = *payload.IntervalSeconds
	}
	if payload.CronExpr != nil {
		expr := strings.TrimSpace(*payload.CronExpr)
		if expr != "" {
			if _, err := cronexpr.Parse(expr); err != nil {
				s.writeAPIError(w, http.StatusBadRequest, "invalid cron_expr: "+err.Error())
				return
			}
		}
		sch.CronExpr = expr
	}
	if payload.NotifyWebhook != nil {
		sch.NotifyWebhook = strings.TrimSpace(*payload.NotifyWebhook)
	}
	if payload.NotifyOnComplete != nil {
		sch.NotifyOnComplete = *payload.NotifyOnComplete
	}
	if payload.NotifyOnCritical != nil {
		sch.NotifyOnCritical = *payload.NotifyOnCritical
	}
	if sch.CronExpr == "" {
		if err := validateScheduleInterval(sch.IntervalSeconds); err != nil {
			s.writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	now := time.Now().UTC()
	switch {
	case payload.RunImmediately:
		sch.NextRunAt = &now
		sch.Enabled = true
	case payload.RunAt != nil:
		runAt, err := parseScheduleRunAt(*payload.RunAt, now)
		if err != nil {
			s.writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		if runAt == nil {
			s.writeAPIError(w, http.StatusBadRequest, "run_at is required when provided")
			return
		}
		sch.NextRunAt = runAt
		sch.Enabled = true
	default:
		if next, err := nextScheduleRun(sch, now); err == nil {
			sch.NextRunAt = &next
		}
	}
	sch.UpdatedAt = now
	if err := s.deps.Store.UpdateSchedule(sch); err != nil {
		s.internalError(w, r, "update schedule", err)
		return
	}
	s.writeJSON(w, http.StatusOK, redactSchedule(sch))
}

// handleDeleteSchedule removes a recurring scan definition.
func (s *Server) handleDeleteSchedule(w http.ResponseWriter, r *http.Request) {
	sch, ok := s.loadSchedule(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	if err := s.deps.Store.DeleteSchedule(sch.ID); err != nil {
		s.internalError(w, r, "delete schedule", err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": sch.ID})
}

func (s *Server) loadSchedule(w http.ResponseWriter, r *http.Request, id string) (model.Schedule, bool) {
	sch, err := s.deps.Store.GetSchedule(id)
	if errors.Is(err, store.ErrScheduleNotFound) {
		s.writeError(w, r, http.StatusNotFound, "schedule not found")
		return model.Schedule{}, false
	}
	if err != nil {
		s.internalError(w, r, "load schedule", err)
		return model.Schedule{}, false
	}
	return sch, true
}

func (s *Server) parseScheduleForm(form map[string][]string, uploadedTargets []string) (model.ScanOptions, int, string, error) {
	get := func(key string) string {
		if values := form[key]; len(values) > 0 {
			return values[0]
		}
		return ""
	}

	specs := mergeTargetSpecs(splitTargets(get("targets")), uploadedTargets)
	if len(specs) == 0 {
		return model.ScanOptions{}, 0, "", errors.New("targets is required")
	}
	for _, spec := range specs {
		if strings.HasPrefix(spec, "@") {
			return model.ScanOptions{}, 0, "", errors.New("target file specs are not accepted via the API")
		}
	}

	enableVuln := formBool(get("enable_vuln"))
	enableAuth := formBool(get("enable_auth"))
	enableScreens := formBool(get("enable_screens"))
	ack := formBool(get("ack_authorized"))
	if (enableAuth || enableScreens) && !ack {
		return model.ScanOptions{}, 0, "", errors.New("credential checks and screenshots require the authorization acknowledgement")
	}

	ports, err := target.ParsePorts(get("ports"))
	if err != nil {
		return model.ScanOptions{}, 0, "", err
	}
	concurrency, err := parseConcurrency(get("concurrency"))
	if err != nil {
		return model.ScanOptions{}, 0, "", err
	}
	rate, err := parseRate(get("rate"))
	if err != nil {
		return model.ScanOptions{}, 0, "", err
	}
	timeout, err := parseTimeout(get("timeout"))
	if err != nil {
		return model.ScanOptions{}, 0, "", err
	}
	maxAuthFailures, err := parseMaxAuthFailures(get("max_auth_failures"))
	if err != nil {
		return model.ScanOptions{}, 0, "", err
	}
	interval := int((24 * time.Hour).Seconds())
	if v := strings.TrimSpace(get("interval_seconds")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return model.ScanOptions{}, 0, "", errors.New("invalid interval_seconds")
		}
		interval = n
	}

	userWordlist := strings.TrimSpace(get("user_wordlist"))
	passwordWordlist := strings.TrimSpace(get("password_wordlist"))

	name := strings.TrimSpace(get("name"))
	if name == "" {
		name = "Schedule: " + scanName(specs, "")
	}
	if utf8.RuneCountInString(name) > 200 {
		return model.ScanOptions{}, 0, "", errors.New("name must be at most 200 characters")
	}

	opts := model.ScanOptions{
		Targets:          specs,
		Ports:            ports,
		TimeoutMS:        int(timeout / time.Millisecond),
		Concurrency:      concurrency,
		RatePerSecond:    rate,
		EnableVuln:       enableVuln,
		EnableAuth:       enableAuth,
		EnableScreens:    enableScreens,
		MaxAuthFailures:  maxAuthFailures,
		UserWordlist:     userWordlist,
		PasswordWordlist: passwordWordlist,
		Acknowledged:     ack,
	}
	if err := applyAuthOptions(&opts, get); err != nil {
		return model.ScanOptions{}, 0, "", err
	}
	if opts.EnableAuth && !ack {
		return model.ScanOptions{}, 0, "", errors.New("credential checks and screenshots require the authorization acknowledgement")
	}
	if opts.EnableAuth && opts.AuthMode == model.AuthModeWordlist {
		defaultUser, defaultPassword := s.wordlistDefaults()
		if opts.UserWordlist == "" {
			opts.UserWordlist = defaultUser
		}
		if opts.PasswordWordlist == "" {
			opts.PasswordWordlist = defaultPassword
		}
	}
	return opts, interval, name, nil
}

func validateScheduleInterval(seconds int) error {
	min := int(minScheduleInterval.Seconds())
	max := int(maxScheduleInterval.Seconds())
	if seconds < min || seconds > max {
		return errors.New("interval_seconds must be between " + strconv.Itoa(min) + " and " + strconv.Itoa(max))
	}
	return nil
}

// parseScheduleRunAt accepts RFC3339 / RFC3339Nano or a naive local datetime
// (YYYY-MM-DDTHH:MM[:SS]) from <input type="datetime-local">. Empty input
// returns (nil, nil). Past times more than one minute behind now are rejected.
func parseScheduleRunAt(raw string, now time.Time) (*time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		t, err = time.Parse(time.RFC3339, raw)
	}
	if err != nil {
		normalized := strings.ReplaceAll(raw, " ", "T")
		for _, layout := range []string{
			"2006-01-02T15:04:05",
			"2006-01-02T15:04",
		} {
			t, err = time.ParseInLocation(layout, normalized, time.Local)
			if err == nil {
				break
			}
		}
	}
	if err != nil {
		return nil, errors.New("run_at must be an RFC3339 timestamp or YYYY-MM-DDTHH:MM")
	}
	t = t.UTC()
	if t.Before(now.Add(-time.Minute)) {
		return nil, errors.New("run_at must be in the future")
	}
	return &t, nil
}
