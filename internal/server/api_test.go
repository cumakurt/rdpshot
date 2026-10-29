package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"rdpshot/internal/events"
	"rdpshot/internal/model"
	"rdpshot/internal/scanner"
	"rdpshot/internal/store"
)

// testEnv wires a real store, hub and scan engine behind a test server.
type testEnv struct {
	server  *Server
	store   *store.Store
	hub     *events.Hub
	outputs string
	http    *httptest.Server
}

func newTestEnv(t *testing.T, cfg Config) *testEnv {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})

	hub := events.NewHub(0)
	t.Cleanup(hub.Close)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := scanner.New(scanner.Dependencies{Store: st, Hub: hub, Logger: logger})
	if cfg.OutputsDir == "" {
		cfg.OutputsDir = dir
	}
	srv, err := New(cfg, Dependencies{Store: st, Hub: hub, Engine: engine, Logger: logger})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &testEnv{server: srv, store: st, hub: hub, outputs: dir, http: ts}
}

// closedPort returns a loopback port that was just released, so connecting to
// it fails fast with "connection refused".
func closedPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatalf("release port: %v", err)
	}
	return port
}

func postForm(t *testing.T, url string, form url.Values) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post %s: %v", url, err)
	}
	return resp
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(body)
}

func get(t *testing.T, url string) *http.Response {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("get %s: %v", url, err)
	}
	return resp
}

// seededScan persists a scan record without starting the engine.
func seededScan(t *testing.T, st *store.Store, id string, status model.ScanStatus) model.Scan {
	t.Helper()
	scan := model.Scan{
		ID:        id,
		Name:      "seeded " + id,
		Status:    status,
		CreatedAt: time.Now().UTC(),
		Options: model.ScanOptions{
			Targets:     []string{"127.0.0.1"},
			Ports:       []uint16{3389},
			Concurrency: 4,
		},
	}
	if err := st.CreateScan(scan); err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	return scan
}

func TestCreateScanThenListAndDetail(t *testing.T) {
	env := newTestEnv(t, Config{})
	port := closedPort(t)

	resp := postForm(t, env.http.URL+"/api/v1/scans", url.Values{
		"targets":        {"127.0.0.1:" + strconv.Itoa(port)},
		"concurrency":    {"2"},
		"rate":           {"100"},
		"timeout":        {"200ms"},
		"enable_vuln":    {"true"},
		"ack_authorized": {"true"},
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create scan status = %d, body: %s", resp.StatusCode, readBody(t, resp))
	}
	var created scanCreated
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		resp.Body.Close()
		t.Fatalf("decode create response: %v", err)
	}
	resp.Body.Close()
	if !strings.HasPrefix(created.ID, "scan-") {
		t.Fatalf("scan id = %q, want scan- prefix", created.ID)
	}
	if created.URL != "/scans/"+created.ID {
		t.Fatalf("scan url = %q", created.URL)
	}

	listResp := get(t, env.http.URL+"/api/v1/scans")
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list scans status = %d", listResp.StatusCode)
	}
	var scans []model.Scan
	if err := json.NewDecoder(listResp.Body).Decode(&scans); err != nil {
		listResp.Body.Close()
		t.Fatalf("decode scan list: %v", err)
	}
	listResp.Body.Close()
	found := false
	for _, sc := range scans {
		if sc.ID == created.ID {
			found = true
			if sc.Options.Concurrency != 2 {
				t.Fatalf("stored concurrency = %d, want 2", sc.Options.Concurrency)
			}
		}
	}
	if !found {
		t.Fatalf("created scan %s missing from list: %+v", created.ID, scans)
	}

	detailResp := get(t, env.http.URL+"/api/v1/scans/"+created.ID)
	if detailResp.StatusCode != http.StatusOK {
		t.Fatalf("get scan status = %d", detailResp.StatusCode)
	}
	var detail model.Scan
	if err := json.NewDecoder(detailResp.Body).Decode(&detail); err != nil {
		detailResp.Body.Close()
		t.Fatalf("decode scan: %v", err)
	}
	detailResp.Body.Close()
	if detail.ID != created.ID {
		t.Fatalf("detail id = %q, want %q", detail.ID, created.ID)
	}
}

func TestCreateScanRequiresAuthorizationAck(t *testing.T) {
	env := newTestEnv(t, Config{})
	port := closedPort(t)

	for _, form := range []url.Values{
		{"targets": {"127.0.0.1:" + strconv.Itoa(port)}, "enable_auth": {"on"}},
		{"targets": {"127.0.0.1:" + strconv.Itoa(port)}, "enable_screens": {"on"}},
	} {
		resp := postForm(t, env.http.URL+"/api/v1/scans", form)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body: %s", resp.StatusCode, readBody(t, resp))
		}
		body := readBody(t, resp)
		if !strings.Contains(body, "credential checks and screenshots require the authorization acknowledgement") {
			t.Fatalf("error body = %s", body)
		}
	}
}

func TestCreateScanRequiresTargets(t *testing.T) {
	env := newTestEnv(t, Config{})
	resp := postForm(t, env.http.URL+"/api/v1/scans", url.Values{"ack_authorized": {"true"}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	body := readBody(t, resp)
	if !strings.Contains(body, "targets is required") {
		t.Fatalf("error body = %s", body)
	}
}

func TestReportCSV(t *testing.T) {
	env := newTestEnv(t, Config{})
	seededScan(t, env.store, "scan-csv0000000001", model.ScanCompleted)

	resp := get(t, env.http.URL+"/api/v1/scans/scan-csv0000000001/report?format=csv")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("report status = %d, body: %s", resp.StatusCode, readBody(t, resp))
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("content type = %q", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); cd != `attachment; filename="rdpshot-scan-csv0000000001.csv"` {
		t.Fatalf("content disposition = %q", cd)
	}
	body := readBody(t, resp)
	if !strings.Contains(body, "scan_id,address,port,check_id,title,severity,status,cve,cvss,detected_at,evidence,remediation") {
		t.Fatalf("csv header missing from body: %q", body)
	}

	for _, format := range []string{"html", "pdf"} {
		resp := get(t, env.http.URL+"/api/v1/scans/scan-csv0000000001/report?format="+format)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("report %s status = %d", format, resp.StatusCode)
		}
		if body := readBody(t, resp); len(body) == 0 {
			t.Fatalf("report %s body is empty", format)
		}
	}
}

func TestReportUnknownFormat(t *testing.T) {
	env := newTestEnv(t, Config{})
	seededScan(t, env.store, "scan-fmt00000000001", model.ScanCompleted)
	for _, format := range []string{"docx", "html; rm -rf /", ""} {
		resp := get(t, env.http.URL+"/api/v1/scans/scan-fmt00000000001/report?format="+url.QueryEscape(format))
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("format %q status = %d, want 400", format, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

func TestSummaryEndpoint(t *testing.T) {
	env := newTestEnv(t, Config{})
	seededScan(t, env.store, "scan-sum00000000001", model.ScanCompleted)

	resp := get(t, env.http.URL+"/api/v1/summary")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("summary status = %d", resp.StatusCode)
	}
	var summary model.Summary
	if err := json.NewDecoder(resp.Body).Decode(&summary); err != nil {
		resp.Body.Close()
		t.Fatalf("decode summary: %v", err)
	}
	resp.Body.Close()
	if summary.ScansTotal != 1 {
		t.Fatalf("scans total = %d, want 1", summary.ScansTotal)
	}
}

func TestTokenEnforcement(t *testing.T) {
	env := newTestEnv(t, Config{Token: "sekret-token"})

	resp := get(t, env.http.URL+"/api/v1/summary")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token status = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	req, err := http.NewRequest(http.MethodGet, env.http.URL+"/api/v1/summary", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		resp.Body.Close()
		t.Fatalf("wrong token status = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	req, err = http.NewRequest(http.MethodGet, env.http.URL+"/api/v1/summary", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer sekret-token")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bearer token status = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	resp = get(t, env.http.URL+"/api/v1/summary?token=sekret-token")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("query token status = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	resp = get(t, env.http.URL+"/")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("page without token status = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestSecurityHeaders(t *testing.T) {
	env := newTestEnv(t, Config{})
	resp := get(t, env.http.URL+"/api/v1/summary")
	defer resp.Body.Close()
	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	}
	for k, v := range want {
		if got := resp.Header.Get(k); got != v {
			t.Fatalf("header %s = %q, want %q", k, got, v)
		}
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
		t.Fatalf("csp = %q", csp)
	}
}

func TestCredentialSecretNeverExposed(t *testing.T) {
	env := newTestEnv(t, Config{})
	scan := seededScan(t, env.store, "scan-mask000000001", model.ScanCompleted)
	if _, err := env.store.InsertCredential(model.Credential{
		ScanID: scan.ID, HostID: 1, Address: "10.0.0.5", Port: 3389,
		Username: "admin", Secret: "hunter2", Domain: "CORP",
		Method: "ntlm", VerifiedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("insert credential: %v", err)
	}

	urls := []struct {
		path    string
		timeout time.Duration
	}{
		{"/api/v1/scans/" + scan.ID, 2 * time.Second},
		{"/api/v1/scans/" + scan.ID + "/credentials", 2 * time.Second},
		{"/api/v1/scans/" + scan.ID + "/findings", 2 * time.Second},
		{"/api/v1/scans/" + scan.ID + "/hosts", 2 * time.Second},
		{"/api/v1/scans/" + scan.ID + "/screenshots", 2 * time.Second},
		{"/api/v1/scans/" + scan.ID + "/report?format=csv", 2 * time.Second},
		{"/api/v1/scans/" + scan.ID + "/report?format=html", 2 * time.Second},
		{"/api/v1/scans/" + scan.ID + "/report?format=pdf", 2 * time.Second},
		{"/api/v1/summary", 2 * time.Second},
		// The event stream never ends; read only what it emits at once.
		{"/api/v1/events?scan=" + scan.ID, 250 * time.Millisecond},
		{"/scans/" + scan.ID, 2 * time.Second},
		{"/reports", 2 * time.Second},
		{"/gallery", 2 * time.Second},
		{"/", 2 * time.Second},
	}
	for _, u := range urls {
		body := fetchBoundedBody(t, env.http.URL+u.path, u.timeout)
		if strings.Contains(body, "hunter2") {
			t.Fatalf("response for %s leaked the credential secret", u.path)
		}
	}

	// The credential API must show the masked placeholder instead.
	resp := get(t, env.http.URL+"/api/v1/scans/"+scan.ID+"/credentials")
	body := readBody(t, resp)
	if !strings.Contains(body, "********") {
		t.Fatalf("credentials response does not mask the secret: %s", body)
	}
	var creds []model.Credential
	if err := json.Unmarshal([]byte(body), &creds); err != nil {
		t.Fatalf("decode credentials: %v", err)
	}
	if len(creds) != 1 || creds[0].Secret != "********" {
		t.Fatalf("credentials = %+v, want masked secret", creds)
	}
}

// fetchBoundedBody reads at most 512 KiB of a response, enough to detect a
// secret leak without buffering the SSE stream forever. A read that outlives
// the timeout returns what it has, which is the expected outcome for streams.
func fetchBoundedBody(t *testing.T, rawURL string, timeout time.Duration) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get %s: %v", rawURL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	if err != nil {
		t.Logf("bounded read of %s stopped early: %v", rawURL, err)
	}
	return string(body)
}

func TestCancelScan(t *testing.T) {
	env := newTestEnv(t, Config{})

	// Unknown id -> 404.
	resp := postForm(t, env.http.URL+"/api/v1/scans/scan-missing0000001/cancel", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown scan cancel status = %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()

	// Finished scan -> 409.
	seededScan(t, env.store, "scan-done00000000001", model.ScanCompleted)
	resp = postForm(t, env.http.URL+"/api/v1/scans/scan-done00000000001/cancel", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("finished scan cancel status = %d, want 409", resp.StatusCode)
	}
	resp.Body.Close()

	// Tracked running scan -> 202 and the run context is cancelled.
	seededScan(t, env.store, "scan-live00000000001", model.ScanRunning)
	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env.server.runsMu.Lock()
	env.server.runs["scan-live00000000001"] = &scanRun{cancel: cancel}
	env.server.runsMu.Unlock()

	resp = postForm(t, env.http.URL+"/api/v1/scans/scan-live00000000001/cancel", nil)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("live scan cancel status = %d, want 202; body: %s", resp.StatusCode, readBody(t, resp))
	}
	body := readBody(t, resp)
	if !strings.Contains(body, "cancelling") {
		t.Fatalf("cancel response = %s", body)
	}
	select {
	case <-runCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("cancel did not stop the scan run context")
	}
}

func TestUnknownScanReturns404(t *testing.T) {
	env := newTestEnv(t, Config{})
	for _, path := range []string{
		"/api/v1/scans/scan-nothing0000001",
		"/api/v1/scans/scan-nothing0000001/findings",
		"/api/v1/scans/scan-nothing0000001/hosts",
		"/api/v1/scans/scan-nothing0000001/screenshots",
		"/api/v1/scans/scan-nothing0000001/credentials",
		"/api/v1/scans/scan-nothing0000001/report?format=csv",
	} {
		resp := get(t, env.http.URL+path)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s status = %d, want 404", path, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

// TestListenAndServeGracefulShutdown boots the real listener and verifies a
// cancelled context shuts it down cleanly.
func TestListenAndServeGracefulShutdown(t *testing.T) {
	addr := "127.0.0.1:" + strconv.Itoa(closedPort(t))
	env := newTestEnv(t, Config{Addr: addr})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- env.server.ListenAndServe(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, err := http.Get("http://" + addr + "/api/v1/summary")
		if err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server never became reachable: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ListenAndServe returned %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAndServe did not shut down after context cancellation")
	}
}

func TestServesStaticAndScreenshotFiles(t *testing.T) {
	env := newTestEnv(t, Config{})
	if err := os.MkdirAll(filepath.Join(env.outputs, "screenshots"), 0o700); err != nil {
		t.Fatalf("create screenshot dir: %v", err)
	}
	image := filepath.Join(env.outputs, "screenshots", "shot.png")
	if err := os.WriteFile(image, []byte("png-bytes"), 0o600); err != nil {
		t.Fatalf("write image: %v", err)
	}

	resp := get(t, env.http.URL+"/static/css/app.css")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("static asset status = %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = get(t, env.http.URL+"/files/screenshots/shot.png")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("screenshot status = %d", resp.StatusCode)
	}
	if body := readBody(t, resp); body != "png-bytes" {
		t.Fatalf("screenshot body = %q", body)
	}

	// Traversal attempts must not escape the outputs directory.
	for _, path := range []string{
		"/files/../test.db",
		"/files/screenshots/../../test.db",
		"/files/%2e%2e/test.db",
	} {
		resp := get(t, env.http.URL+path)
		body := readBody(t, resp)
		if resp.StatusCode == http.StatusOK && strings.Contains(body, "CREATE TABLE") {
			t.Fatalf("path traversal %s served database content", path)
		}
	}
}

func TestRenameAndDeleteScan(t *testing.T) {
	env := newTestEnv(t, Config{})
	seededScan(t, env.store, "scan-rename000000001", model.ScanCompleted)

	req, err := http.NewRequest(http.MethodPatch, env.http.URL+"/api/v1/scans/scan-rename000000001",
		strings.NewReader(`{"name":"quarterly audit"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rename status = %d, body: %s", resp.StatusCode, readBody(t, resp))
	}
	var renamed model.Scan
	if err := json.NewDecoder(resp.Body).Decode(&renamed); err != nil {
		resp.Body.Close()
		t.Fatalf("decode rename: %v", err)
	}
	resp.Body.Close()
	if renamed.Name != "quarterly audit" {
		t.Fatalf("renamed name = %q", renamed.Name)
	}

	delReq, err := http.NewRequest(http.MethodDelete, env.http.URL+"/api/v1/scans/scan-rename000000001", nil)
	if err != nil {
		t.Fatalf("new delete: %v", err)
	}
	delResp, err := http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if delResp.StatusCode != http.StatusOK {
		t.Fatalf("delete status = %d, body: %s", delResp.StatusCode, readBody(t, delResp))
	}
	delResp.Body.Close()

	getResp := get(t, env.http.URL+"/api/v1/scans/scan-rename000000001")
	if getResp.StatusCode != http.StatusNotFound {
		t.Fatalf("get deleted status = %d, want 404", getResp.StatusCode)
	}
	getResp.Body.Close()
}

func TestDeleteActiveScan(t *testing.T) {
	env := newTestEnv(t, Config{})
	seededScan(t, env.store, "scan-delete-active0001", model.ScanPaused)

	cancelled := false
	env.server.runsMu.Lock()
	env.server.runs["scan-delete-active0001"] = &scanRun{
		cancel:  func() { cancelled = true },
		control: scanner.NewRunControl(nil),
	}
	env.server.runsMu.Unlock()

	delReq, err := http.NewRequest(http.MethodDelete, env.http.URL+"/api/v1/scans/scan-delete-active0001", nil)
	if err != nil {
		t.Fatalf("new delete: %v", err)
	}
	delResp, err := http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if delResp.StatusCode != http.StatusOK {
		t.Fatalf("delete status = %d, body: %s", delResp.StatusCode, readBody(t, delResp))
	}
	delResp.Body.Close()
	if !cancelled {
		t.Fatal("expected active run to be cancelled before delete")
	}
	if _, err := env.store.GetScan("scan-delete-active0001"); !errors.Is(err, store.ErrScanNotFound) {
		t.Fatalf("get deleted: %v", err)
	}
}

func TestPauseResumeScan(t *testing.T) {
	env := newTestEnv(t, Config{})
	seededScan(t, env.store, "scan-pause0000000001", model.ScanRunning)

	control := scanner.NewRunControl(func(status model.ScanStatus, progress model.Progress) {
		env.server.persistScanState("scan-pause0000000001", status, progress)
	})
	env.server.runsMu.Lock()
	env.server.runs["scan-pause0000000001"] = &scanRun{
		cancel:  func() {},
		control: control,
	}
	env.server.runsMu.Unlock()

	resp := postForm(t, env.http.URL+"/api/v1/scans/scan-pause0000000001/pause", nil)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("pause status = %d, body: %s", resp.StatusCode, readBody(t, resp))
	}
	resp.Body.Close()

	scan, err := env.store.GetScan("scan-pause0000000001")
	if err != nil {
		t.Fatalf("get after pause: %v", err)
	}
	if scan.Status != model.ScanPaused {
		t.Fatalf("status after pause = %q", scan.Status)
	}

	resp = postForm(t, env.http.URL+"/api/v1/scans/scan-pause0000000001/resume", nil)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("resume status = %d, body: %s", resp.StatusCode, readBody(t, resp))
	}
	resp.Body.Close()

	scan, err = env.store.GetScan("scan-pause0000000001")
	if err != nil {
		t.Fatalf("get after resume: %v", err)
	}
	if scan.Status != model.ScanRunning {
		t.Fatalf("status after resume = %q", scan.Status)
	}
}

func TestAnalyticsEndpoint(t *testing.T) {
	env := newTestEnv(t, Config{})
	resp := get(t, env.http.URL+"/api/v1/analytics")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("analytics status = %d", resp.StatusCode)
	}
	var a model.Analytics
	if err := json.NewDecoder(resp.Body).Decode(&a); err != nil {
		resp.Body.Close()
		t.Fatalf("decode analytics: %v", err)
	}
	resp.Body.Close()
}

func TestWordlistSettingsRoundTrip(t *testing.T) {
	env := newTestEnv(t, Config{})
	dir := t.TempDir()
	userPath := filepath.Join(dir, "users.txt")
	passPath := filepath.Join(dir, "passwords.txt")
	if err := os.WriteFile(userPath, []byte("admin\n"), 0o600); err != nil {
		t.Fatalf("write users: %v", err)
	}
	if err := os.WriteFile(passPath, []byte("Password1!\n"), 0o600); err != nil {
		t.Fatalf("write passwords: %v", err)
	}

	req, err := http.NewRequest(http.MethodPatch, env.http.URL+"/api/v1/settings/wordlists",
		strings.NewReader(`{"user_wordlist":`+strconv.Quote(userPath)+`,"password_wordlist":`+strconv.Quote(passPath)+`}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("patch status = %d, body: %s", resp.StatusCode, readBody(t, resp))
	}
	resp.Body.Close()

	getResp := get(t, env.http.URL+"/api/v1/settings/wordlists")
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("get status = %d", getResp.StatusCode)
	}
	var settings wordlistSettings
	if err := json.NewDecoder(getResp.Body).Decode(&settings); err != nil {
		getResp.Body.Close()
		t.Fatalf("decode: %v", err)
	}
	getResp.Body.Close()
	if settings.UserWordlist != userPath || settings.PasswordWordlist != passPath {
		t.Fatalf("settings = %+v", settings)
	}
}

func TestCreateScanAcceptsTargetsFile(t *testing.T) {
	env := newTestEnv(t, Config{OutputsDir: t.TempDir()})
	port := closedPort(t)

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	_ = writer.WriteField("ack_authorized", "true")
	_ = writer.WriteField("enable_vuln", "true")
	_ = writer.WriteField("concurrency", "2")
	_ = writer.WriteField("rate", "100")
	_ = writer.WriteField("timeout", "200ms")
	part, err := writer.CreateFormFile("targets_file", "targets.txt")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := part.Write([]byte("# comment\n127.0.0.1:" + strconv.Itoa(port) + "\n\n")); err != nil {
		t.Fatalf("write targets: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, env.http.URL+"/api/v1/scans", &body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, body: %s", resp.StatusCode, readBody(t, resp))
	}
	resp.Body.Close()
}
