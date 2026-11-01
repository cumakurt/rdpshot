package server

import (
	"bytes"
	"context"
	"encoding/base64"
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

func TestCreateScanWebhookAndADOptions(t *testing.T) {
	env := newTestEnv(t, Config{
		WebhookURL:   "https://default-hook.example/alert",
		WebhookLevel: "high",
	})
	resp := postForm(t, env.http.URL+"/api/v1/scans", url.Values{
		"targets":        {"127.0.0.1:3389"},
		"ack_authorized": {"true"},
		"webhook_url":    {"https://soar.example/webhook"},
		"webhook_level":  {"critical"},
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", resp.StatusCode, readBody(t, resp))
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	sc, err := env.store.GetScan(created.ID)
	if err != nil {
		t.Fatalf("get scan: %v", err)
	}
	if sc.Options.WebhookURL != "https://soar.example/webhook" {
		t.Errorf("webhook_url = %q, want https://soar.example/webhook", sc.Options.WebhookURL)
	}
	if sc.Options.WebhookLevel != "critical" {
		t.Errorf("webhook_level = %q, want critical", sc.Options.WebhookLevel)
	}

	// Test fallback to server default when webhook_url not specified in scan form
	resp2 := postForm(t, env.http.URL+"/api/v1/scans", url.Values{
		"targets":        {"127.0.0.1:3389"},
		"ack_authorized": {"true"},
	})
	if resp2.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", resp2.StatusCode, readBody(t, resp2))
	}
	var created2 struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&created2); err != nil {
		t.Fatalf("decode: %v", err)
	}
	sc2, err := env.store.GetScan(created2.ID)
	if err != nil {
		t.Fatalf("get scan: %v", err)
	}
	if sc2.Options.WebhookURL != "https://default-hook.example/alert" {
		t.Errorf("fallback webhook_url = %q, want https://default-hook.example/alert", sc2.Options.WebhookURL)
	}
	if sc2.Options.WebhookLevel != "high" {
		t.Errorf("fallback webhook_level = %q, want high", sc2.Options.WebhookLevel)
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
	if !strings.Contains(body, "scan_id,address,port,check_id,title,severity,status,cve,cvss,detected_at,compliance,evidence,remediation") {
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

func TestReportsExportScanSelector(t *testing.T) {
	env := newTestEnv(t, Config{})
	scanA := seededScan(t, env.store, "scan-exp0000000000a", model.ScanCompleted)
	_ = seededScan(t, env.store, "scan-exp0000000000b", model.ScanCompleted)

	pngPath := filepath.Join(env.outputs, "shot-export.png")
	writeMinimalPNG(t, pngPath)
	if _, err := env.store.InsertScreenshot(model.Screenshot{
		ScanID:     scanA.ID,
		Address:    "10.0.0.9",
		Port:       3389,
		Username:   "rdp-login",
		FilePath:   pngPath,
		CapturedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("insert screenshot: %v", err)
	}

	resp := get(t, env.http.URL+"/api/v1/reports/export?format=csv&scan="+scanA.ID)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("single export status = %d, body: %s", resp.StatusCode, readBody(t, resp))
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, scanA.ID) {
		t.Fatalf("content disposition = %q", cd)
	}
	body := readBody(t, resp)
	if !strings.Contains(body, "SCREENSHOT") {
		t.Fatalf("csv export missing SCREENSHOT row: %q", body)
	}

	allResp := get(t, env.http.URL+"/api/v1/reports/export?format=html&scan=all")
	if allResp.StatusCode != http.StatusOK {
		t.Fatalf("all export status = %d, body: %s", allResp.StatusCode, readBody(t, allResp))
	}
	allBody := readBody(t, allResp)
	if !strings.Contains(allBody, "All scans") {
		t.Fatal("combined html missing all-scans title")
	}
	if !strings.Contains(allBody, `src="data:image/png;base64,`) {
		t.Fatal("combined html must embed screenshot bytes")
	}

	pdfResp := get(t, env.http.URL+"/api/v1/reports/export?format=pdf&scan=all")
	if pdfResp.StatusCode != http.StatusOK {
		t.Fatalf("pdf export status = %d", pdfResp.StatusCode)
	}
	pdfBody, err := io.ReadAll(pdfResp.Body)
	pdfResp.Body.Close()
	if err != nil {
		t.Fatalf("read pdf: %v", err)
	}
	if len(pdfBody) < 100 || !bytes.HasPrefix(pdfBody, []byte("%PDF")) {
		t.Fatalf("pdf export is not a PDF (%d bytes)", len(pdfBody))
	}
}

func TestComparePDFEndpoint(t *testing.T) {
	env := newTestEnv(t, Config{})
	scanA := model.Scan{
		ID:        "scan-cmp-0001",
		Name:      "Baseline Scan",
		Status:    model.ScanCompleted,
		CreatedAt: time.Now().Add(-2 * time.Hour),
		Options:   model.ScanOptions{Targets: []string{"10.0.0.1"}},
	}
	scanB := model.Scan{
		ID:        "scan-cmp-0002",
		Name:      "Remediated Scan",
		Status:    model.ScanCompleted,
		CreatedAt: time.Now().Add(-1 * time.Hour),
		Options:   model.ScanOptions{Targets: []string{"10.0.0.1"}},
	}
	if err := env.store.CreateScan(scanA); err != nil {
		t.Fatal(err)
	}
	if err := env.store.CreateScan(scanB); err != nil {
		t.Fatal(err)
	}

	// Missing parameters
	badResp := get(t, env.http.URL+"/api/v1/reports/compare-pdf")
	if badResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing params status = %d, want 400", badResp.StatusCode)
	}

	// Equal base and against
	eqResp := get(t, env.http.URL+"/api/v1/reports/compare-pdf?base="+scanA.ID+"&against="+scanA.ID)
	if eqResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("equal base and against status = %d, want 400", eqResp.StatusCode)
	}

	// Valid compare PDF
	resp := get(t, env.http.URL+"/api/v1/reports/compare-pdf?base="+scanA.ID+"&against="+scanB.ID)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("compare-pdf status = %d, body: %s", resp.StatusCode, readBody(t, resp))
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/pdf" {
		t.Errorf("content-type = %q, want application/pdf", ct)
	}
	pdfBody, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read compare-pdf: %v", err)
	}
	if !bytes.HasPrefix(pdfBody, []byte("%PDF")) {
		t.Errorf("response body does not have %%PDF prefix (%d bytes)", len(pdfBody))
	}
}

func writeMinimalPNG(t *testing.T, path string) {
	t.Helper()
	// 1x1 PNG
	const b64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO5W2/0AAAAASUVORK5CYII="
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode png: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write png: %v", err)
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

func postJSON(t *testing.T, url string, payload any) *http.Response {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post %s: %v", url, err)
	}
	return resp
}

func TestBulkDeleteScans(t *testing.T) {
	env := newTestEnv(t, Config{})
	seededScan(t, env.store, "scan-bulk0000000001", model.ScanCompleted)
	seededScan(t, env.store, "scan-bulk0000000002", model.ScanCompleted)
	seededScan(t, env.store, "scan-bulk0000000003", model.ScanCompleted)

	resp := postJSON(t, env.http.URL+"/api/v1/scans/bulk-delete", map[string]any{
		"ids": []string{"scan-bulk0000000001", "scan-bulk0000000003"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bulk delete status = %d, body: %s", resp.StatusCode, readBody(t, resp))
	}
	var result struct {
		Deleted []string           `json:"deleted"`
		Failed  []bulkDeleteResult `json:"failed"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		resp.Body.Close()
		t.Fatalf("decode bulk delete: %v", err)
	}
	resp.Body.Close()
	if len(result.Deleted) != 2 || len(result.Failed) != 0 {
		t.Fatalf("bulk delete result = %+v", result)
	}

	for _, id := range []string{"scan-bulk0000000001", "scan-bulk0000000003"} {
		if _, err := env.store.GetScan(id); !errors.Is(err, store.ErrScanNotFound) {
			t.Fatalf("scan %s still present: %v", id, err)
		}
	}
	if _, err := env.store.GetScan("scan-bulk0000000002"); err != nil {
		t.Fatalf("unselected scan was removed: %v", err)
	}
}

func TestBulkDeleteScansReportsPartialFailure(t *testing.T) {
	env := newTestEnv(t, Config{})
	seededScan(t, env.store, "scan-bulk0000000011", model.ScanCompleted)

	// Duplicate ids collapse, and an unknown id lands in "failed" without
	// aborting the scans that do exist.
	resp := postJSON(t, env.http.URL+"/api/v1/scans/bulk-delete", map[string]any{
		"ids": []string{"scan-bulk0000000011", "scan-bulk0000000011", "scan-missing00000001"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bulk delete status = %d, body: %s", resp.StatusCode, readBody(t, resp))
	}
	var result struct {
		Deleted []string           `json:"deleted"`
		Failed  []bulkDeleteResult `json:"failed"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		resp.Body.Close()
		t.Fatalf("decode bulk delete: %v", err)
	}
	resp.Body.Close()
	if len(result.Deleted) != 1 || len(result.Failed) != 1 {
		t.Fatalf("bulk delete result = %+v", result)
	}
	if result.Failed[0].ID != "scan-missing00000001" || result.Failed[0].Error != "scan not found" {
		t.Fatalf("unexpected failure entry: %+v", result.Failed[0])
	}
}

func TestBulkDeleteScansRejectsBadInput(t *testing.T) {
	env := newTestEnv(t, Config{})

	for name, payload := range map[string]any{
		"empty ids":   map[string]any{"ids": []string{}},
		"blank id":    map[string]any{"ids": []string{" "}},
		"missing key": map[string]any{},
	} {
		resp := postJSON(t, env.http.URL+"/api/v1/scans/bulk-delete", payload)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s status = %d, want 400", name, resp.StatusCode)
		}
		resp.Body.Close()
	}

	tooMany := make([]string, maxBulkDeleteScans+1)
	for i := range tooMany {
		tooMany[i] = "scan-bulk" + strconv.Itoa(i)
	}
	resp := postJSON(t, env.http.URL+"/api/v1/scans/bulk-delete", map[string]any{"ids": tooMany})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversized batch status = %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()
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

func TestCreateScanSingleCredAndPTHRedactsSecrets(t *testing.T) {
	env := newTestEnv(t, Config{})
	port := closedPort(t)
	ntHash := "a4f49c406510bdcab6824ee7c30fd852"

	cases := []struct {
		name string
		form url.Values
		mode string
	}{
		{
			name: "single",
			form: url.Values{
				"targets":        {"127.0.0.1:" + strconv.Itoa(port)},
				"concurrency":    {"1"},
				"rate":           {"100"},
				"timeout":        {"200ms"},
				"enable_auth":    {"true"},
				"ack_authorized": {"true"},
				"auth_mode":      {"single"},
				"auth_username":  {"alice"},
				"auth_domain":    {"CORP"},
				"auth_password":  {"SecretPass!"},
			},
			mode: model.AuthModeSingle,
		},
		{
			name: "pth",
			form: url.Values{
				"targets":        {"127.0.0.1:" + strconv.Itoa(port)},
				"concurrency":    {"1"},
				"rate":           {"100"},
				"timeout":        {"200ms"},
				"enable_auth":    {"true"},
				"ack_authorized": {"true"},
				"auth_mode":      {"pth"},
				"auth_username":  {"bob"},
				"auth_nthash":    {ntHash},
			},
			mode: model.AuthModePTH,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := postForm(t, env.http.URL+"/api/v1/scans", tc.form)
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("create status = %d, body: %s", resp.StatusCode, readBody(t, resp))
			}
			var created scanCreated
			if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
				resp.Body.Close()
				t.Fatalf("decode create: %v", err)
			}
			resp.Body.Close()

			stored, err := env.store.GetScan(created.ID)
			if err != nil {
				t.Fatalf("store get: %v", err)
			}
			if stored.Options.AuthMode != tc.mode {
				t.Fatalf("stored auth_mode = %q, want %q", stored.Options.AuthMode, tc.mode)
			}
			if stored.Options.EnableScreens {
				t.Fatal("single/pth must not force EnableScreens; form omitted enable_screens")
			}
			if !stored.Options.EnableAuth {
				t.Fatal("single/pth must force EnableAuth")
			}
			if tc.mode == model.AuthModeSingle && stored.Options.AuthPassword == "" {
				t.Fatal("store must retain auth_password for the scan engine")
			}
			if tc.mode == model.AuthModePTH && stored.Options.AuthNTHash != ntHash {
				t.Fatalf("stored nthash = %q, want %q", stored.Options.AuthNTHash, ntHash)
			}

			detailResp := get(t, env.http.URL+"/api/v1/scans/"+created.ID)
			if detailResp.StatusCode != http.StatusOK {
				t.Fatalf("get status = %d", detailResp.StatusCode)
			}
			var detail model.Scan
			if err := json.NewDecoder(detailResp.Body).Decode(&detail); err != nil {
				detailResp.Body.Close()
				t.Fatalf("decode detail: %v", err)
			}
			detailResp.Body.Close()
			if detail.Options.AuthPassword != "" {
				t.Fatalf("API leaked auth_password: %q", detail.Options.AuthPassword)
			}
			if detail.Options.AuthNTHash != "" {
				t.Fatalf("API leaked auth_nthash: %q", detail.Options.AuthNTHash)
			}
			if detail.Options.AuthMode != tc.mode {
				t.Fatalf("detail auth_mode = %q", detail.Options.AuthMode)
			}
			if detail.Options.AuthUsername == "" {
				t.Fatal("username should remain visible after redaction")
			}
		})
	}
}

func TestCreateScanRejectsInvalidAuthMode(t *testing.T) {
	env := newTestEnv(t, Config{})
	port := closedPort(t)
	resp := postForm(t, env.http.URL+"/api/v1/scans", url.Values{
		"targets":        {"127.0.0.1:" + strconv.Itoa(port)},
		"enable_auth":    {"true"},
		"ack_authorized": {"true"},
		"auth_mode":      {"spray"},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", resp.StatusCode, readBody(t, resp))
	}
	body := readBody(t, resp)
	if !strings.Contains(body, "auth_mode") {
		t.Fatalf("error body = %s", body)
	}
}

func TestCreateScanWithNmapXMLUpload(t *testing.T) {
	env := newTestEnv(t, Config{})
	xmlData := `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <status state="up"/>
    <address addr="10.42.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="3389"><state state="open"/></port>
    </ports>
  </host>
</nmaprun>`

	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	_ = w.WriteField("name", "nmap-import-test")
	part, _ := w.CreateFormFile("targets_file", "nmap.xml")
	_, _ = part.Write([]byte(xmlData))
	_ = w.Close()

	req, _ := http.NewRequest(http.MethodPost, env.http.URL+"/api/v1/scans", &body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 201/202/200; body: %s", resp.StatusCode, readBody(t, resp))
	}
	var created scanCreated
	_ = json.NewDecoder(resp.Body).Decode(&created)
	scan, err := env.store.GetScan(created.ID)
	if err != nil {
		t.Fatalf("GetScan: %v", err)
	}
	if len(scan.Options.Targets) != 1 || scan.Options.Targets[0] != "10.42.0.1:3389" {
		t.Fatalf("scan targets = %v, want [10.42.0.1:3389]", scan.Options.Targets)
	}
}

func TestDownloadRDPConfig(t *testing.T) {
	env := newTestEnv(t, Config{})

	// Missing address -> 400
	resp := get(t, env.http.URL+"/api/v1/hosts/connect.rdp")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}

	// Valid address, port, user
	resp = get(t, env.http.URL+"/api/v1/hosts/connect.rdp?address=172.16.3.128&port=3389&user=cmk&domain=CORP")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/x-rdp" {
		t.Fatalf("content-type = %s, want application/x-rdp", ct)
	}
	body := readBody(t, resp)
	if !strings.Contains(body, "full address:s:172.16.3.128:3389") {
		t.Fatalf("body missing full address: %s", body)
	}
	if !strings.Contains(body, "username:s:CORP\\cmk") {
		t.Fatalf("body missing username: %s", body)
	}
	if !strings.Contains(body, "enablecredsspsupport:i:1") {
		t.Fatalf("body missing enablecredsspsupport: %s", body)
	}
}

func TestPlaybookScriptAPI(t *testing.T) {
	env := newTestEnv(t, Config{})

	// 404 for unknown check
	resp := get(t, env.http.URL+"/api/v1/playbooks/unknown-check-id/script")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}

	// JSON format (all scripts)
	resp = get(t, env.http.URL+"/api/v1/playbooks/nla-not-required/script")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body := readBody(t, resp)
	if !strings.Contains(body, "powershell") || !strings.Contains(body, "UserAuthentication") {
		t.Fatalf("unexpected body: %s", body)
	}

	// PowerShell format plain text
	resp = get(t, env.http.URL+"/api/v1/playbooks/nla-not-required/script?format=powershell")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body = readBody(t, resp)
	if !strings.Contains(body, "UserAuthentication") {
		t.Fatalf("powershell body missing UserAuthentication: %s", body)
	}

	// Ansible format
	resp = get(t, env.http.URL+"/api/v1/playbooks/nla-not-required/script?format=ansible")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body = readBody(t, resp)
	if !strings.Contains(body, "ansible.windows.win_regedit") {
		t.Fatalf("ansible body missing win_regedit: %s", body)
	}
}

func TestCompliancePostureAPI(t *testing.T) {
	env := newTestEnv(t, Config{})

	// "all" scans posture
	resp := get(t, env.http.URL+"/api/v1/scans/all/compliance-posture")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body := readBody(t, resp)
	if !strings.Contains(body, "CIS") || !strings.Contains(body, "PCI-DSS") || !strings.Contains(body, "overall_score") {
		t.Fatalf("unexpected body: %s", body)
	}
}

func TestBlastRadiusAPI(t *testing.T) {
	env := newTestEnv(t, Config{})

	resp := get(t, env.http.URL+"/api/v1/estate/blast-radius")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body := readBody(t, resp)
	if !strings.Contains(body, "nodes") || !strings.Contains(body, "edges") {
		t.Fatalf("unexpected body: %s", body)
	}
}

func TestInspectScreenshotAPI(t *testing.T) {
	env := newTestEnv(t, Config{})

	// 404 for unknown screenshot
	resp := get(t, env.http.URL+"/api/v1/screenshots/99999/inspect")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}

	// Insert test screenshot into store
	shotID, err := env.store.InsertScreenshot(model.Screenshot{
		ScanID:     "s1",
		HostID:     1,
		Address:    "172.16.3.128",
		Port:       3389,
		Username:   "Administrator",
		FilePath:   "/outputs/screenshots/172.16.3.128_3389_admin.png",
		Width:      1280,
		Height:     800,
		CapturedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("insert screenshot: %v", err)
	}

	resp = get(t, env.http.URL+"/api/v1/screenshots/"+strconv.FormatInt(shotID, 10)+"/inspect")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body := readBody(t, resp)
	if !strings.Contains(body, "is_sensitive") || !strings.Contains(body, "bounding_boxes") || !strings.Contains(body, "keywords") {
		t.Fatalf("unexpected inspect body: %s", body)
	}
}
