package notify

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"rdpshot/internal/model"
)

func TestDetectPlatform(t *testing.T) {
	cases := []struct {
		url  string
		want Platform
	}{
		{"https://hooks.slack.com/services/T00/B00/X00", PlatformSlack},
		{"https://discord.com/api/webhooks/123/abc", PlatformDiscord},
		{"https://discordapp.com/api/webhooks/456/def", PlatformDiscord},
		{"https://outlook.office.com/webhook/789/IncomingWebhook", PlatformTeams},
		{"https://prod-00.logic.azure.com/workflows/teams", PlatformTeams},
		{"https://api.example.com/alerts", PlatformGeneric},
	}
	for _, tc := range cases {
		got := DetectPlatform(tc.url)
		if got != tc.want {
			t.Errorf("DetectPlatform(%q) = %q, want %q", tc.url, got, tc.want)
		}
	}
}

func TestWebhookDelivery(t *testing.T) {
	var receivedBody string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	payload := Payload{
		Event:    "scan_finished",
		At:       time.Now().UTC(),
		ScanID:   "scan-001",
		ScanName: "Nightly Audit",
		Status:   "completed",
		Critical: 2,
		High:     3,
		Detail:   "Scan completed with 2 critical findings",
	}

	if err := Webhook(context.Background(), ts.URL, payload); err != nil {
		t.Fatalf("Webhook delivery failed: %v", err)
	}

	if !strings.Contains(receivedBody, "scan-001") {
		t.Errorf("received body missing scan-001: %s", receivedBody)
	}
	if !strings.Contains(receivedBody, "Nightly Audit") {
		t.Errorf("received body missing scan name: %s", receivedBody)
	}
}

func TestNotifyFinding(t *testing.T) {
	var receivedBody string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	finding := model.Finding{
		Address:  "192.168.1.100",
		Port:     3389,
		CheckID:  "bluekeep-cve-2019-0708",
		Title:    "BlueKeep Vulnerable (MS_T120)",
		Severity: model.SeverityCritical,
		Status:   model.FindingVulnerable,
	}

	if err := NotifyFinding(context.Background(), ts.URL, "scan-001", "Nightly", finding); err != nil {
		t.Fatalf("NotifyFinding failed: %v", err)
	}

	if !strings.Contains(receivedBody, "finding_alert") {
		t.Errorf("received body missing finding_alert: %s", receivedBody)
	}
	if !strings.Contains(receivedBody, "BlueKeep") {
		t.Errorf("received body missing BlueKeep: %s", receivedBody)
	}
}
