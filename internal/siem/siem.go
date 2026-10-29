// Package siem formats and delivers scan events to SIEM HTTP collectors.
package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"rdpshot/internal/model"
)

// Format selects the wire encoding.
type Format string

const (
	FormatJSON Format = "json"
	FormatCEF  Format = "cef"
)

// Event is one outbound SIEM record.
type Event struct {
	Type       string    `json:"type"`
	At         time.Time `json:"at"`
	ScanID     string    `json:"scan_id,omitempty"`
	ScanName   string    `json:"scan_name,omitempty"`
	Engagement string    `json:"engagement,omitempty"`
	Severity   string    `json:"severity,omitempty"`
	CheckID    string    `json:"check_id,omitempty"`
	Host       string    `json:"host,omitempty"`
	Port       uint16    `json:"port,omitempty"`
	Message    string    `json:"message,omitempty"`
	Score      int       `json:"score,omitempty"`
}

// Deliver posts events to an HTTP collector.
func Deliver(ctx context.Context, url string, format Format, events []Event) error {
	url = strings.TrimSpace(url)
	if url == "" || len(events) == 0 {
		return nil
	}
	if format == "" {
		format = FormatJSON
	}
	var body []byte
	var contentType string
	switch format {
	case FormatCEF:
		var b strings.Builder
		for _, ev := range events {
			b.WriteString(toCEF(ev))
			b.WriteByte('\n')
		}
		body = []byte(b.String())
		contentType = "text/plain"
	default:
		var err error
		body, err = json.Marshal(events)
		if err != nil {
			return err
		}
		contentType = "application/json"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "rdpshot-siem/1")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("siem: status %d", resp.StatusCode)
	}
	return nil
}

// FromFinding builds a SIEM event for one finding.
func FromFinding(scan model.Scan, f model.Finding) Event {
	return Event{
		Type: "finding", At: f.DetectedAt, ScanID: scan.ID, ScanName: scan.Name,
		Engagement: scan.Engagement, Severity: string(f.Severity), CheckID: f.CheckID,
		Host: f.Address, Port: f.Port, Message: f.Title,
	}
}

// FromScanFinished builds a completion event.
func FromScanFinished(scan model.Scan, hardeningScore int) Event {
	return Event{
		Type: "scan.finished", At: time.Now().UTC(), ScanID: scan.ID, ScanName: scan.Name,
		Engagement: scan.Engagement, Message: string(scan.Status), Score: hardeningScore,
	}
}

func toCEF(ev Event) string {
	// CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
	sev := 3
	switch strings.ToLower(ev.Severity) {
	case "critical":
		sev = 10
	case "high":
		sev = 8
	case "medium":
		sev = 5
	case "low":
		sev = 3
	case "info":
		sev = 1
	}
	sig := ev.CheckID
	if sig == "" {
		sig = ev.Type
	}
	name := ev.Message
	if name == "" {
		name = ev.Type
	}
	ext := fmt.Sprintf("msg=%s cs1=%s cs1Label=scanId", escapeCEF(name), escapeCEF(ev.ScanID))
	if ev.Host != "" {
		ext += " dst=" + escapeCEF(ev.Host)
	}
	if ev.Port != 0 {
		ext += fmt.Sprintf(" dpt=%d", ev.Port)
	}
	return fmt.Sprintf("CEF:0|RDPShot|rdpshot|1|%s|%s|%d|%s",
		escapeCEF(sig), escapeCEF(name), sev, ext)
}

func escapeCEF(s string) string {
	r := strings.NewReplacer("\\", "\\\\", "=", "\\=", "\n", " ", "|", "\\|")
	return r.Replace(s)
}
