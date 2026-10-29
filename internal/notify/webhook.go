// Package notify delivers outbound scan notifications to operator webhooks.
package notify

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

// Payload is the JSON body posted to schedule webhooks.
type Payload struct {
	Event      string         `json:"event"`
	At         time.Time      `json:"at"`
	ScheduleID string         `json:"schedule_id,omitempty"`
	ScanID     string         `json:"scan_id"`
	ScanName   string         `json:"scan_name"`
	Status     string         `json:"status"`
	Summary    model.Summary  `json:"summary"`
	Critical   int64          `json:"critical"`
	High       int64          `json:"high"`
	Engagement string         `json:"engagement,omitempty"`
	Detail     string         `json:"detail,omitempty"`
}

// Webhook posts a JSON notification with a bounded timeout.
func Webhook(ctx context.Context, url string, payload Payload) error {
	url = strings.TrimSpace(url)
	if url == "" {
		return fmt.Errorf("notify: webhook URL is empty")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("notify: encode payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("notify: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "rdpshot-notify/1")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("notify: post webhook: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("notify: webhook status %d", resp.StatusCode)
	}
	return nil
}
