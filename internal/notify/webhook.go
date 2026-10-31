// Package notify delivers outbound scan notifications to operator webhooks
// supporting Slack, Microsoft Teams, Discord, and generic JSON endpoints.
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

// Platform identifies the destination webhook service.
type Platform string

const (
	PlatformGeneric Platform = "generic"
	PlatformSlack   Platform = "slack"
	PlatformDiscord Platform = "discord"
	PlatformTeams   Platform = "teams"
)

// DetectPlatform determines the webhook platform based on the endpoint URL.
func DetectPlatform(url string) Platform {
	lower := strings.ToLower(url)
	switch {
	case strings.Contains(lower, "hooks.slack.com"):
		return PlatformSlack
	case strings.Contains(lower, "discord.com/api/webhooks") || strings.Contains(lower, "discordapp.com/api/webhooks"):
		return PlatformDiscord
	case strings.Contains(lower, "webhook.office.com") || strings.Contains(lower, "outlook.office.com") || strings.Contains(lower, "logic.azure.com"):
		return PlatformTeams
	default:
		return PlatformGeneric
	}
}

// Payload is the notification message body for scan lifecycles and alerts.
type Payload struct {
	Event      string        `json:"event"`
	At         time.Time     `json:"at"`
	ScheduleID string        `json:"schedule_id,omitempty"`
	ScanID     string        `json:"scan_id"`
	ScanName   string        `json:"scan_name"`
	Status     string        `json:"status"`
	Summary    model.Summary `json:"summary"`
	Critical   int64         `json:"critical"`
	High       int64         `json:"high"`
	Engagement string        `json:"engagement,omitempty"`
	Detail     string        `json:"detail,omitempty"`
}

// Webhook posts a notification to the specified URL, formatting it appropriately
// for Slack, Discord, MS Teams, or standard JSON.
func Webhook(ctx context.Context, url string, payload Payload) error {
	url = strings.TrimSpace(url)
	if url == "" {
		return fmt.Errorf("notify: webhook URL is empty")
	}

	platform := DetectPlatform(url)
	body, err := formatMessage(platform, payload)
	if err != nil {
		return fmt.Errorf("notify: format message: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("notify: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "rdpshot-notify/2")

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

// NotifyFinding sends an instant alert for a high-priority finding.
func NotifyFinding(ctx context.Context, url string, scanID, scanName string, f model.Finding) error {
	p := Payload{
		Event:    "finding_alert",
		At:       time.Now().UTC(),
		ScanID:   scanID,
		ScanName: scanName,
		Status:   string(f.Severity),
		Detail:   fmt.Sprintf("[%s] %s on %s:%d (%s)", f.Severity, f.Title, f.Address, f.Port, f.Status),
	}
	if f.Severity == model.SeverityCritical {
		p.Critical = 1
	} else if f.Severity == model.SeverityHigh {
		p.High = 1
	}
	return Webhook(ctx, url, p)
}

func formatMessage(platform Platform, p Payload) ([]byte, error) {
	switch platform {
	case PlatformSlack:
		color := "#10b981" // emerald
		if p.Critical > 0 {
			color = "#e11d48" // rose
		} else if p.High > 0 {
			color = "#f97316" // amber
		}
		title := fmt.Sprintf("*RDPShot Audit Event: %s*", p.Event)
		text := fmt.Sprintf("Scan: *%s* (`%s`)\nStatus: %s\nCritical: *%d* | High: *%d*\nDetail: %s",
			p.ScanName, p.ScanID, p.Status, p.Critical, p.High, p.Detail)

		slackPayload := map[string]any{
			"text": title,
			"attachments": []map[string]any{
				{
					"color": color,
					"text":  text,
					"ts":    p.At.Unix(),
				},
			},
		}
		return json.Marshal(slackPayload)

	case PlatformDiscord:
		color := 0x10b981
		if p.Critical > 0 {
			color = 0xe11d48
		} else if p.High > 0 {
			color = 0xf97316
		}
		discordPayload := map[string]any{
			"content": fmt.Sprintf("**[RDPShot] %s**", p.Event),
			"embeds": []map[string]any{
				{
					"title":       p.ScanName,
					"description": p.Detail,
					"color":       color,
					"fields": []map[string]any{
						{"name": "Scan ID", "value": p.ScanID, "inline": true},
						{"name": "Status", "value": p.Status, "inline": true},
						{"name": "Critical / High", "value": fmt.Sprintf("%d / %d", p.Critical, p.High), "inline": true},
					},
					"timestamp": p.At.Format(time.RFC3339),
				},
			},
		}
		return json.Marshal(discordPayload)

	case PlatformTeams:
		themeColor := "10b981"
		if p.Critical > 0 {
			themeColor = "e11d48"
		} else if p.High > 0 {
			themeColor = "f97316"
		}
		teamsPayload := map[string]any{
			"@type":      "MessageCard",
			"@context":   "https://schema.org/extensions",
			"themeColor": themeColor,
			"title":      fmt.Sprintf("RDPShot: %s (%s)", p.ScanName, p.Event),
			"text":       p.Detail,
			"sections": []map[string]any{
				{
					"facts": []map[string]string{
						{"name": "Scan ID", "value": p.ScanID},
						{"name": "Status", "value": p.Status},
						{"name": "Critical Findings", "value": fmt.Sprintf("%d", p.Critical)},
						{"name": "High Findings", "value": fmt.Sprintf("%d", p.High)},
					},
				},
			},
		}
		return json.Marshal(teamsPayload)

	default:
		return json.Marshal(p)
	}
}
