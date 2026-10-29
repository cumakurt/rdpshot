// Package alerts evaluates operator-defined post-scan alert rules.
package alerts

import (
	"context"
	"fmt"
	"strings"
	"time"

	"rdpshot/internal/model"
	"rdpshot/internal/notify"
)

// Evaluate decides which alert events to fire for a finished scan.
func Evaluate(rules model.AlertRules, scan model.Scan, summary model.Summary, hosts []model.Host, priorHosts []model.Host, reuseMax int) []notify.Payload {
	if !rules.Enabled || strings.TrimSpace(rules.WebhookURL) == "" {
		return nil
	}
	var out []notify.Payload
	critical := summary.CountBySeverity(model.SeverityCritical)
	if rules.OnCritical && critical > 0 {
		out = append(out, notify.Payload{
			Event: "alert.critical", At: time.Now().UTC(), ScanID: scan.ID, ScanName: scan.Name,
			Status: string(scan.Status), Summary: summary, Critical: critical,
			Engagement: scan.Engagement,
		})
	}
	if rules.OnNLARegressed && nlaRegressed(hosts, priorHosts) {
		out = append(out, notify.Payload{
			Event: "alert.nla_regressed", At: time.Now().UTC(), ScanID: scan.ID, ScanName: scan.Name,
			Status: string(scan.Status), Engagement: scan.Engagement,
		})
	}
	minReuse := rules.OnCredReuseMin
	if minReuse > 0 && reuseMax >= minReuse {
		out = append(out, notify.Payload{
			Event: "alert.cred_reuse", At: time.Now().UTC(), ScanID: scan.ID, ScanName: scan.Name,
			Status: string(scan.Status), Engagement: scan.Engagement,
			Detail: fmt.Sprintf("credential reused on %d hosts", reuseMax),
		})
	}
	return out
}

// Deliver sends payloads to the rules webhook.
func Deliver(ctx context.Context, rules model.AlertRules, payloads []notify.Payload) error {
	var first error
	for _, p := range payloads {
		if err := notify.Webhook(ctx, rules.WebhookURL, p); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func nlaRegressed(current, prior []model.Host) bool {
	if len(prior) == 0 {
		return false
	}
	priorNLA := map[string]bool{}
	for _, h := range prior {
		if h.State != "open" || h.Service == nil {
			continue
		}
		priorNLA[h.Endpoint.Key()] = h.Service.NLARequired
	}
	for _, h := range current {
		if h.State != "open" || h.Service == nil {
			continue
		}
		was, ok := priorNLA[h.Endpoint.Key()]
		if ok && was && !h.Service.NLARequired {
			return true
		}
	}
	return false
}
