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

// Input carries everything Evaluate needs for SLA-style post-scan checks.
type Input struct {
	Scan             model.Scan
	Summary          model.Summary
	Hosts            []model.Host
	PriorHosts       []model.Host
	Findings         []model.Finding
	HardeningScore   int
	CredReuseMax     int
}

// Evaluate decides which alert events to fire for a finished scan.
func Evaluate(rules model.AlertRules, in Input) []notify.Payload {
	if !rules.Enabled || strings.TrimSpace(rules.WebhookURL) == "" {
		return nil
	}
	var out []notify.Payload
	critical := in.Summary.CountBySeverity(model.SeverityCritical)
	high := in.Summary.CountBySeverity(model.SeverityHigh)
	now := time.Now().UTC()

	if rules.OnCritical && critical > 0 {
		out = append(out, notify.Payload{
			Event: "alert.critical", At: now, ScanID: in.Scan.ID, ScanName: in.Scan.Name,
			Status: string(in.Scan.Status), Summary: in.Summary, Critical: critical, High: high,
			Engagement: in.Scan.Engagement,
		})
	}
	if rules.OnHigh && high > 0 {
		out = append(out, notify.Payload{
			Event: "alert.high", At: now, ScanID: in.Scan.ID, ScanName: in.Scan.Name,
			Status: string(in.Scan.Status), Summary: in.Summary, Critical: critical, High: high,
			Engagement: in.Scan.Engagement,
			Detail:     fmt.Sprintf("%d high-severity finding(s)", high),
		})
	}
	if rules.OnNLARegressed && nlaRegressed(in.Hosts, in.PriorHosts) {
		out = append(out, notify.Payload{
			Event: "alert.nla_regressed", At: now, ScanID: in.Scan.ID, ScanName: in.Scan.Name,
			Status: string(in.Scan.Status), Engagement: in.Scan.Engagement,
		})
	}
	minReuse := rules.OnCredReuseMin
	if minReuse > 0 && in.CredReuseMax >= minReuse {
		out = append(out, notify.Payload{
			Event: "alert.cred_reuse", At: now, ScanID: in.Scan.ID, ScanName: in.Scan.Name,
			Status: string(in.Scan.Status), Engagement: in.Scan.Engagement,
			Detail: fmt.Sprintf("credential reused on %d hosts", in.CredReuseMax),
		})
	}
	if rules.MinHardeningScore > 0 && in.HardeningScore < rules.MinHardeningScore {
		out = append(out, notify.Payload{
			Event: "alert.hardening_sla", At: now, ScanID: in.Scan.ID, ScanName: in.Scan.Name,
			Status: string(in.Scan.Status), Engagement: in.Scan.Engagement,
			Detail: fmt.Sprintf("hardening score %d below SLA floor %d", in.HardeningScore, rules.MinHardeningScore),
		})
	}
	if rules.OnOpenTriageCritical {
		openCrit := 0
		for _, f := range in.Findings {
			if f.Severity != model.SeverityCritical {
				continue
			}
			if f.Status != model.FindingVulnerable && f.Status != model.FindingPotential {
				continue
			}
			triage := f.TriageStatus
			if triage == "" {
				triage = model.TriageOpen
			}
			if triage == model.TriageOpen || triage == model.TriageConfirmed {
				openCrit++
			}
		}
		if openCrit > 0 {
			out = append(out, notify.Payload{
				Event: "alert.open_triage_critical", At: now, ScanID: in.Scan.ID, ScanName: in.Scan.Name,
				Status: string(in.Scan.Status), Summary: in.Summary, Critical: critical,
				Engagement: in.Scan.Engagement,
				Detail:     fmt.Sprintf("%d critical finding(s) still open in triage", openCrit),
			})
		}
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
