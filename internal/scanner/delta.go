package scanner

import (
	"rdpshot/internal/model"
)

// FilterDeltaEndpoints keeps endpoints that are new/changed relative to the
// base scan hosts, or that still have open/confirmed triage findings.
func FilterDeltaEndpoints(all []model.Endpoint, baseHosts []model.Host, baseFindings []model.Finding) []model.Endpoint {
	baseByKey := map[string]model.Host{}
	for _, h := range baseHosts {
		baseByKey[h.Endpoint.Key()] = h
	}
	keep := map[string]bool{}
	for _, f := range baseFindings {
		triage := f.TriageStatus
		if triage == "" {
			triage = model.TriageOpen
		}
		if triage != model.TriageOpen && triage != model.TriageConfirmed {
			continue
		}
		if f.Status != model.FindingVulnerable && f.Status != model.FindingPotential {
			continue
		}
		keep[model.Endpoint{Address: f.Address, Port: f.Port}.Key()] = true
	}
	var out []model.Endpoint
	seen := map[string]bool{}
	for _, ep := range all {
		k := ep.Key()
		if seen[k] {
			continue
		}
		seen[k] = true
		prev, ok := baseByKey[k]
		if !ok {
			out = append(out, ep)
			continue
		}
		if keep[k] {
			out = append(out, ep)
			continue
		}
		// Changed posture: previously non-open now retested always; open hosts
		// without open findings are skipped for delta runs.
		if prev.State != "open" {
			out = append(out, ep)
		}
	}
	return out
}
