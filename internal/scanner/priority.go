package scanner

import (
	"sort"

	"rdpshot/internal/model"
)

// hostAuthPriority ranks an open host for credential-audit ordering.
// Higher values are audited sooner (NLA off, weak TLS, critical findings).
func hostAuthPriority(h model.Host, findings []model.Finding) int {
	score := 0
	if h.Service != nil {
		if !h.Service.NLARequired {
			score += 100
		}
		switch h.Service.TLSVersion {
		case "SSL 3.0", "TLS 1.0", "TLS 1.1":
			score += 40
		}
		if h.Service.Certificate != nil && h.Service.Certificate.SelfSigned {
			score += 15
		}
	}
	for _, f := range findings {
		if f.Status != model.FindingVulnerable && f.Status != model.FindingPotential {
			continue
		}
		switch f.Severity {
		case model.SeverityCritical:
			score += 80
		case model.SeverityHigh:
			score += 40
		case model.SeverityMedium:
			score += 15
		}
	}
	return score
}

// PrioritizeEndpoints orders endpoints so previously high-risk hosts are
// audited earlier. Unknown hosts keep relative order after known ones.
func PrioritizeEndpoints(endpoints []model.Endpoint, priorHosts []model.Host, priorFindings []model.Finding) {
	findingsByHost := map[string][]model.Finding{}
	for _, f := range priorFindings {
		k := model.Endpoint{Address: f.Address, Port: f.Port}.Key()
		findingsByHost[k] = append(findingsByHost[k], f)
	}
	hostByKey := map[string]model.Host{}
	for _, h := range priorHosts {
		hostByKey[h.Endpoint.Key()] = h
	}
	type ranked struct {
		ep    model.Endpoint
		score int
		idx   int
	}
	items := make([]ranked, len(endpoints))
	for i, ep := range endpoints {
		score := 0
		if h, ok := hostByKey[ep.Key()]; ok {
			score = hostAuthPriority(h, findingsByHost[ep.Key()])
		}
		items[i] = ranked{ep: ep, score: score, idx: i}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].score != items[j].score {
			return items[i].score > items[j].score
		}
		return items[i].idx < items[j].idx
	})
	for i, it := range items {
		endpoints[i] = it.ep
	}
}

// mergeReuseCredentials prepends previously verified credentials so reuse is
// attempted before wordlist candidates. Duplicates are skipped.
func mergeReuseCredentials(prior, candidates []model.Credential) []model.Credential {
	if len(prior) == 0 {
		return candidates
	}
	seen := map[string]bool{}
	key := func(c model.Credential) string {
		return c.Domain + "\x00" + c.Username + "\x00" + c.Secret
	}
	out := make([]model.Credential, 0, len(prior)+len(candidates))
	for _, c := range prior {
		k := key(c)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, model.Credential{
			Domain: c.Domain, Username: c.Username, Secret: c.Secret, Method: c.Method,
		})
	}
	for _, c := range candidates {
		k := key(c)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, c)
	}
	return out
}
