package store

import (
	"strconv"

	"rdpshot/internal/model"
)

// DiffScans compares the hosts and findings of two scans. against is treated
// as the newer audit: "added" means present only there.
func (s *Store) DiffScans(baseID, againstID string) (model.ScanDiff, error) {
	base, err := s.GetScan(baseID)
	if err != nil {
		return model.ScanDiff{}, err
	}
	against, err := s.GetScan(againstID)
	if err != nil {
		return model.ScanDiff{}, err
	}

	baseHosts, err := s.ListHosts(baseID)
	if err != nil {
		return model.ScanDiff{}, err
	}
	againstHosts, err := s.ListHosts(againstID)
	if err != nil {
		return model.ScanDiff{}, err
	}
	baseFindings, err := s.ListFindings(baseID)
	if err != nil {
		return model.ScanDiff{}, err
	}
	againstFindings, err := s.ListFindings(againstID)
	if err != nil {
		return model.ScanDiff{}, err
	}

	diff := model.ScanDiff{
		BaseID:      base.ID,
		AgainstID:   against.ID,
		BaseName:    base.Name,
		AgainstName: against.Name,
	}

	baseHostMap := map[string]model.Host{}
	for _, h := range baseHosts {
		baseHostMap[h.Endpoint.Key()] = h
	}
	againstHostMap := map[string]model.Host{}
	for _, h := range againstHosts {
		key := h.Endpoint.Key()
		againstHostMap[key] = h
		before, ok := baseHostMap[key]
		if !ok {
			diff.HostsAdded = append(diff.HostsAdded, h)
			continue
		}
		beforeSnap := hostSnap(before)
		afterSnap := hostSnap(h)
		if beforeSnap != afterSnap {
			diff.HostsChanged = append(diff.HostsChanged, model.HostChange{
				Address: h.Endpoint.Address,
				Port:    h.Endpoint.Port,
				Before:  beforeSnap,
				After:   afterSnap,
			})
		}
	}
	for key, h := range baseHostMap {
		if _, ok := againstHostMap[key]; !ok {
			diff.HostsRemoved = append(diff.HostsRemoved, h)
		}
	}

	baseFindingMap := map[string]model.Finding{}
	for _, f := range baseFindings {
		baseFindingMap[findingKey(f)] = f
	}
	againstFindingMap := map[string]model.Finding{}
	for _, f := range againstFindings {
		key := findingKey(f)
		againstFindingMap[key] = f
		before, ok := baseFindingMap[key]
		if !ok {
			diff.FindingsAdded = append(diff.FindingsAdded, f)
			continue
		}
		beforeSnap := findingSnap(before)
		afterSnap := findingSnap(f)
		if beforeSnap != afterSnap {
			diff.FindingsChanged = append(diff.FindingsChanged, model.FindingChange{
				Address: f.Address,
				Port:    f.Port,
				CheckID: f.CheckID,
				Title:   f.Title,
				Before:  beforeSnap,
				After:   afterSnap,
			})
		}
	}
	for key, f := range baseFindingMap {
		if _, ok := againstFindingMap[key]; !ok {
			diff.FindingsRemoved = append(diff.FindingsRemoved, f)
		}
	}

	diff.Summary = model.ScanDiffSummary{
		HostsAdded:      len(diff.HostsAdded),
		HostsRemoved:    len(diff.HostsRemoved),
		HostsChanged:    len(diff.HostsChanged),
		FindingsAdded:   len(diff.FindingsAdded),
		FindingsRemoved: len(diff.FindingsRemoved),
		FindingsChanged: len(diff.FindingsChanged),
	}
	return diff, nil
}

func findingKey(f model.Finding) string {
	return f.Address + ":" + strconv.Itoa(int(f.Port)) + "|" + f.CheckID
}

func hostSnap(h model.Host) model.HostSnap {
	snap := model.HostSnap{State: h.State}
	if h.Service != nil {
		snap.NLARequired = h.Service.NLARequired
		snap.TLSVersion = h.Service.TLSVersion
		snap.OSGuess = h.Service.OSGuess
		if h.Service.Certificate != nil {
			snap.SelfSigned = h.Service.Certificate.SelfSigned
		}
	}
	return snap
}

func findingSnap(f model.Finding) model.FindingSnap {
	return model.FindingSnap{
		Severity: f.Severity,
		Status:   f.Status,
		CVSS:     f.CVSS,
		CVE:      f.CVE,
	}
}
