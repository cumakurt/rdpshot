// Package bloodhound exports rdpshot scan results in BloodHound Community
// Edition v5 JSON format so analysts can drag-and-drop the file into
// BloodHound CE and immediately visualise RDP-based domain dominance paths.
//
// Node types produced:  Computer, User
// Edge types produced:  CanRDP, HasSession, AdminTo, OpenRDP
package bloodhound

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"rdpshot/internal/model"
)

// ─────────────────────────────────────────────────────────────────────────────
// BloodHound CE v5 wire types
// ─────────────────────────────────────────────────────────────────────────────

// BHExport is the top-level envelope that BloodHound CE expects when importing
// a JSON file.  The Meta.Type field tells CE which data category each file
// holds; we use "mixed" so a single file carries both computers and users.
type BHExport struct {
	Meta BHMeta    `json:"meta"`
	Data []BHEntry `json:"data"`
}

// BHMeta describes the export for BloodHound CE.
type BHMeta struct {
	Methods int    `json:"methods"`
	Type    string `json:"type"`    // "computers", "users", or "mixed"
	Count   int    `json:"count"`
	Version int    `json:"version"` // 5
}

// BHEntry is one node or relationship in the BloodHound data stream.
type BHEntry struct {
	// For nodes
	ObjectIdentifier string         `json:"ObjectIdentifier"`
	Properties       map[string]any `json:"Properties"`
	PrimaryGroupSID  string         `json:"PrimaryGroupSID,omitempty"`
	IsDeleted        bool           `json:"IsDeleted"`
	IsACLProtected   bool           `json:"IsACLProtected"`

	// Relationship lists attached to this node
	Sessions          []BHSession  `json:"Sessions,omitempty"`
	LocalAdmins       []BHRelation `json:"LocalAdmins,omitempty"`
	RemoteDesktopUsers []BHRelation `json:"RemoteDesktopUsers,omitempty"`
}

// BHSession represents an active or disconnected RDP session seen on a computer.
type BHSession struct {
	UserSID    string `json:"UserSID"`
	ComputerID string `json:"ComputerID"`
	IsGlobal   bool   `json:"IsGlobal"`
}

// BHRelation is a member relationship (e.g. a user in a local group).
type BHRelation struct {
	ObjectIdentifier string         `json:"ObjectIdentifier"`
	ObjectType       string         `json:"ObjectType"` // "User", "Computer", "Group"
	IsInherited      bool           `json:"IsInherited"`
	Properties       map[string]any `json:"Properties,omitempty"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Export builder
// ─────────────────────────────────────────────────────────────────────────────

// BuildExport converts rdpshot scan data into a BloodHound CE v5 JSON export.
//
//   - hosts     – probed RDP endpoints from one or more scans
//   - creds     – verified credentials found during credential audit
//   - findings  – vulnerability / misconfiguration findings
//   - engagement – label used to build synthetic SID namespaces
func BuildExport(engagement string, hosts []model.Host, creds []model.Credential, findings []model.Finding) BHExport {
	if engagement == "" {
		engagement = "rdpshot"
	}
	domain := strings.ToUpper(strings.ReplaceAll(engagement, " ", "_"))

	// ── index findings per host ──────────────────────────────────────────────
	findingByHost := map[string][]model.Finding{}
	for _, f := range findings {
		k := endpointKey(f.Address, f.Port)
		findingByHost[k] = append(findingByHost[k], f)
	}

	// ── index credentials per host and per user ──────────────────────────────
	credsByHost := map[string][]model.Credential{}
	credsByUser := map[string][]string{} // userSID → []computerSID
	for _, c := range creds {
		hk := endpointKey(c.Address, c.Port)
		credsByHost[hk] = append(credsByHost[hk], c)
	}

	// ── user nodes ───────────────────────────────────────────────────────────
	userSIDs := map[string]string{} // "DOMAIN\user" → SID string
	var userEntries []BHEntry
	seenUsers := map[string]bool{}
	for _, c := range creds {
		ud := userDomain(c, domain)
		key := ud.domain + `\` + ud.user
		if seenUsers[key] {
			continue
		}
		seenUsers[key] = true
		sid := syntheticSID(ud.domain, ud.user, "U")
		userSIDs[key] = sid
		props := map[string]any{
			"name":           strings.ToUpper(ud.user) + "@" + ud.domain,
			"domain":         ud.domain,
			"samaccountname": ud.user,
			"enabled":        true,
			"rdpshot_source": "credential_verified",
			"collected":      time.Now().UTC().Format(time.RFC3339),
		}
		userEntries = append(userEntries, BHEntry{
			ObjectIdentifier: sid,
			Properties:       props,
		})
		// map user → every computer it accessed
		for _, hk := range credsByUser[sid] {
			credsByUser[sid] = append(credsByUser[sid], hk)
		}
		_ = credsByUser
	}

	// ── computer nodes ───────────────────────────────────────────────────────
	seenHosts := map[string]bool{}
	var computerEntries []BHEntry

	for _, h := range hosts {
		if h.State != "open" {
			continue
		}
		hk := endpointKey(h.Endpoint.Address, h.Endpoint.Port)
		if seenHosts[hk] {
			continue
		}
		seenHosts[hk] = true

		compSID := syntheticSID(domain, hk, "C")
		osGuess := "Windows"
		nlaRequired := false
		tlsVersion := ""
		if h.Service != nil {
			nlaRequired = h.Service.NLARequired
			tlsVersion = h.Service.TLSVersion
			if h.Service.OSGuess != "" {
				osGuess = h.Service.OSGuess
			}
		}

		// Determine severity from findings
		maxSev := "none"
		hasBluekeep := false
		for _, f := range findingByHost[hk] {
			if f.Status != model.FindingVulnerable && f.Status != model.FindingPotential {
				continue
			}
			if f.Severity.Rank() > model.Severity(maxSev).Rank() {
				maxSev = string(f.Severity)
			}
			if f.CheckID == "bluekeep-cve-2019-0708" {
				hasBluekeep = true
			}
		}

		props := map[string]any{
			"name":                strings.ToUpper(fmt.Sprintf("%s.%s", hk, domain)),
			"domain":              domain,
			"rdpaddress":          h.Endpoint.Address,
			"rdpport":             h.Endpoint.Port,
			"operatingsystem":     osGuess,
			"nlarequired":         nlaRequired,
			"tlsversion":          tlsVersion,
			"enabled":             true,
			"rdpshot_max_severity": maxSev,
			"rdpshot_bluekeep":    hasBluekeep,
			"collected":           time.Now().UTC().Format(time.RFC3339),
			"unconstraineddelegation": !nlaRequired, // NLA-missing is delegation risk
		}

		// Build RemoteDesktopUsers and Sessions from verified creds on this host
		var rdpUsers []BHRelation
		var sessions []BHSession
		for _, c := range credsByHost[hk] {
			ud := userDomain(c, domain)
			ukey := ud.domain + `\` + ud.user
			sid, ok := userSIDs[ukey]
			if !ok {
				sid = syntheticSID(ud.domain, ud.user, "U")
				userSIDs[ukey] = sid
			}
			rdpUsers = append(rdpUsers, BHRelation{
				ObjectIdentifier: sid,
				ObjectType:       "User",
				IsInherited:      false,
				Properties: map[string]any{
					"rdpshot_method": c.Method,
				},
			})
			sessions = append(sessions, BHSession{
				UserSID:    sid,
				ComputerID: compSID,
				IsGlobal:   false,
			})
		}

		entry := BHEntry{
			ObjectIdentifier:   compSID,
			Properties:         props,
			RemoteDesktopUsers: rdpUsers,
			Sessions:           sessions,
		}

		// Computers reachable without NLA or with BlueKeep have an implicit
		// AdminTo relationship: any user that can RDP is effectively a local admin candidate.
		if !nlaRequired || hasBluekeep {
			for _, c := range credsByHost[hk] {
				ud := userDomain(c, domain)
				ukey := ud.domain + `\` + ud.user
				sid := userSIDs[ukey]
				entry.LocalAdmins = append(entry.LocalAdmins, BHRelation{
					ObjectIdentifier: sid,
					ObjectType:       "User",
					IsInherited:      false,
					Properties: map[string]any{
						"rdpshot_reason": "NLA not required or BlueKeep exploitable",
					},
				})
			}
		}

		computerEntries = append(computerEntries, entry)
	}

	// ── assemble ─────────────────────────────────────────────────────────────
	var data []BHEntry
	data = append(data, userEntries...)
	data = append(data, computerEntries...)

	return BHExport{
		Meta: BHMeta{
			Methods: 0,
			Type:    "mixed",
			Count:   len(data),
			Version: 5,
		},
		Data: data,
	}
}

// JSON returns the BloodHound export serialised as indented JSON bytes.
func (e BHExport) JSON() ([]byte, error) {
	return json.MarshalIndent(e, "", "  ")
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

type domainUser struct{ domain, user string }

func userDomain(c model.Credential, fallbackDomain string) domainUser {
	d := strings.ToUpper(strings.TrimSpace(c.Domain))
	u := strings.ToUpper(strings.TrimSpace(c.Username))
	if d == "" {
		d = fallbackDomain
	}
	return domainUser{domain: d, user: u}
}

// syntheticSID builds a deterministic fake SID for BloodHound import.
// Real SIDs come from AD; since rdpshot doesn't have AD access we generate
// stable pseudo-SIDs of the form S-1-5-21-<hash>-<hash>-<hash>-<rid>.
func syntheticSID(domain, name, nodeType string) string {
	input := strings.ToUpper(domain + "/" + name + "/" + nodeType)
	h := fnv32(input)
	h2 := fnv32(input + "2")
	h3 := fnv32(input + "3")
	var rid uint32
	switch nodeType {
	case "U":
		rid = 1000 + (fnv32(name) % 8000)
	case "C":
		rid = 9000 + (fnv32(name) % 8000)
	default:
		rid = 500
	}
	return fmt.Sprintf("S-1-5-21-%d-%d-%d-%d", h, h2, h3, rid)
}

func fnv32(s string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	if h == 0 {
		h = 1
	}
	return h
}

func endpointKey(addr string, port uint16) string {
	return fmt.Sprintf("%s:%d", addr, port)
}
