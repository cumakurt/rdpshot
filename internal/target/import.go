package target

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"rdpshot/internal/model"
)

// Nmap XML schema models
type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status    nmapStatus    `xml:"status"`
	Addresses []nmapAddress `xml:"address"`
	Ports     nmapPorts     `xml:"ports"`
}

type nmapStatus struct {
	State string `xml:"state,attr"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   uint16      `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name string `xml:"name,attr"`
}

// Masscan JSON structure
type masscanEntry struct {
	IP    string `json:"ip"`
	Ports []struct {
		Port   uint16 `json:"port"`
		Proto  string `json:"proto"`
		Status string `json:"status"`
	} `json:"ports"`
}

// IsRDPPortOrService checks if a port or service name indicates an RDP listener.
func IsRDPPortOrService(port uint16, serviceName string) bool {
	if port == DefaultPort {
		return true
	}
	s := strings.ToLower(strings.TrimSpace(serviceName))
	if strings.Contains(s, "rdp") ||
		strings.Contains(s, "ms-wbt-server") ||
		strings.Contains(s, "ms-term-serv") ||
		strings.Contains(s, "terminal") {
		return true
	}
	return false
}

// ParseNmapXML extracts open RDP endpoints from Nmap or Masscan XML (-oX) output.
func ParseNmapXML(r io.Reader) ([]model.Endpoint, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read nmap xml: %w", err)
	}
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("parse nmap xml: %w", err)
	}

	seen := make(map[string]bool)
	var endpoints []model.Endpoint

	for _, h := range run.Hosts {
		if h.Status.State != "" && h.Status.State != "up" {
			continue
		}
		var hostIP string
		for _, a := range h.Addresses {
			if a.AddrType == "ipv4" || a.AddrType == "ipv6" || a.AddrType == "" {
				if net.ParseIP(a.Addr) != nil {
					hostIP = a.Addr
					break
				}
			}
		}
		if hostIP == "" && len(h.Addresses) > 0 {
			hostIP = h.Addresses[0].Addr
		}
		if hostIP == "" {
			continue
		}

		for _, p := range h.Ports.Ports {
			if p.State.State != "open" {
				continue
			}
			if p.Protocol != "" && p.Protocol != "tcp" {
				continue
			}
			if !IsRDPPortOrService(p.PortID, p.Service.Name) {
				continue
			}

			key := net.JoinHostPort(hostIP, strconv.Itoa(int(p.PortID)))
			if !seen[key] {
				seen[key] = true
				endpoints = append(endpoints, model.Endpoint{
					Address: hostIP,
					Port:    p.PortID,
				})
			}
		}
	}

	sortEndpoints(endpoints)
	return endpoints, nil
}

// ParseMasscanJSON extracts open RDP endpoints from Masscan JSON output.
func ParseMasscanJSON(r io.Reader) ([]model.Endpoint, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read masscan json: %w", err)
	}

	var entries []masscanEntry
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, nil
	}

	if err := json.Unmarshal(data, &entries); err != nil {
		// Attempt parsing line-delimited JSON
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			line = strings.TrimSuffix(line, ",")
			if line == "" || line == "[" || line == "]" {
				continue
			}
			var entry masscanEntry
			if jErr := json.Unmarshal([]byte(line), &entry); jErr == nil {
				entries = append(entries, entry)
			}
		}
	}

	seen := make(map[string]bool)
	var endpoints []model.Endpoint

	for _, e := range entries {
		ip := strings.TrimSpace(e.IP)
		if ip == "" || net.ParseIP(ip) == nil {
			continue
		}
		for _, p := range e.Ports {
			if p.Status != "" && p.Status != "open" {
				continue
			}
			if p.Proto != "" && p.Proto != "tcp" {
				continue
			}
			if p.Port != DefaultPort && !IsRDPPortOrService(p.Port, "") {
				continue
			}
			key := net.JoinHostPort(ip, strconv.Itoa(int(p.Port)))
			if !seen[key] {
				seen[key] = true
				endpoints = append(endpoints, model.Endpoint{
					Address: ip,
					Port:    p.Port,
				})
			}
		}
	}

	sortEndpoints(endpoints)
	return endpoints, nil
}

// ParseMasscanList extracts endpoints from Masscan text list format ("open tcp 3389 192.168.1.1 1600000000").
func ParseMasscanList(r io.Reader) ([]model.Endpoint, error) {
	scanner := bufio.NewScanner(r)
	seen := make(map[string]bool)
	var endpoints []model.Endpoint

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		// Expected format: open tcp <port> <ip> <timestamp>
		if len(parts) >= 4 && parts[0] == "open" && parts[1] == "tcp" {
			portNum, err := strconv.ParseUint(parts[2], 10, 16)
			if err != nil {
				continue
			}
			ip := parts[3]
			if net.ParseIP(ip) == nil {
				continue
			}
			p := uint16(portNum)
			if !IsRDPPortOrService(p, "") {
				continue
			}
			key := net.JoinHostPort(ip, parts[2])
			if !seen[key] {
				seen[key] = true
				endpoints = append(endpoints, model.Endpoint{
					Address: ip,
					Port:    p,
				})
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	sortEndpoints(endpoints)
	return endpoints, nil
}

// ParseImport automatically detects the format (Nmap XML, Masscan JSON, or Masscan List) and extracts RDP endpoints.
func ParseImport(r io.Reader) ([]model.Endpoint, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read import: %w", err)
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, nil
	}

	if bytes.HasPrefix(trimmed, []byte("<?xml")) || bytes.HasPrefix(trimmed, []byte("<nmaprun")) {
		return ParseNmapXML(bytes.NewReader(trimmed))
	}
	if bytes.HasPrefix(trimmed, []byte("[")) || bytes.HasPrefix(trimmed, []byte("{")) {
		return ParseMasscanJSON(bytes.NewReader(trimmed))
	}
	if bytes.HasPrefix(trimmed, []byte("open tcp")) || bytes.Contains(trimmed, []byte("open tcp")) {
		return ParseMasscanList(bytes.NewReader(trimmed))
	}

	// Fallback to Nmap XML if XML tags are present
	if bytes.Contains(trimmed, []byte("<host")) && bytes.Contains(trimmed, []byte("</host>")) {
		return ParseNmapXML(bytes.NewReader(trimmed))
	}

	return nil, fmt.Errorf("target: unrecognized scan import format (expected Nmap XML, Masscan JSON, or Masscan list)")
}

// ImportFile reads an Nmap XML or Masscan output file and returns the discovered RDP endpoints.
func ImportFile(filePath string) ([]model.Endpoint, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("open import file: %w", err)
	}
	defer f.Close()
	return ParseImport(f)
}

func sortEndpoints(eps []model.Endpoint) {
	sort.Slice(eps, func(i, j int) bool {
		if eps[i].Address == eps[j].Address {
			return eps[i].Port < eps[j].Port
		}
		return eps[i].Address < eps[j].Address
	})
}
