// Package target resolves scan target specifications into concrete endpoints.
package target

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"rdpshot/internal/model"
)

// DefaultPort is used when a specification carries no explicit port.
const DefaultPort uint16 = 3389

// Options controls target resolution.
type Options struct {
	// Specs are raw target specifications: IP, CIDR, hostname, host:port or @file.
	Specs []string
	// Ports are the scan ports applied to specs without an explicit port.
	Ports []uint16
	// Blacklist entries (IP, CIDR or hostname) are always excluded.
	Blacklist []string
	// MaxTargets bounds the expansion; exceeding it is a hard error.
	MaxTargets int
	// Lookup resolves hostnames; defaults to net.DefaultResolver. Injectable for tests.
	Lookup func(ctx context.Context, host string) ([]net.IP, error)
}

// Result carries resolved endpoints plus non-fatal warnings (e.g. unresolvable hosts).
type Result struct {
	Endpoints []model.Endpoint
	Warnings  []string
}

// ParsePorts parses a port list such as "3389,3390,33800-33810".
func ParsePorts(spec string) ([]uint16, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return []uint16{DefaultPort}, nil
	}
	seen := make(map[uint16]bool)
	var ports []uint16
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("target: empty port entry in %q", spec)
		}
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			lo, err := parsePort(bounds[0])
			if err != nil {
				return nil, err
			}
			hi, err := parsePort(bounds[1])
			if err != nil {
				return nil, err
			}
			if lo > hi {
				return nil, fmt.Errorf("target: invalid port range %q (lower bound above upper bound)", part)
			}
			for p := lo; p <= hi; p++ {
				if !seen[p] {
					seen[p] = true
					ports = append(ports, p)
				}
			}
			continue
		}
		p, err := parsePort(part)
		if err != nil {
			return nil, err
		}
		if !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("target: no ports parsed from %q", spec)
	}
	return ports, nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("target: invalid port %q", s)
	}
	return uint16(n), nil
}

// Resolve expands the specifications into a deduplicated, deterministic
// endpoint list. Specs may reference a file via the "@path" syntax.
func Resolve(ctx context.Context, opts Options) (Result, error) {
	lookup := opts.Lookup
	if lookup == nil {
		lookup = func(ctx context.Context, host string) ([]net.IP, error) {
			addrs, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
			return addrs, err
		}
	}
	ports := opts.Ports
	if len(ports) == 0 {
		ports = []uint16{DefaultPort}
	}
	maxTargets := opts.MaxTargets
	if maxTargets <= 0 {
		maxTargets = 65536
	}

	specs, err := expandFileSpecs(opts.Specs)
	if err != nil {
		return Result{}, err
	}

	blacklist, err := buildBlacklist(ctx, opts.Blacklist, lookup)
	if err != nil {
		return Result{}, err
	}

	var result Result
	seen := make(map[model.Endpoint]bool)
	add := func(address string, port uint16) error {
		if blacklist.contains(address) {
			return nil
		}
		ep := model.Endpoint{Address: address, Port: port}
		if seen[ep] {
			return nil
		}
		if len(seen) >= maxTargets {
			return fmt.Errorf("target: target limit of %d endpoints exceeded", maxTargets)
		}
		seen[ep] = true
		result.Endpoints = append(result.Endpoints, ep)
		return nil
	}

	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}
		host, explicitPort, err := splitHostPort(spec)
		if err != nil {
			return Result{}, err
		}
		targetPorts := ports
		if explicitPort != nil {
			targetPorts = []uint16{*explicitPort}
		}
		switch {
		case strings.Contains(host, "/"):
			ips, err := expandCIDR(host, maxTargets-len(seen))
			if err != nil {
				return Result{}, err
			}
			for _, ip := range ips {
				for _, p := range targetPorts {
					if err := add(ip.String(), p); err != nil {
						return Result{}, err
					}
				}
			}
		case net.ParseIP(host) != nil:
			for _, p := range targetPorts {
				if err := add(host, p); err != nil {
					return Result{}, err
				}
			}
		default:
			addrs, err := lookup(ctx, host)
			if err != nil {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("hostname %q could not be resolved: %v", host, err))
				continue
			}
			if len(addrs) == 0 {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("hostname %q resolved to no addresses", host))
				continue
			}
			for _, ip := range addrs {
				for _, p := range targetPorts {
					if err := add(ip.String(), p); err != nil {
						return Result{}, err
					}
				}
			}
		}
	}

	sort.Slice(result.Endpoints, func(i, j int) bool {
		a, b := result.Endpoints[i], result.Endpoints[j]
		if cmp := compareIPs(net.ParseIP(a.Address), net.ParseIP(b.Address)); cmp != 0 {
			return cmp < 0
		}
		return a.Port < b.Port
	})
	return result, nil
}

func expandFileSpecs(specs []string) ([]string, error) {
	var out []string
	for _, spec := range specs {
		if !strings.HasPrefix(spec, "@") {
			out = append(out, spec)
			continue
		}
		path := strings.TrimSpace(strings.TrimPrefix(spec, "@"))
		if path == "" {
			return nil, fmt.Errorf("target: empty file spec %q", spec)
		}
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("target: open target file %q: %w", path, err)
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			out = append(out, line)
		}
		scanErr := scanner.Err()
		closeErr := f.Close()
		if scanErr != nil {
			return nil, fmt.Errorf("target: read target file %q: %w", path, scanErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("target: close target file %q: %w", path, closeErr)
		}
	}
	return out, nil
}

// splitHostPort separates an optional explicit port from a spec. IPv6
// addresses are recognized before port splitting so "2001:db8::1" stays intact.
func splitHostPort(spec string) (host string, port *uint16, err error) {
	if net.ParseIP(spec) != nil || strings.Contains(spec, "/") {
		return spec, nil, nil
	}
	if strings.Count(spec, ":") == 1 || strings.HasPrefix(spec, "[") {
		h, p, splitErr := net.SplitHostPort(spec)
		if splitErr != nil {
			// Not a valid host:port pair; treat the whole spec as a hostname.
			return spec, nil, nil
		}
		parsed, parseErr := parsePort(p)
		if parseErr != nil {
			return "", nil, parseErr
		}
		return h, &parsed, nil
	}
	return spec, nil, nil
}

func expandCIDR(spec string, budget int) ([]net.IP, error) {
	ip, ipNet, err := net.ParseCIDR(spec)
	if err != nil {
		return nil, fmt.Errorf("target: invalid CIDR %q: %w", spec, err)
	}
	ones, bits := ipNet.Mask.Size()
	if bits == 128 && ones < 112 {
		return nil, fmt.Errorf("target: IPv6 prefix %q is too broad (minimum /112)", spec)
	}
	hostBits := bits - ones
	total := int64(1) << uint(hostBits)
	usable := total
	if bits == 32 && hostBits >= 2 {
		// Skip the network and broadcast addresses of IPv4 subnets.
		usable = total - 2
	}
	if usable > int64(budget) {
		return nil, fmt.Errorf("target: CIDR %q expands to %d addresses, beyond the remaining target budget (%d)", spec, usable, budget)
	}

	start := ip.Mask(ipNet.Mask).To16()
	if start == nil {
		return nil, fmt.Errorf("target: invalid CIDR %q", spec)
	}
	skip := bits == 32 && hostBits >= 2
	ips := make([]net.IP, 0, usable)
	current := make(net.IP, len(start))
	copy(current, start)
	for i := int64(0); i < total; i++ {
		if !(skip && (i == 0 || i == total-1)) {
			ipCopy := make(net.IP, len(current))
			copy(ipCopy, current)
			ips = append(ips, ipCopy)
		}
		incIP(current)
	}
	return ips, nil
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return
		}
	}
}

type blacklistEntry struct {
	ip   net.IP
	cidr *net.IPNet
}

type blacklist []blacklistEntry

func buildBlacklist(ctx context.Context, specs []string, lookup func(context.Context, string) ([]net.IP, error)) (blacklist, error) {
	var list blacklist
	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}
		if strings.Contains(spec, "/") {
			ip, ipNet, err := net.ParseCIDR(spec)
			if err != nil {
				return nil, fmt.Errorf("target: invalid blacklist CIDR %q: %w", spec, err)
			}
			list = append(list, blacklistEntry{ip: ip, cidr: ipNet})
			continue
		}
		if ip := net.ParseIP(spec); ip != nil {
			list = append(list, blacklistEntry{ip: ip})
			continue
		}
		addrs, err := lookup(ctx, spec)
		if err != nil {
			return nil, fmt.Errorf("target: resolve blacklist host %q: %w", spec, err)
		}
		for _, ip := range addrs {
			list = append(list, blacklistEntry{ip: ip})
		}
	}
	return list, nil
}

func (b blacklist) contains(address string) bool {
	ip := net.ParseIP(address)
	if ip == nil {
		return false
	}
	for _, entry := range b {
		if entry.cidr != nil {
			if entry.cidr.Contains(ip) {
				return true
			}
			continue
		}
		if entry.ip.Equal(ip) {
			return true
		}
	}
	return false
}

func compareIPs(a, b net.IP) int {
	if a == nil || b == nil {
		return 0
	}
	a4, b4 := a.To16(), b.To16()
	for i := 0; i < len(a4); i++ {
		switch {
		case a4[i] < b4[i]:
			return -1
		case a4[i] > b4[i]:
			return 1
		}
	}
	return 0
}
