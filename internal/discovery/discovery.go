// Package discovery performs optional, detection-only probes for alternate
// RDP exposure paths (RD Web, RD Gateway hints, UDP 3389).
package discovery

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Result captures alternate exposure signals for one address.
type Result struct {
	RDWeb             bool   `json:"rd_web,omitempty"`
	RDWebURL          string `json:"rd_web_url,omitempty"`
	RDWebEvidence     string `json:"rd_web_evidence,omitempty"`
	RDGateway         bool   `json:"rd_gateway,omitempty"`
	RDGatewayEvidence string `json:"rd_gateway_evidence,omitempty"`
	RDGatewayAuth     string `json:"rd_gateway_auth,omitempty"`
	UDP3389           bool   `json:"udp_3389,omitempty"`
	UDPEvidence       string `json:"udp_evidence,omitempty"`
}

// Probe runs lightweight HTTP and UDP checks against address.
func Probe(ctx context.Context, address string) Result {
	var out Result
	out.RDWeb, out.RDWebURL, out.RDWebEvidence = probeRDWeb(ctx, address)
	out.RDGateway, out.RDGatewayEvidence, out.RDGatewayAuth = probeRDGateway(ctx, address)
	out.UDP3389, out.UDPEvidence = probeUDP3389(ctx, address)
	return out
}

func probeRDWeb(ctx context.Context, address string) (bool, string, string) {
	client := &http.Client{
		Timeout: 4 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // detection-only fingerprinting
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 2 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	paths := []string{
		"https://" + net.JoinHostPort(address, "443") + "/RDWeb",
		"https://" + net.JoinHostPort(address, "443") + "/RDWeb/Pages",
		"http://" + net.JoinHostPort(address, "80") + "/RDWeb",
	}
	for _, u := range paths {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "rdpshot-discovery/1")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		text := string(body)
		lower := strings.ToLower(text)
		if strings.Contains(lower, "rdweb") || strings.Contains(lower, "remote desktop") ||
			strings.Contains(lower, "rd web access") || resp.Header.Get("X-MS-Server-Fqdn") != "" {
			return true, u, fmt.Sprintf("HTTP %d with RD Web markers", resp.StatusCode)
		}
	}
	return false, "", ""
}

func probeRDGateway(ctx context.Context, address string) (bool, string, string) {
	client := &http.Client{
		Timeout: 4 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec
		},
	}
	u := "https://" + net.JoinHostPort(address, "443") + "/remoteDesktopGateway/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false, "", ""
	}
	req.Header.Set("User-Agent", "rdpshot-discovery/1")
	resp, err := client.Do(req)
	if err != nil {
		u = "https://" + net.JoinHostPort(address, "443") + "/rpc/rpcproxy.dll"
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return false, "", ""
		}
		resp, err = client.Do(req)
		if err != nil {
			return false, "", ""
		}
	}
	defer resp.Body.Close()
	authHeader := resp.Header.Get("WWW-Authenticate")
	auth := strings.ToLower(authHeader)
	server := strings.ToLower(resp.Header.Get("Server"))
	schemes := parseAuthSchemes(authHeader)
	if strings.Contains(auth, "negotiate") || strings.Contains(server, "microsoft") ||
		resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		if strings.Contains(u, "remoteDesktopGateway") || strings.Contains(u, "rpcproxy") {
			return true, fmt.Sprintf("HTTP %d on gateway path (%s)", resp.StatusCode, u), schemes
		}
	}
	return false, "", schemes
}

func parseAuthSchemes(header string) string {
	if header == "" {
		return ""
	}
	var schemes []string
	seen := map[string]bool{}
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name := strings.Fields(part)[0]
		name = strings.ToLower(name)
		if seen[name] {
			continue
		}
		seen[name] = true
		schemes = append(schemes, name)
	}
	return strings.Join(schemes, ",")
}

func probeUDP3389(ctx context.Context, address string) (bool, string) {
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(address, "3389"))
	if err != nil {
		return false, ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	// Minimal RDP-UDP probe byte; any ICMP/refusal still means the socket opened.
	_, err = conn.Write([]byte{0x00})
	if err != nil {
		return false, ""
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err == nil && n > 0 {
		return true, fmt.Sprintf("UDP/3389 responded with %d bytes", n)
	}
	// UDP is connectionless; silence is inconclusive and must not mark exposure.
	return false, ""
}
