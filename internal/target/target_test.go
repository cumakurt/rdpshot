package target

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"rdpshot/internal/model"
)

func TestParsePorts(t *testing.T) {
	cases := []struct {
		in   string
		want []uint16
	}{
		{"", []uint16{3389}},
		{"3390", []uint16{3390}},
		{"3389,3390", []uint16{3389, 3390}},
		{"3389,3389", []uint16{3389}},
		{"33800-33802", []uint16{33800, 33801, 33802}},
		{"3389, 3390-3391", []uint16{3389, 3390, 3391}},
	}
	for _, tc := range cases {
		got, err := ParsePorts(tc.in)
		if err != nil {
			t.Fatalf("ParsePorts(%q): %v", tc.in, err)
		}
		if len(got) != len(tc.want) {
			t.Fatalf("ParsePorts(%q) = %v, want %v", tc.in, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("ParsePorts(%q) = %v, want %v", tc.in, got, tc.want)
			}
		}
	}
}

func TestParsePortsRejectsInvalid(t *testing.T) {
	for _, in := range []string{"0", "70000", "http", "10-5", "3389,", "-"} {
		if _, err := ParsePorts(in); err == nil {
			t.Fatalf("ParsePorts(%q): expected error", in)
		}
	}
}

func staticLookup(table map[string][]string) func(context.Context, string) ([]net.IP, error) {
	return func(_ context.Context, host string) ([]net.IP, error) {
		values, ok := table[host]
		if !ok {
			return nil, &net.DNSError{Err: "no such host", Name: host}
		}
		ips := make([]net.IP, 0, len(values))
		for _, v := range values {
			ips = append(ips, net.ParseIP(v))
		}
		return ips, nil
	}
}

func TestResolveSingleIPAndPort(t *testing.T) {
	res, err := Resolve(context.Background(), Options{
		Specs: []string{"192.168.1.10"},
		Ports: []uint16{3389, 3390},
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	want := []model.Endpoint{
		{Address: "192.168.1.10", Port: 3389},
		{Address: "192.168.1.10", Port: 3390},
	}
	assertEndpoints(t, res.Endpoints, want)
}

func TestResolveExplicitPortWins(t *testing.T) {
	res, err := Resolve(context.Background(), Options{
		Specs: []string{"192.168.1.10:3391"},
		Ports: []uint16{3389},
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	assertEndpoints(t, res.Endpoints, []model.Endpoint{{Address: "192.168.1.10", Port: 3391}})
}

func TestResolveCIDR(t *testing.T) {
	res, err := Resolve(context.Background(), Options{
		Specs: []string{"10.0.0.0/29"},
		Ports: []uint16{3389},
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(res.Endpoints) != 6 {
		t.Fatalf("expected 6 endpoints (network/broadcast skipped), got %d: %v", len(res.Endpoints), res.Endpoints)
	}
	if res.Endpoints[0].Address != "10.0.0.1" || res.Endpoints[5].Address != "10.0.0.6" {
		t.Fatalf("unexpected expansion: %v", res.Endpoints)
	}
}

func TestResolveHostname(t *testing.T) {
	lookup := staticLookup(map[string][]string{"lab.local": {"10.1.2.3", "10.1.2.4"}})
	res, err := Resolve(context.Background(), Options{
		Specs:  []string{"lab.local"},
		Ports:  []uint16{3389},
		Lookup: lookup,
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	assertEndpoints(t, res.Endpoints, []model.Endpoint{
		{Address: "10.1.2.3", Port: 3389},
		{Address: "10.1.2.4", Port: 3389},
	})
}

func TestResolveUnresolvableHostWarns(t *testing.T) {
	lookup := staticLookup(nil)
	res, err := Resolve(context.Background(), Options{
		Specs:  []string{"missing.local"},
		Lookup: lookup,
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(res.Warnings) != 1 {
		t.Fatalf("expected one warning, got %v", res.Warnings)
	}
	if len(res.Endpoints) != 0 {
		t.Fatalf("expected no endpoints, got %v", res.Endpoints)
	}
}

func TestResolveBlacklist(t *testing.T) {
	res, err := Resolve(context.Background(), Options{
		Specs:     []string{"10.0.0.0/29"},
		Ports:     []uint16{3389},
		Blacklist: []string{"10.0.0.2", "10.0.0.0/31"},
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	for _, ep := range res.Endpoints {
		if ep.Address == "10.0.0.1" || ep.Address == "10.0.0.2" {
			t.Fatalf("blacklisted address leaked: %v", res.Endpoints)
		}
	}
}

func TestResolveFileSpec(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.txt")
	content := "# comment\n\n192.168.5.5\nlab.local:3390\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	lookup := staticLookup(map[string][]string{"lab.local": {"10.9.9.9"}})
	res, err := Resolve(context.Background(), Options{
		Specs:  []string{"@" + path},
		Ports:  []uint16{3389},
		Lookup: lookup,
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	assertEndpoints(t, res.Endpoints, []model.Endpoint{
		{Address: "10.9.9.9", Port: 3390},
		{Address: "192.168.5.5", Port: 3389},
	})
}

func TestResolveMissingFile(t *testing.T) {
	if _, err := Resolve(context.Background(), Options{Specs: []string{"@/nope/targets.txt"}}); err == nil {
		t.Fatal("expected error for missing target file")
	}
}

func TestResolveDeduplicates(t *testing.T) {
	res, err := Resolve(context.Background(), Options{
		Specs: []string{"10.0.0.5", "10.0.0.5", "10.0.0.5:3389"},
		Ports: []uint16{3389},
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(res.Endpoints) != 1 {
		t.Fatalf("expected deduplication, got %v", res.Endpoints)
	}
}

func TestResolveEnforcesMaxTargets(t *testing.T) {
	_, err := Resolve(context.Background(), Options{
		Specs:      []string{"10.0.0.0/24"},
		Ports:      []uint16{3389},
		MaxTargets: 10,
	})
	if err == nil || !strings.Contains(err.Error(), "budget") {
		t.Fatalf("expected target budget error, got %v", err)
	}
}

func TestResolveRejectsBroadIPv6(t *testing.T) {
	if _, err := Resolve(context.Background(), Options{Specs: []string{"2001:db8::/64"}}); err == nil {
		t.Fatal("expected error for broad IPv6 prefix")
	}
}

func assertEndpoints(t *testing.T, got, want []model.Endpoint) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("endpoint count = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("endpoint[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}
