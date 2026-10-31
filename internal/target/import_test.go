package target

import (
	"strings"
	"testing"
)

func TestParseNmapXML(t *testing.T) {
	xmlData := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="3389">
        <state state="open"/>
        <service name="ms-wbt-server"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="3390">
        <state state="open"/>
        <service name="rdp"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="down"/>
    <address addr="192.168.1.99" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="3389">
        <state state="open"/>
      </port>
    </ports>
  </host>
</nmaprun>`

	endpoints, err := ParseNmapXML(strings.NewReader(xmlData))
	if err != nil {
		t.Fatalf("ParseNmapXML failed: %v", err)
	}

	if len(endpoints) != 2 {
		t.Fatalf("expected 2 endpoints, got %d: %+v", len(endpoints), endpoints)
	}

	if endpoints[0].Address != "10.0.0.5" || endpoints[0].Port != 3390 {
		t.Errorf("unexpected endpoint 0: %+v", endpoints[0])
	}
	if endpoints[1].Address != "192.168.1.10" || endpoints[1].Port != 3389 {
		t.Errorf("unexpected endpoint 1: %+v", endpoints[1])
	}
}

func TestParseMasscanJSON(t *testing.T) {
	jsonData := `[
  { "ip": "172.16.1.100", "ports": [ {"port": 3389, "proto": "tcp", "status": "open"} ] },
  { "ip": "172.16.1.200", "ports": [ {"port": 80, "proto": "tcp", "status": "open"} ] },
  { "ip": "172.16.1.100", "ports": [ {"port": 3389, "proto": "tcp", "status": "open"} ] }
]`

	endpoints, err := ParseMasscanJSON(strings.NewReader(jsonData))
	if err != nil {
		t.Fatalf("ParseMasscanJSON failed: %v", err)
	}

	if len(endpoints) != 1 {
		t.Fatalf("expected 1 unique endpoint, got %d: %+v", len(endpoints), endpoints)
	}
	if endpoints[0].Address != "172.16.1.100" || endpoints[0].Port != 3389 {
		t.Errorf("unexpected endpoint: %+v", endpoints[0])
	}
}

func TestParseMasscanList(t *testing.T) {
	listData := `# masscan list format
open tcp 3389 10.10.10.1 1600000000
open tcp 445 10.10.10.2 1600000000
open tcp 3389 10.10.10.3 1600000000
`
	endpoints, err := ParseMasscanList(strings.NewReader(listData))
	if err != nil {
		t.Fatalf("ParseMasscanList failed: %v", err)
	}

	if len(endpoints) != 2 {
		t.Fatalf("expected 2 endpoints, got %d: %+v", len(endpoints), endpoints)
	}
	if endpoints[0].Address != "10.10.10.1" || endpoints[0].Port != 3389 {
		t.Errorf("unexpected endpoint 0: %+v", endpoints[0])
	}
	if endpoints[1].Address != "10.10.10.3" || endpoints[1].Port != 3389 {
		t.Errorf("unexpected endpoint 1: %+v", endpoints[1])
	}
}

func TestParseImportAutoDetect(t *testing.T) {
	xmlSnippet := `<nmaprun><host><status state="up"/><address addr="10.0.0.1"/><ports><port protocol="tcp" portid="3389"><state state="open"/></port></ports></host></nmaprun>`
	eps, err := ParseImport(strings.NewReader(xmlSnippet))
	if err != nil {
		t.Fatalf("ParseImport XML failed: %v", err)
	}
	if len(eps) != 1 || eps[0].Address != "10.0.0.1" {
		t.Errorf("unexpected eps: %+v", eps)
	}

	jsonSnippet := `[{"ip": "10.0.0.2", "ports": [{"port": 3389, "status": "open"}]}]`
	eps, err = ParseImport(strings.NewReader(jsonSnippet))
	if err != nil {
		t.Fatalf("ParseImport JSON failed: %v", err)
	}
	if len(eps) != 1 || eps[0].Address != "10.0.0.2" {
		t.Errorf("unexpected eps: %+v", eps)
	}
}
