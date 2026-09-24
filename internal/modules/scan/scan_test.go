package scan

import (
	"testing"
)

func TestGetPortSet(t *testing.T) {
	m := &Module{
		portSet:     "top100",
		customPorts: "",
	}

	ports := m.getPortSet("quick")
	if len(ports) != len(top100Ports) {
		t.Errorf("expected %d ports, got %d", len(top100Ports), len(ports))
	}

	m.portSet = "top1000"
	ports = m.getPortSet("quick")
	if len(ports) != len(top1000Ports) {
		t.Errorf("expected %d ports, got %d", len(top1000Ports), len(ports))
	}

	m.portSet = "custom"
	m.customPorts = "22,80,443"
	ports = m.getPortSet("quick")
	if len(ports) != 3 {
		t.Errorf("expected 3 ports, got %d", len(ports))
	}
}

func TestServiceNameForPort(t *testing.T) {
	tests := []struct {
		port     int
		expected string
	}{
		{22, "ssh"},
		{80, "http"},
		{443, "https"},
		{3306, "mysql"},
		{9999, ""},
	}

	for _, test := range tests {
		result := serviceNameForPort(test.port)
		if result != test.expected {
			t.Errorf("port %d: expected %q, got %q", test.port, test.expected, result)
		}
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		slice    []string
		item     string
		expected bool
	}{
		{[]string{"mdns_respond", "icmp_respond"}, "mdns", true},
		{[]string{"mdns_respond", "icmp_respond"}, "netbios", false},
		{[]string{}, "anything", false},
	}

	for _, test := range tests {
		result := contains(test.slice, test.item)
		if result != test.expected {
			t.Errorf("contains(%v, %q): expected %v, got %v", test.slice, test.item, test.expected, result)
		}
	}
}

func TestGuessOS(t *testing.T) {
	m := &Module{}

	// Test with mDNS responding
	result := &ScanResult{
		IP:       "192.168.1.100",
		Findings: []string{"mdns_respond"},
	}
	m.guessOS(result)

	if len(result.OSGuesses) == 0 {
		t.Errorf("expected OS guesses for mDNS response, got none")
	}

	foundLinux := false
	for _, guess := range result.OSGuesses {
		if guess.OS == "Linux/macOS/BSD" {
			foundLinux = true
			if guess.Confidence != 0.7 {
				t.Errorf("expected confidence 0.7, got %f", guess.Confidence)
			}
		}
	}
	if !foundLinux {
		t.Errorf("expected Linux/macOS/BSD guess for mDNS response")
	}

	// Test with NetBIOS responding
	result2 := &ScanResult{
		IP:       "192.168.1.101",
		Findings: []string{"netbios_respond"},
	}
	m.guessOS(result2)

	if len(result2.OSGuesses) == 0 {
		t.Errorf("expected OS guesses for NetBIOS response, got none")
	}

	foundWindows := false
	for _, guess := range result2.OSGuesses {
		if guess.OS == "Windows" {
			foundWindows = true
			if guess.Confidence != 0.8 {
				t.Errorf("expected confidence 0.8, got %f", guess.Confidence)
			}
		}
	}
	if !foundWindows {
		t.Errorf("expected Windows guess for NetBIOS response")
	}
}

func TestNmapXMLParsing(t *testing.T) {
	m := &Module{}

	xmlData := []byte(`<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -oX - localhost" start="1234567890" startstr="Wed Feb 13 16:31:30 2019" version="7.70" xmloutputversion="1.05">
<host starttime="1234567890" endtime="1234567891">
<status state="up" reason="syn-ack" reason_ttl="0"/>
<ports>
<port protocol="tcp" portid="22">
<state state="open" reason="syn-ack" reason_ttl="0"/>
<service name="ssh" version="OpenSSH 7.4"/>
</port>
<port protocol="tcp" portid="80">
<state state="open" reason="syn-ack" reason_ttl="0"/>
<service name="http" product="Apache httpd" version="2.4.6"/>
</port>
</ports>
<os>
<osmatch name="Linux 4.15 - 5.6" accuracy="95" line="65432"/>
</os>
</host>
</nmaprun>`)

	result := &ScanResult{
		IP:       "127.0.0.1",
		Services: make(map[string]*Service),
	}

	err := m.parseNmapXML(xmlData, result)
	if err != nil {
		t.Errorf("failed to parse nmap XML: %v", err)
	}

	if len(result.OpenPorts) != 2 {
		t.Errorf("expected 2 open ports, got %d", len(result.OpenPorts))
	}

	if len(result.OSGuesses) != 1 {
		t.Errorf("expected 1 OS guess, got %d", len(result.OSGuesses))
	}

	if result.OSGuesses[0].OS != "Linux 4.15 - 5.6" {
		t.Errorf("expected OS 'Linux 4.15 - 5.6', got %q", result.OSGuesses[0].OS)
	}

	if result.OSGuesses[0].Confidence != 0.95 {
		t.Errorf("expected confidence 0.95, got %f", result.OSGuesses[0].Confidence)
	}
}
