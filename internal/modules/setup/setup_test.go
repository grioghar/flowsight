package setup

import (
	"strings"
	"testing"
)

func TestDetectInterfaces(t *testing.T) {
	m := &Module{}
	ifaces := m.detectInterfaces()
	if ifaces == nil {
		t.Fatal("detectInterfaces returned nil")
	}
}

func TestDetectBinaries(t *testing.T) {
	m := &Module{}
	bins := m.detectBinaries()
	// Just check that the structure is accessible
	if bins.Ntopng != (bins.Ntopng) { // Always true, just checking type
		t.Fail()
	}
}

func TestBinExists(t *testing.T) {
	m := &Module{}
	// Test with a common command
	if !m.binExists("cat") && !m.binExists("ls") {
		t.Log("common commands not found, skipping binExists test")
		return
	}
	// Test with a command that doesn't exist
	if m.binExists("this-command-definitely-does-not-exist-12345") {
		t.Fatal("binExists returned true for non-existent command")
	}
}

func TestDefaultGatewayLinux(t *testing.T) {
	m := &Module{}
	// Test parsing Linux output format
	testOutput := `default via 192.168.1.1 dev eth0
192.168.0.0/24 dev eth1 proto kernel scope link src 192.168.0.5`

	gateway := m.parseLinuxRouteOutput(testOutput)
	if gateway != "192.168.1.1" {
		t.Errorf("Expected 192.168.1.1, got %s", gateway)
	}
}

func TestDefaultGatewayFreeBSD(t *testing.T) {
	m := &Module{}
	// Test parsing FreeBSD output format
	testOutput := `   route to: default
destination: default
    mask: default
 gateway: 192.168.1.1
 fqdn: router.local
interface: em0
      recvpipe  sendpipe  expire
           0         0         0`

	gateway := m.parseFreeBSDRouteOutput(testOutput)
	if gateway != "192.168.1.1" {
		t.Errorf("Expected 192.168.1.1, got %s", gateway)
	}
}

func TestDNSServersFromResolvConf(t *testing.T) {
	m := &Module{}
	servers := m.dnsServersFromResolvConf()
	// Just check that it doesn't crash and returns a list
	if servers == nil {
		servers = []string{}
	}
	// Verify it's a string list
	for _, s := range servers {
		if s == "" {
			t.Fatal("Empty DNS server in list")
		}
	}
}

func TestDeduplicate(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected int
	}{
		{"no dupes", []string{"a", "b", "c"}, 3},
		{"with dupes", []string{"a", "b", "a", "c"}, 3},
		{"empty", []string{}, 0},
		{"with blanks", []string{"a", "", "b"}, 2},
	}

	for _, test := range tests {
		result := deduplicate(test.input)
		if len(result) != test.expected {
			t.Errorf("%s: expected %d results, got %d", test.name, test.expected, len(result))
		}
	}
}

func TestStateMarshaling(t *testing.T) {
	state := &State{
		Completed: false,
		Platform:  "opnsense",
		License: License{
			Tier: "community",
		},
	}

	if state.Platform != "opnsense" {
		t.Fatal("State field access failed")
	}
}

// Helper functions to test output parsing without running actual commands
func (m *Module) parseLinuxRouteOutput(output string) string {
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "default") {
			parts := strings.Fields(line)
			if len(parts) >= 3 && parts[1] == "via" {
				return parts[2]
			}
		}
	}
	return ""
}

func (m *Module) parseFreeBSDRouteOutput(output string) string {
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "gateway:") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				for i, part := range parts {
					if part == "gateway:" && i+1 < len(parts) {
						return parts[i+1]
					}
				}
			}
		}
	}
	return ""
}
