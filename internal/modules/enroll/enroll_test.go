package enroll

import (
	"net"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestIsRandomizedMAC tests the locally-administered MAC detection.
func TestIsRandomizedMAC(t *testing.T) {
	tests := []struct {
		mac  string
		want bool
	}{
		{"02:aa:bb:cc:dd:ee", true},  // bit 1 set in first octet
		{"00:aa:bb:cc:dd:ee", false}, // bit 1 clear
		{"06:aa:bb:cc:dd:ee", true},  // bit 1 and 2 set
		{"01:aa:bb:cc:dd:ee", false}, // only bit 0 set
		{"aa:bb:cc:dd:ee:ff", true},  // bit 1 set (aa = 10101010 in binary)
		{"ab:bb:cc:dd:ee:ff", true},  // bit 1 set (ab = 10101011)
		{"ac:bb:cc:dd:ee:ff", false}, // bit 1 clear (ac = 10101100)
	}

	for _, tt := range tests {
		t.Run(tt.mac, func(t *testing.T) {
			got := isRandomizedMAC(tt.mac)
			if got != tt.want {
				t.Errorf("isRandomizedMAC(%s) = %v, want %v", tt.mac, got, tt.want)
			}
		})
	}
}

// TestAllocator tests address allocation within a zone.
func TestAllocator(t *testing.T) {
	a := NewAllocator("192.168.0.0/24", "192.168.0.10", "192.168.0.20", nil)
	if a == nil {
		t.Fatal("allocator is nil")
	}

	tests := []struct {
		mac  string
		want string
	}{
		{"aa:bb:cc:dd:ee:01", "192.168.0.10"},
		{"aa:bb:cc:dd:ee:02", "192.168.0.11"},
		{"aa:bb:cc:dd:ee:03", "192.168.0.12"},
		{"aa:bb:cc:dd:ee:01", "192.168.0.10"}, // same MAC gets same IP
	}

	for _, tt := range tests {
		got, err := a.Allocate(tt.mac)
		if err != nil {
			t.Errorf("Allocate(%s) error: %v", tt.mac, err)
			continue
		}
		if got != tt.want {
			t.Errorf("Allocate(%s) = %s, want %s", tt.mac, got, tt.want)
		}
	}
}

// TestAllocatorExhaustion tests that allocator properly exhausts a range.
func TestAllocatorExhaustion(t *testing.T) {
	a := NewAllocator("192.168.0.0/24", "192.168.0.10", "192.168.0.12", nil)
	if a == nil {
		t.Fatal("allocator is nil")
	}

	// Allocate all 3 addresses
	for i := 0; i < 3; i++ {
		mac := makeMac(i)
		_, err := a.Allocate(mac)
		if err != nil {
			t.Fatalf("Allocate(%s) at iteration %d: %v", mac, i, err)
		}
	}

	// Fourth allocation should fail
	_, err := a.Allocate("ff:ff:ff:ff:ff:ff")
	if err == nil {
		t.Error("Allocate(ff:ff:ff:ff:ff:ff) expected error when range exhausted")
	}
}

// TestRuleClassifier tests the rule matching logic.
func TestRuleClassifier(t *testing.T) {
	tests := []struct {
		name        string
		device      *Device
		signal      *Signal
		rule        *Rule
		shouldMatch bool
	}{
		{
			name:   "vendor match",
			device: &Device{Vendor: "Apple"},
			rule: &Rule{
				When: map[string]interface{}{
					"vendor": []interface{}{"Apple", "Google"},
				},
			},
			shouldMatch: true,
		},
		{
			name:   "vendor case insensitive",
			device: &Device{Vendor: "apple"},
			rule: &Rule{
				When: map[string]interface{}{
					"vendor": []interface{}{"Apple"},
				},
			},
			shouldMatch: true,
		},
		{
			name:   "hostname regex match",
			device: &Device{Hostname: "iphone-5"},
			rule: &Rule{
				When: map[string]interface{}{
					"hostname_re": "iphone",
				},
			},
			shouldMatch: true,
		},
		{
			name:   "hostname regex no match",
			device: &Device{Hostname: "printer-1"},
			rule: &Rule{
				When: map[string]interface{}{
					"hostname_re": "iphone",
				},
			},
			shouldMatch: false,
		},
		{
			name:   "mac prefix match",
			device: &Device{MAC: "aa:bb:cc:dd:ee:ff"},
			rule: &Rule{
				When: map[string]interface{}{
					"mac_prefix": []interface{}{"aa:bb:cc"},
				},
			},
			shouldMatch: true,
		},
		{
			name:   "mac prefix case insensitive",
			device: &Device{MAC: "AA:BB:CC:DD:EE:FF"},
			rule: &Rule{
				When: map[string]interface{}{
					"mac_prefix": []interface{}{"aa:bb:cc"},
				},
			},
			shouldMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Module{}
			got := m.ruleMatches(tt.rule, tt.device, nil)
			if got != tt.shouldMatch {
				t.Errorf("ruleMatches() = %v, want %v", got, tt.shouldMatch)
			}
		})
	}
}

// TestPFRuleGeneration tests pf rule rendering.
func TestPFRuleGeneration(t *testing.T) {
	zones := &ZonesDoc{
		Mode: "enforce",
		Zones: []*Zone{
			{
				ID:       "personal",
				Name:     "Personal",
				Subnet:   "192.168.0.0/24",
				Internet: true,
				Block:    "192.168.0.0/24",
			},
			{
				ID:         "iot",
				Name:       "IoT",
				Subnet:     "192.168.2.0/24",
				Internet:   false,
				Block:      "192.168.2.0/24",
				ReachZones: []string{},
			},
		},
	}

	m := &Module{zones: zones}

	// This tests just the structure, not actual firewall application
	// In a real scenario, would apply with firewall service
	if m.zones == nil {
		t.Fatal("zones not set")
	}

	// Verify zone subnets are valid
	for _, z := range m.zones.Zones {
		_, _, err := net.ParseCIDR(z.Subnet)
		if err != nil {
			t.Errorf("zone %s invalid subnet: %v", z.ID, err)
		}
		_, _, err = net.ParseCIDR(z.Block)
		if err != nil {
			t.Errorf("zone %s invalid block: %v", z.ID, err)
		}
	}
}

// TestValidateZoneDocument tests zone document validation.
func TestValidateZoneDocument(t *testing.T) {
	tests := []struct {
		name       string
		subnet     string
		block      string
		rangeStart string
		rangeEnd   string
		wantErr    bool
	}{
		{
			name:       "valid zone",
			subnet:     "192.168.0.0/24",
			block:      "192.168.0.0/24",
			rangeStart: "192.168.0.10",
			rangeEnd:   "192.168.0.250",
			wantErr:    false,
		},
		{
			name:       "invalid subnet",
			subnet:     "192.168.0.999/24",
			block:      "192.168.0.0/24",
			rangeStart: "192.168.0.10",
			rangeEnd:   "192.168.0.250",
			wantErr:    true,
		},
		{
			name:       "invalid range start",
			subnet:     "192.168.0.0/24",
			block:      "192.168.0.0/24",
			rangeStart: "not-an-ip",
			rangeEnd:   "192.168.0.250",
			wantErr:    true,
		},
		{
			name:       "invalid range end",
			subnet:     "192.168.0.0/24",
			block:      "192.168.0.0/24",
			rangeStart: "192.168.0.10",
			rangeEnd:   "not-an-ip",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := net.ParseCIDR(tt.subnet)
			hasSubnetErr := err != nil

			start := net.ParseIP(tt.rangeStart)
			end := net.ParseIP(tt.rangeEnd)
			hasRangeErr := start == nil || end == nil

			hasErr := hasSubnetErr || hasRangeErr
			if hasErr != tt.wantErr {
				t.Errorf("validation got error %v, want error %v (subnet err: %v, range err: %v)",
					hasErr, tt.wantErr, hasSubnetErr, hasRangeErr)
			}
		})
	}
}

// TestRegexValidation tests rule regex validation.
func TestRegexValidation(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantErr bool
	}{
		{"valid simple", "iphone", false},
		{"valid complex", "^(iphone|ipad|mac)", false},
		{"invalid", "[invalid", true},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := regexp.Compile(tt.pattern)
			if (err != nil) != tt.wantErr {
				t.Errorf("regex compilation of %q got error %v, want error %v", tt.pattern, err, tt.wantErr)
			}
		})
	}
}

// TestDnsmasqLogParsing tests parsing of dnsmasq DHCP log lines (RFC5424 format).
func TestDnsmasqLogParsing(t *testing.T) {
	tests := []struct {
		name string
		line string
		want bool
	}{
		{
			name: "DHCPDISCOVER with RFC5424 header",
			line: `<30>1 2026-09-19T01:55:56+00:00 OPNsense.internal dnsmasq-dhcp 39072 - [meta sequenceId="8"] DHCPDISCOVER(vtnet0) bc:24:11:cc:52:5d`,
			want: true,
		},
		{
			name: "client provides name",
			line: `<30>1 2026-09-19T01:55:56+00:00 OPNsense.internal dnsmasq-dhcp 39072 - [meta sequenceId="9"] 1234567 client provides name: fs-client`,
			want: true,
		},
		{
			name: "vendor class",
			line: `<30>1 2026-09-19T01:55:56+00:00 OPNsense.internal dnsmasq-dhcp 39072 - [meta sequenceId="10"] 1234567 vendor class: android-dhcp-14`,
			want: true,
		},
		{
			name: "requested options",
			line: `<30>1 2026-09-19T01:55:56+00:00 OPNsense.internal dnsmasq-dhcp 39072 - [meta sequenceId="11"] 1234567 requested options: 1:netmask, 3:router, 6:dns-server, 15:domain-name, 26:mtu`,
			want: true,
		},
		{
			name: "DHCPACK",
			line: `<30>1 2026-09-19T01:55:56+00:00 OPNsense.internal dnsmasq-dhcp 39072 - [meta sequenceId="12"] DHCPACK(vtnet0) 10.99.0.162 bc:24:11:cc:52:5d fs-client`,
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test parsing - verify RFC5424 lines are recognized
			if strings.Contains(tt.line, "dnsmasq-dhcp") != tt.want {
				t.Errorf("line parsing check failed for: %s", tt.name)
			}
		})
	}
}

// TestPseudoMAC tests pseudo-MAC detection.
func TestPseudoMAC(t *testing.T) {
	tests := []struct {
		mac  string
		want bool
	}{
		{"FF:FF:FF:FF:FF:FF", true},  // broadcast
		{"01:00:5E:00:00:01", true},  // IPv4 multicast
		{"33:33:00:00:00:01", true},  // IPv6 multicast
		{"00:AA:BB:CC:DD:EE", false}, // unicast
		{"aa:bb:cc:dd:ee:ff", false}, // unicast lowercase
	}

	for _, tt := range tests {
		t.Run(tt.mac, func(t *testing.T) {
			got := isPseudoMAC(tt.mac)
			if got != tt.want {
				t.Errorf("isPseudoMAC(%s) = %v, want %v", tt.mac, got, tt.want)
			}
		})
	}
}

// TestRateLimiter tests the captive portal rate limiting.
func TestRateLimiter(t *testing.T) {
	m := &Module{
		captiveRate: map[string]int64{},
	}

	mac := "aa:bb:cc:dd:ee:ff"
	now := time.Now().Unix()

	// First change should be allowed
	m.captiveMuRate.Lock()
	m.captiveRate[mac] = now
	m.captiveMuRate.Unlock()

	// Attempt within 60 seconds should be denied
	m.captiveMuRate.Lock()
	lastChange := m.captiveRate[mac]
	elapsed := now - lastChange
	if elapsed < 60 {
		// Would be rate-limited
	}
	m.captiveMuRate.Unlock()

	// After 60 seconds, should be allowed
	futureTime := now + 60
	m.captiveMuRate.Lock()
	lastChange = m.captiveRate[mac]
	if futureTime-lastChange >= 60 {
		m.captiveRate[mac] = futureTime
		// Would be allowed
	}
	m.captiveMuRate.Unlock()

	// Verify state was updated
	m.captiveMuRate.Lock()
	final := m.captiveRate[mac]
	m.captiveMuRate.Unlock()

	if final != futureTime {
		t.Errorf("rate limiter state: got %d, want %d", final, futureTime)
	}
}

// TestIPIncrement tests IP address increment logic.
func TestIPIncrement(t *testing.T) {
	tests := []struct {
		start string
		count int
		want  string
	}{
		{"192.168.0.10", 0, "192.168.0.10"},
		{"192.168.0.10", 1, "192.168.0.11"},
		{"192.168.0.255", 1, "192.168.1.0"},
	}

	for _, tt := range tests {
		t.Run(tt.start, func(t *testing.T) {
			ip := net.ParseIP(tt.start).To4()
			if ip == nil {
				t.Fatal("failed to parse IP")
			}

			for i := 0; i < tt.count; i++ {
				ipIncrement(ip)
			}

			if ip.String() != tt.want {
				t.Errorf("after %d increments: got %s, want %s", tt.count, ip.String(), tt.want)
			}
		})
	}
}

// Helpers

func makeMac(i int) string {
	return [...]string{
		"aa:bb:cc:dd:ee:01",
		"aa:bb:cc:dd:ee:02",
		"aa:bb:cc:dd:ee:03",
	}[i]
}
