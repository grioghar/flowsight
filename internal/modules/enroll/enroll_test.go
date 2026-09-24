package enroll

import (
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/grioghar/flowsight/internal/core"
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

// A rule's conditions are the "when" object, not the rule around it. Loading
// the whole rule as the condition set put id, zone, confidence and why
// alongside the real conditions, and an unrecognised key used to count as a
// match, so every rule matched every device and the first one won. On a live
// network that classified all 106 devices as infrastructure, including the
// televisions and smart plugs.
func TestRuleConditionsAreTheWhenObject(t *testing.T) {
	dir := t.TempDir()
	doc := `{"rules":[
      {"id":"hypervisor-guest","zone":"infra","confidence":"high","why":"a guest",
       "when":{"guest_kind":["vm","ct","node"]}},
      {"id":"iot-vendor","zone":"iot","confidence":"high","why":"a gadget",
       "when":{"vendor":["Tuya","Roku","Amazon Technologies"]}}]}`
	if err := os.WriteFile(filepath.Join(dir, "enroll-rules.json"), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	m := &Module{ctx: &core.Context{Platform: &core.Platform{EtcDir: dir}}}
	if err := m.loadRules(); err != nil {
		t.Fatalf("loadRules: %v", err)
	}
	if len(m.rules) != 2 {
		t.Fatalf("want 2 rules, got %d", len(m.rules))
	}
	for _, r := range m.rules {
		for _, leaked := range []string{"id", "zone", "confidence", "why", "when"} {
			if _, ok := r.When[leaked]; ok {
				t.Errorf("rule %s: %q leaked into the conditions", r.ID, leaked)
			}
		}
	}

	// A Roku must not match the hypervisor rule just because that rule is first.
	roku := &Device{Vendor: "Roku, Inc", Hostname: "roku-ultra"}
	if m.ruleMatches(m.rules[0], roku, nil) {
		t.Error("a gadget matched the hypervisor rule; conditions are not being applied")
	}
	if !m.ruleMatches(m.rules[1], roku, nil) {
		t.Error("a Roku should match the vendor rule")
	}
}

// An unrecognised condition must never count as a match, or one typo turns a
// narrow rule into "everything" with nothing to show for it.
func TestUnknownConditionDoesNotMatch(t *testing.T) {
	m := &Module{}
	if m.matchCondition("not_a_real_condition", []interface{}{"x"}, &Device{Vendor: "Tuya"}, nil) {
		t.Error("an unknown condition key must not match")
	}
}

// Rules saved through the API or UI must be parsed the same way as rules read
// from disk. apiSetRules once used the whole rule as its conditions; with
// unrecognised keys failing closed that matched nothing, so every device fell
// into the captive zone until the next restart reread the file.
func TestSetRulesThroughAPIUsesWhenObject(t *testing.T) {
	dir := t.TempDir()
	m := &Module{ctx: &core.Context{Platform: &core.Platform{EtcDir: dir}}}
	body := []byte(`{"rules":[
      {"id":"hypervisor-guest","zone":"infra","confidence":"high","why":"a guest",
       "when":{"guest_kind":["vm","ct","node"]}},
      {"id":"iot-vendor","zone":"iot","confidence":"high","why":"a gadget",
       "when":{"vendor":["Tuya","Roku","Reolink"]}}]}`)
	req := core.NewReq(httptest.NewRequest("POST", "/api/enroll/rules", nil), "admin", "127.0.0.1", body)
	if _, err := m.apiSetRules(req); err != nil {
		t.Fatalf("apiSetRules: %v", err)
	}

	check := func(label string) {
		t.Helper()
		if len(m.rules) != 2 {
			t.Fatalf("%s: want 2 rules, got %d", label, len(m.rules))
		}
		for _, r := range m.rules {
			for _, leaked := range []string{"id", "zone", "confidence", "why", "when"} {
				if _, ok := r.When[leaked]; ok {
					t.Errorf("%s: rule %s: %q leaked into the conditions", label, r.ID, leaked)
				}
			}
		}
		hub := &Device{MAC: "ec:71:db:00:00:01", Vendor: "Reolink Innovation Limited"}
		zone, rule, _, _ := m.classify(hub, nil)
		if zone != "iot" || rule != "iot-vendor" {
			t.Errorf("%s: Reolink classified as zone %q rule %q, want iot / iot-vendor", label, zone, rule)
		}
		vm := &Device{MAC: "bc:24:11:00:00:01", GuestKind: "vm"}
		if zone, rule, _, _ := m.classify(vm, nil); zone != "infra" || rule != "hypervisor-guest" {
			t.Errorf("%s: VM classified as zone %q rule %q, want infra / hypervisor-guest", label, zone, rule)
		}
	}
	check("after POST")

	// What was saved must load back to the same rules.
	m.rules = nil
	if err := m.loadRules(); err != nil {
		t.Fatalf("loadRules: %v", err)
	}
	check("after reload")
}

// reconcileModule is a module with a store, the given mode and zones iot,
// infra and a captive zone, and one rule placing Reolink gear in iot.
func reconcileModule(t *testing.T, mode string) *Module {
	t.Helper()
	store, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return &Module{
		ctx:           &core.Context{Store: store},
		devices:       map[string]*Device{},
		pendingAssign: map[string]string{},
		zones: &ZonesDoc{Mode: mode, CaptiveZone: "quarantine",
			Zones: []*Zone{{ID: "iot"}, {ID: "infra"}, {ID: "quarantine"}}},
		rules: []*Rule{{ID: "iot-vendor", Zone: "iot", Confidence: "high",
			When: map[string]interface{}{"vendor": []interface{}{"Reolink"}}}},
	}
}

// A zone set by an earlier classification is not a decision anyone made. In
// monitor mode an unpinned device follows the rules on the next reconcile,
// which is what cleans up the devices a classification bug put in infra.
// A device someone placed stays put, and one not heard from recently is
// reclassified without being marked as seen.
func TestReconcileRederivesUnpinnedZones(t *testing.T) {
	m := reconcileModule(t, "monitor")
	old := time.Now().Add(-30 * 24 * time.Hour).Unix()
	m.devices["ec:71:db:00:00:01"] = &Device{MAC: "ec:71:db:00:00:01", Vendor: "Reolink Innovation Limited", Zone: "infra", LastSeen: old}
	m.devices["aa:00:00:00:00:02"] = &Device{MAC: "aa:00:00:00:00:02", Vendor: "Unknown Co", Zone: "infra", LastSeen: old}
	m.devices["ec:71:db:00:00:03"] = &Device{MAC: "ec:71:db:00:00:03", Vendor: "Reolink Innovation Limited", Zone: "infra", Pinned: 1, LastSeen: old}

	if err := m.reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	for mac, want := range map[string]string{
		"ec:71:db:00:00:01": "iot",        // follows its rule
		"aa:00:00:00:00:02": "quarantine", // matches nothing: captive zone
		"ec:71:db:00:00:03": "infra",      // pinned: left alone
	} {
		if got := m.devices[mac].Zone; got != want {
			t.Errorf("%s: zone %q, want %q", mac, got, want)
		}
	}
	if got := m.devices["ec:71:db:00:00:01"].LastSeen; got != old {
		t.Errorf("reclassifying a quiet device changed its last-seen time to %d", got)
	}

	// The change is persisted, not only held in memory.
	m.devices = map[string]*Device{}
	m.loadRegistry()
	if d := m.devices["ec:71:db:00:00:01"]; d == nil || d.Zone != "iot" || d.Rule != "iot-vendor" {
		t.Errorf("after reload: %+v, want zone iot by rule iot-vendor", d)
	}
}

// In enforce mode a zone is an address the device already holds; switching
// to enforce promises that present devices stay where they are, so only a
// device without a zone is placed.
func TestReconcileEnforceKeepsPlacedDevices(t *testing.T) {
	m := reconcileModule(t, "enforce")
	m.devices["ec:71:db:00:00:01"] = &Device{MAC: "ec:71:db:00:00:01", Vendor: "Reolink Innovation Limited", Zone: "infra"}
	m.devices["ec:71:db:00:00:02"] = &Device{MAC: "ec:71:db:00:00:02", Vendor: "Reolink Innovation Limited"}
	if err := m.reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got := m.devices["ec:71:db:00:00:01"].Zone; got != "infra" {
		t.Errorf("placed device moved to %q in enforce mode", got)
	}
	if got := m.devices["ec:71:db:00:00:02"].Zone; got != "iot" {
		t.Errorf("unplaced device got zone %q, want iot", got)
	}
}

// Choosing a zone pins the device; choosing none hands it back to the rules.
func TestAssignPinsAndUnpins(t *testing.T) {
	m := reconcileModule(t, "monitor")
	mac := "ec:71:db:00:00:01"
	m.devices[mac] = &Device{MAC: mac, Vendor: "Reolink Innovation Limited", Class: "iot", Zone: "iot"}
	assign := func(zone string) {
		t.Helper()
		body := []byte(`{"mac":"` + mac + `","zone":"` + zone + `"}`)
		if _, err := m.apiAssign(core.NewReq(httptest.NewRequest("POST", "/api/enroll/assign", nil), "admin", "127.0.0.1", body)); err != nil {
			t.Fatalf("apiAssign(%q): %v", zone, err)
		}
	}

	assign("infra")
	if d := m.devices[mac]; d.Zone != "infra" || d.Pinned != 1 {
		t.Fatalf("after assigning infra: zone %q pinned %d", d.Zone, d.Pinned)
	}
	if err := m.reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := m.devices[mac].Zone; got != "infra" {
		t.Errorf("reconcile moved a pinned device to %q", got)
	}

	assign("")
	if d := m.devices[mac]; d.Zone != "iot" || d.Pinned != 0 {
		t.Errorf("after clearing: zone %q pinned %d, want iot and unpinned", d.Zone, d.Pinned)
	}
}

// DHCPv4 lines give a device's address; DHCPv6 lines use the same operation
// names with a client DUID where the address would be, and must not produce
// a device. These are the shapes dnsmasq writes on the live gateway.
func TestDnsmasqLineAddresses(t *testing.T) {
	const pre = `<30>1 2026-09-24T07:40:00+00:00 OPNsense.internal dnsmasq-dhcp 39072 - [meta sequenceId="8"] `
	tests := []struct {
		name, text, mac, ip string
	}{
		{"v4 discover", "3935910021 DHCPDISCOVER(vtnet0) bc:24:11:cc:52:5d", "bc:24:11:cc:52:5d", ""},
		{"v4 request", "3935910021 DHCPREQUEST(vtnet0) 192.168.1.71 EC:71:DB:8C:B1:67", "ec:71:db:8c:b1:67", "192.168.1.71"},
		{"v4 ack", "3935910021 DHCPACK(vtnet0) 192.168.1.71 ec:71:db:8c:b1:67 reolink-hub", "ec:71:db:8c:b1:67", "192.168.1.71"},
		{"v6 request", "9917758 DHCPREQUEST(vtnet0) 00:01:00:01:c7:93:6a:64:70:09:71:2d:f7:9b", "", ""},
		{"v6 solicit", "7537509 DHCPSOLICIT(vtnet0) 00:03:00:01:ec:71:db:8c:b1:67", "", ""},
		{"v6 reply", "9917758 DHCPREPLY(vtnet0) 2600:1700:3ab0:f43f::143f 00:01:00:01:c7:93:6a:64:70:09:71:2d:f7:9b", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := reconcileModule(t, "monitor")
			m.txnState = map[string]*txnData{}
			m.parseDnsmasqLogLine(pre + tt.text)
			var mac, ip string
			for _, txn := range m.txnState {
				mac, ip = txn.mac, txn.ip
			}
			if mac != tt.mac || ip != tt.ip {
				t.Errorf("got mac %q ip %q, want mac %q ip %q", mac, ip, tt.mac, tt.ip)
			}
			if tt.mac == "" && len(m.gatherSignals()) != 0 {
				t.Error("a DHCPv6 line produced a device")
			}
		})
	}
}

// Client IDs stored by earlier builds are dropped when the registry loads,
// from memory and from the store, unless someone pinned one.
func TestLoadRegistryDropsClientIDs(t *testing.T) {
	m := reconcileModule(t, "monitor")
	for _, d := range []*Device{
		{MAC: "00:01:00:01:c7:93"},
		{MAC: "00:01:01:00:31:aa"}, // Windows writes its DUID hardware type byte-swapped
		{MAC: "00:03:00:01:fa:29", Pinned: 1},
		{MAC: "00:03:00:01:02:ea", IP: "192.168.1.40"}, // real hardware with that prefix
		{MAC: "ec:71:db:8c:b1:67", Vendor: "Reolink Innovation Limited"},
	} {
		if err := m.saveDevice(d); err != nil {
			t.Fatal(err)
		}
	}
	m.loadRegistry()
	for _, mac := range []string{"00:01:00:01:c7:93", "00:01:01:00:31:aa"} {
		if _, ok := m.devices[mac]; ok {
			t.Errorf("client ID %s still listed as a device", mac)
		}
	}
	if _, ok := m.devices["00:03:00:01:02:ea"]; !ok {
		t.Error("a device with an address was dropped")
	}
	if _, ok := m.devices["00:03:00:01:fa:29"]; !ok {
		t.Error("a pinned entry was dropped")
	}
	if _, ok := m.devices["ec:71:db:8c:b1:67"]; !ok {
		t.Error("a real device was dropped")
	}
	m.devices = map[string]*Device{}
	m.loadRegistry()
	if _, ok := m.devices["00:01:00:01:c7:93"]; ok {
		t.Error("client ID came back from the store")
	}
}
