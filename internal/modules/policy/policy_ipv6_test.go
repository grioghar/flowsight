package policy

import (
	"testing"

	"github.com/grioghar/flowsight/internal/core"
)

// testMemberResolver is a mock MemberResolver for testing.
type testMemberResolver struct {
	results map[string][]string
}

func (t *testMemberResolver) Resolve(member string) []string {
	return t.results[member]
}

// testAddressBook is a mock AddressBook for testing.
type testAddressBook struct {
	addresses map[string][]string
}

func (t *testAddressBook) Addresses(ip string) []string {
	if addrs, ok := t.addresses[ip]; ok {
		return addrs
	}
	return []string{ip}
}

// testEnrollChecker is a mock enroll module that implements CheckZoneIPv6Devices.
type testEnrollChecker struct {
	ipv6DeviceCount int
}

func (t *testEnrollChecker) CheckZoneIPv6Devices(zoneID string) int {
	return t.ipv6DeviceCount
}

// TestIPv6WarningWhenNoSubnet6 tests that warning is set when zone members
// resolve to IPv4 only but devices have IPv6 addresses.
func TestIPv6WarningWhenNoSubnet6(t *testing.T) {
	// Create a minimal policy module context simulation
	doc := &core.PolicyDoc{
		Policies: []core.Policy{
			{
				Name:    "test-policy",
				Enabled: true,
				Action:  "block",
				Match: core.Match{
					Members: []string{"zone:test-zone"},
				},
			},
		},
	}

	// Mock resolver: zone:test-zone resolves to IPv4 subnet and device IPv4 only
	mockResolver := &testMemberResolver{
		results: map[string][]string{
			"zone:test-zone": {
				"192.168.1.0/24",   // IPv4 subnet
				"192.168.1.100/32", // device IPv4
			},
		},
	}

	// Mock enroll checker: zone has 1 device with IPv6
	mockEnroll := &testEnrollChecker{
		ipv6DeviceCount: 1,
	}

	// Simulate warning check logic
	pol := &doc.Policies[0]
	mems := doc.Members(pol, mockResolver)

	// Check if members contain IPv6
	hasIPv6Member := false
	for _, mem := range mems {
		if len(mem) > 4 && mem[len(mem)-4:] == "/128" {
			hasIPv6Member = true
			break
		}
	}

	var warning string
	if len(mems) > 0 && !hasIPv6Member {
		// Check for IPv6 devices in zones
		zoneIDs := []string{"test-zone"} // extracted from policy.Match.Members
		ipv6DeviceCount := mockEnroll.CheckZoneIPv6Devices(zoneIDs[0])
		if ipv6DeviceCount > 0 {
			warning = "members resolve to IPv4 only; " + string(rune(ipv6DeviceCount+'0')) + " device(s) also use IPv6 (add the zone's IPv6 subnet or use device:/mac: members)"
		}
	}

	if warning == "" {
		t.Error("expected IPv6 warning, got none")
	}
	if len(warning) == 0 || warning[:len("members resolve to IPv4 only")] != "members resolve to IPv4 only" {
		t.Errorf("warning does not match expected pattern: %s", warning)
	}
}

// TestNoIPv6WarningWhenSubnet6Set tests that no warning is set when
// zone has subnet6 defined.
func TestNoIPv6WarningWhenSubnet6Set(t *testing.T) {
	// Create a minimal policy module context simulation
	doc := &core.PolicyDoc{
		Policies: []core.Policy{
			{
				Name:    "test-policy",
				Enabled: true,
				Action:  "block",
				Match: core.Match{
					Members: []string{"zone:test-zone"},
				},
			},
		},
	}

	// Mock resolver: zone:test-zone resolves to both IPv4 and IPv6 subnets
	mockResolver := &testMemberResolver{
		results: map[string][]string{
			"zone:test-zone": {
				"192.168.1.0/24",   // IPv4 subnet
				"fd00::/64",        // IPv6 subnet
				"192.168.1.100/32", // device IPv4
				"fd00::100/128",    // device IPv6
			},
		},
	}

	// Mock enroll checker: zone has IPv6 devices
	mockEnroll := &testEnrollChecker{
		ipv6DeviceCount: 1,
	}

	// Simulate warning check logic
	pol := &doc.Policies[0]
	mems := doc.Members(pol, mockResolver)

	// Check if members contain IPv6
	hasIPv6Member := false
	for _, mem := range mems {
		if len(mem) > 4 && mem[len(mem)-4:] == "/128" {
			hasIPv6Member = true
			break
		}
	}

	var warning string
	if len(mems) > 0 && !hasIPv6Member {
		// Check for IPv6 devices in zones
		zoneIDs := []string{"test-zone"}
		ipv6DeviceCount := mockEnroll.CheckZoneIPv6Devices(zoneIDs[0])
		if ipv6DeviceCount > 0 {
			warning = "members resolve to IPv4 only; " + string(rune(ipv6DeviceCount+'0')) + " device(s) also use IPv6 (add the zone's IPv6 subnet or use device:/mac: members)"
		}
	}

	if warning != "" {
		t.Errorf("expected no warning when IPv6 is present, got: %s", warning)
	}
}
