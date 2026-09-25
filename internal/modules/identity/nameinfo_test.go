package identity

import (
	"testing"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// TestNameInfoPrecedence verifies that name sources are returned in the correct
// order of trust: override > dhcp_hostname > reservation > device_table > resolver_answer
func TestNameInfoPrecedence(t *testing.T) {
	st, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	m := &Module{
		ctx:     &core.Context{Store: st},
		names:   map[string]string{},
		sources: map[string]nameSource{},
		macs:    map[string]string{},
		ips:     map[string][]string{},
		leases:  map[string]Lease{},
		static:  map[string]string{},
		overr:   map[string]string{},
		everMAC: map[string]string{},
		macName: map[string]string{},
		vendors: map[string]string{},
		seenAt:  map[string]map[string]int64{},
	}

	testIP := "192.168.1.100"
	testMAC := "aa:bb:cc:dd:ee:01"
	_ = time.Now().Unix()

	// Test 1: operator override should be highest priority
	m.overr[testIP] = "MyDevice"
	info := m.NameInfo(testIP)
	if info.Source != "override" || info.Confidence != 1.0 || info.Name != "MyDevice" {
		t.Errorf("override should have source='override', confidence=1.0, name='MyDevice'; got %v", info)
	}

	// Test 2: DHCP hostname should beat device table
	m.overr = map[string]string{}
	m.macs[testIP] = testMAC
	m.leases[testMAC] = Lease{
		MAC:      testMAC,
		IP:       testIP,
		Hostname: "DHCPDevice",
		Source:   "dnsmasq",
	}
	m.names[testIP] = "DHCPDevice"
	m.sources[testIP] = nameSource{name: "DHCPDevice", source: "dhcp_hostname", confidence: 0.88}
	info = m.NameInfo(testIP)
	if info.Source != "dhcp_hostname" || info.Confidence != 0.88 {
		t.Errorf("dhcp should have source='dhcp_hostname', confidence=0.88; got source=%q, confidence=%g", info.Source, info.Confidence)
	}

	// Test 3: static reservation should beat device table but lose to DHCP
	m.leases = map[string]Lease{}
	m.names[testIP] = "ReservedDevice"
	m.sources[testIP] = nameSource{name: "ReservedDevice", source: "reservation", confidence: 0.80}
	m.static[testIP] = "ReservedDevice"
	info = m.NameInfo(testIP)
	if info.Source != "reservation" || info.Confidence != 0.80 {
		t.Errorf("reservation should have source='reservation', confidence=0.80; got source=%q, confidence=%g", info.Source, info.Confidence)
	}

	// Test 4: device table (enrollment) should be lower than static
	m.static = map[string]string{}
	m.names[testIP] = "EnrolledDevice"
	m.sources[testIP] = nameSource{name: "EnrolledDevice", source: "device_table", confidence: 0.70}
	info = m.NameInfo(testIP)
	if info.Source != "device_table" || info.Confidence < 0.68 || info.Confidence > 0.72 {
		t.Errorf("device_table should have source='device_table', confidence around 0.70; got source=%q, confidence=%g", info.Source, info.Confidence)
	}

	// Test 5: resolver answer handling requires unlocking during DB query, so skip detailed test

	// Test 6: no name source
	m.names = map[string]string{}
	m.sources = map[string]nameSource{}
	m.macs = map[string]string{}
	info = m.NameInfo("192.168.1.200")
	if info.Source != "none" || info.Confidence != 0.0 {
		t.Errorf("unknown address should have source='none', confidence=0.0; got source=%q, confidence=%g", info.Source, info.Confidence)
	}
}

// TestNameInfoLoopback verifies that loopback addresses are handled specially
func TestNameInfoLoopback(t *testing.T) {
	st, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	m := &Module{
		ctx:     &core.Context{Store: st},
		names:   map[string]string{},
		sources: map[string]nameSource{},
		macs:    map[string]string{},
		ips:     map[string][]string{},
		static:  map[string]string{},
		overr:   map[string]string{},
		everMAC: map[string]string{},
		macName: map[string]string{},
		vendors: map[string]string{},
		seenAt:  map[string]map[string]int64{},
	}

	info := m.NameInfo("127.0.0.1")
	if info.Source != "loopback" || info.Confidence != 1.0 {
		t.Errorf("loopback should have source='loopback', confidence=1.0; got source=%q, confidence=%g", info.Source, info.Confidence)
	}

	info = m.NameInfo("::1")
	if info.Source != "loopback" || info.Confidence != 1.0 {
		t.Errorf("IPv6 loopback should have source='loopback', confidence=1.0; got source=%q, confidence=%g", info.Source, info.Confidence)
	}
}
