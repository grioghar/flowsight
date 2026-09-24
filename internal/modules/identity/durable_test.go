package identity

import (
	"testing"

	"github.com/grioghar/flowsight/internal/core"
)

// An address that has rotated out of the neighbour table still belongs to
// the device the hosts table recorded it against, and carries its name.
func TestAddressesOutsideTheWindowStillBelongToTheirDevice(t *testing.T) {
	st, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	mac := "aa:bb:cc:dd:ee:01"
	if err := st.UpsertHosts([]core.HostUpdate{
		{IP: "192.168.1.119", MAC: mac, Name: "MacBookPro", Source: "dhcp"},
		{IP: "2600:1700:3ab0:f43f:4825:7e4e:55d:b2b6", MAC: mac, Source: "ndp"}, // seen a fortnight ago
		{IP: "2600:1700:3ab0:f43f:ffff::9", Source: "flows"},                    // nobody ever saw a MAC
	}); err != nil {
		t.Fatal(err)
	}
	m := &Module{ctx: &core.Context{Store: st}, names: map[string]string{}, macs: map[string]string{}, ips: map[string][]string{}}
	// The live tables know only the IPv4 lease right now.
	m.macs["192.168.1.119"] = mac
	m.names["192.168.1.119"] = "MacBookPro"
	m.mu.Lock()
	m.everMAC, m.macName, _ = m.durable(m.names, m.macs)
	m.mu.Unlock()

	if got := m.MAC("2600:1700:3ab0:f43f:4825:7e4e:55d:b2b6"); got != mac {
		t.Fatalf("rotated address lost its device: %q", got)
	}
	if got := m.Name("2600:1700:3ab0:f43f:4825:7e4e:55d:b2b6"); got != "MacBookPro" {
		t.Fatalf("rotated address lost its name: %q", got)
	}
	if got := m.MAC("2600:1700:3ab0:f43f:ffff::9"); got != "" {
		t.Fatalf("an address with no recorded MAC was invented one: %q", got)
	}
	addrs := m.Addresses("192.168.1.119")
	if len(addrs) != 2 || addrs[1] != "2600:1700:3ab0:f43f:4825:7e4e:55d:b2b6" {
		t.Fatalf("the device's history should include the rotated address: %v", addrs)
	}
}

// A DHCP address that changed hands names its new holder, not the device the
// hosts table recorded it against, and the old holder does not inherit the
// new holder's name through it.
func TestAddressThatChangedHandsDoesNotCrossNames(t *testing.T) {
	st, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	phone, vacuum := "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"
	if err := st.UpsertHosts([]core.HostUpdate{
		{IP: "192.168.1.56", MAC: phone, Name: "Phone", Source: "dhcp"}, // last week
		{IP: "192.168.1.99", MAC: vacuum, Name: "roborock", Source: "dhcp"},
	}); err != nil {
		t.Fatal(err)
	}
	m := &Module{ctx: &core.Context{Store: st}, names: map[string]string{}, macs: map[string]string{}, ips: map[string][]string{}}
	// Today the vacuum holds .56, unnamed; the phone is off.
	m.macs["192.168.1.56"] = vacuum
	m.mu.Lock()
	var moved []string
	m.everMAC, m.macName, moved = m.durable(m.names, m.macs)
	m.mu.Unlock()
	if got := m.MAC("192.168.1.56"); got != vacuum {
		t.Fatalf("live holder should win: %q", got)
	}
	if got := m.Name("192.168.1.56"); got == "Phone" {
		t.Fatalf("the vacuum was named after the phone")
	}
	if got := m.macName[vacuum]; got != "roborock" {
		t.Fatalf("vacuum lost its own name: %q", got)
	}
	if got := m.macName[phone]; got != "Phone" {
		t.Fatalf("phone lost its name: %q", got)
	}
	if len(moved) != 1 || moved[0] != "192.168.1.56" {
		t.Fatalf("the address that changed hands should be reported: %v", moved)
	}
}
