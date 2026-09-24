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
	m.everMAC, m.macName = m.durable(m.names, m.macs)
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
