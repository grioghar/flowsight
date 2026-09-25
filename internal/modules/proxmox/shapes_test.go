package proxmox

import (
	"encoding/json"
	"os"
	"testing"
)

// The real responses from the user's node: a container's interfaces carry
// addresses as ip-addresses[].ip-address, the agent says inet/inet6.
func TestLXCInterfacesFixtureYieldsAddresses(t *testing.T) {
	b, err := os.ReadFile("testdata/lxc_3140_interfaces.json")
	if err != nil {
		t.Skip("fixture missing")
	}
	var ifaces pveLXCInterfaces
	// The fixture is the bare array (pvesh output); wrap it as the API does.
	if err := json.Unmarshal(b, &ifaces.Data); err != nil {
		if err2 := json.Unmarshal(b, &ifaces); err2 != nil {
			t.Fatal(err)
		}
	}
	var ips, macs []string
	for _, iface := range ifaces.Data {
		mac := iface.HwAddr
		if mac == "" {
			mac = iface.HardwareAddress
		}
		if mac != "" && mac != "00:00:00:00:00:00" {
			macs = append(macs, mac)
		}
		for _, a := range iface.IPAddresses {
			if ip, ok := usableIP(a.IPAddress); ok {
				ips = append(ips, ip)
			}
		}
	}
	if len(macs) == 0 || len(ips) == 0 {
		t.Fatalf("expected a MAC and addresses from the container: macs=%v ips=%v", macs, ips)
	}
	found := false
	for _, ip := range ips {
		if ip == "192.168.1.56" {
			found = true
		}
		if ip == "127.0.0.1" || ip == "::1" {
			t.Fatalf("loopback must be dropped: %v", ips)
		}
	}
	if !found {
		t.Fatalf("192.168.1.56 expected among %v", ips)
	}
}

func TestAgentNetworkFixtureYieldsAddresses(t *testing.T) {
	b, err := os.ReadFile("testdata/qemu_102_agent_network.json")
	if err != nil {
		t.Skip("fixture missing")
	}
	var agentNet pveAgentNetworkResp
	if err := json.Unmarshal(b, &agentNet); err != nil {
		t.Fatal(err)
	}
	var ips []string
	for _, iface := range agentNet.Result {
		for _, a := range iface.IPAddresses {
			if ip, ok := usableIP(a.IPAddress); ok {
				ips = append(ips, ip)
			}
		}
	}
	if len(ips) == 0 {
		t.Fatal("the gateway VM's agent report should yield addresses")
	}
}

func TestUsableIPStripsPrefixAndDropsLocal(t *testing.T) {
	if ip, ok := usableIP("192.168.1.56/17"); !ok || ip != "192.168.1.56" {
		t.Fatalf("cidr: %q %v", ip, ok)
	}
	for _, bad := range []string{"127.0.0.1", "::1", "fe80::1", "", "nonsense"} {
		if _, ok := usableIP(bad); ok {
			t.Fatalf("%q should not be usable", bad)
		}
	}
}
