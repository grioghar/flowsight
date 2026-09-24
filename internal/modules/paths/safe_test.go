package paths

import (
	"net"
	"testing"
)

// A daemon that fetches whatever URL it is given is a proxy into the network
// it sits in. These are the addresses it must refuse to dial, whatever a name
// resolves to.
func TestOnlyPublicAddressesAreDialled(t *testing.T) {
	refuse := []string{
		"127.0.0.1", "::1", // itself
		"10.0.0.1", "172.16.5.5", "192.168.1.1", // the network
		"169.254.169.254",               // the cloud metadata address, the classic target
		"fe80::1", "fc00::1", "fd12::1", // link-local and ULA
		"100.64.0.1",    // carrier-grade NAT
		"192.0.0.1",     // IETF protocol assignments
		"0.0.0.0", "::", // unspecified
		"224.0.0.1", "ff02::1", // multicast
	}
	for _, s := range refuse {
		if err := publicOnly(net.ParseIP(s)); err == nil {
			t.Errorf("%s should be refused", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "8.8.8.8", "193.0.6.139", "2001:4860:4860::8888", "2a00:1450:4009:81f::200e"} {
		if err := publicOnly(net.ParseIP(s)); err != nil {
			t.Errorf("%s is public and should be allowed: %v", s, err)
		}
	}
	if err := publicOnly(nil); err == nil {
		t.Error("an unparseable address must be refused, not dialled")
	}
}

// The shape a user-supplied fetch URL may take.
func TestFetchURLsAreVetted(t *testing.T) {
	for _, bad := range []string{
		"file:///etc/passwd",
		"ftp://example.com/x.json",
		"gopher://example.com/",
		"http://",
		"http://user:pass@example.com/x.json",
		"http://127.0.0.1:8080/api/paths/home",
		"http://192.168.1.1/",
		"http://[::1]/",
		"http://169.254.169.254/latest/meta-data/",
		"not a url at all",
	} {
		if err := checkFetchURL(bad); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
	for _, ok := range []string{
		"https://www.submarinecablemap.com/api/v3/cable/cable-geo.json",
		"https://data.apps.fao.org/catalog/dataset/x/download/afterfibre.geojson",
		"http://example.org/routes.json",
	} {
		if err := checkFetchURL(ok); err != nil {
			t.Errorf("%q should be allowed: %v", ok, err)
		}
	}
}

// A string that came off a traceroute is not an address until it parses as
// one. looksLikeAddress is deliberately loose; this is the gate behind it.
func TestOnlyRealAddressesAreLookedUp(t *testing.T) {
	for _, s := range []string{"1.2.3.4:5:6", "1.2.3", "::g", "", "1.2.3.4/../x", "%2e%2e"} {
		if validIP(s) {
			t.Errorf("%q is not an address", s)
		}
	}
	for _, s := range []string{"1.2.3.4", "::", "2001:db8::1", " 8.8.8.8 "} {
		if !validIP(s) {
			t.Errorf("%q is an address", s)
		}
	}
}

// Six of every seven nodes never answered and nothing draws them. They are
// needed to build the graph -- their place in a route keeps the numbering
// honest -- and not needed in what is sent.
func TestSilentNodesAreDroppedFromTheReplyButCounted(t *testing.T) {
	g := buildGraph([]hopRow{
		{Dst: "9.9.9.9", Index: 1, IP: "10.0.0.1", RTT: 1},
		{Dst: "9.9.9.9", Index: 2, IP: "", RTT: -1},
		{Dst: "9.9.9.9", Index: 3, IP: "", RTT: -1},
		{Dst: "9.9.9.9", Index: 4, IP: "10.0.0.4", RTT: 4},
	})
	for i := range g.Nodes {
		if !g.Nodes[i].Silent {
			g.Nodes[i].Located, g.Nodes[i].Lat, g.Nodes[i].Lon = true, 39, -96
		}
	}
	bridgeGaps(&g)
	legsBefore := len(g.Legs)
	dropSilent(&g)
	if g.SilentCount != 2 {
		t.Errorf("two hops never answered, counted %d", g.SilentCount)
	}
	for _, n := range g.Nodes {
		if n.Silent {
			t.Errorf("silent node %s was sent", n.ID)
		}
	}
	for _, l := range g.Legs {
		for _, id := range []string{l.From, l.To} {
			found := false
			for _, n := range g.Nodes {
				if n.ID == id {
					found = true
				}
			}
			if !found {
				t.Errorf("leg %s>%s dangles after silent nodes were dropped", l.From, l.To)
			}
		}
	}
	// The bridge across the silent stretch survives; it is what the map draws.
	bridged := false
	for _, l := range g.Legs {
		if l.Gap && l.Through == 2 {
			bridged = true
		}
	}
	if !bridged {
		t.Errorf("the bridge over the silent hops should remain (had %d legs, now %d)", legsBefore, len(g.Legs))
	}
}
