package paths

import (
	"strings"
	"testing"
)

func TestOperatorScopedCodesReadMicrosoftSites(t *testing.T) {
	c := popCandidates("be1013.rwa02.co8.ntwk.msn.net")
	if len(c) == 0 || c[0].Code != "co" || !strings.HasPrefix(c[0].Pop.City, "Quincy") {
		t.Fatalf("co under ntwk.msn.net should read as Quincy, got %+v", c)
	}
	// The same fragment under anyone else's domain means nothing.
	for _, m := range popCandidates("co8.example.net") {
		if m.Code == "co" {
			t.Fatal("co should not be a site code outside Microsoft's domain")
		}
	}
	m := &Module{}
	h := Home{Lat: 39.18, Lon: -96.57, OK: true}
	match, score, _ := m.placeFromName("be1013.rwa02.co8.ntwk.msn.net", 58, h)
	if score < 0.55 || !strings.HasPrefix(match.Pop.City, "Quincy") {
		t.Fatalf("58 ms from Kansas fits Quincy; got %s at %.2f", match.Pop.City, score)
	}
}

func TestImpossiblePlacementsAreSetAsideUnlessNamed(t *testing.T) {
	m := &Module{}
	h := Home{Lat: 39.18, Lon: -96.57, OK: true}
	g := Graph{Nodes: []Node{
		{ID: "a", Index: 5, IPs: []string{"51.10.6.166"}, RTT: 58, Located: true, Lat: 1.35, Lon: 103.82, City: "Singapore", Country: "SG", Source: "database"},
		{ID: "b", Index: 6, IPs: []string{"51.10.6.240"}, RTT: 54, Located: true, Lat: 11.17, Lon: -1.15, City: "Pô", Country: "BF", Source: "measured"},
		{ID: "c", Index: 7, IPs: []string{"10.0.0.1"}, Names: []string{"sin01.example.net"}, RTT: 20, Located: true, Lat: 1.35, Lon: 103.82, City: "Singapore", Source: "name"},
		{ID: "d", Index: 8, IPs: []string{"1.2.3.4"}, RTT: 30, Located: true, Lat: 41.88, Lon: -87.63, City: "Chicago", Source: "database"},
	}}
	m.checkPlausible(g.Nodes, h)
	setAsideImpossible(&g)
	if len(g.Rejected) != 2 {
		t.Fatalf("want the database and the measured placements rejected, got %+v", g.Rejected)
	}
	for _, id := range []string{"a", "b"} {
		var n *Node
		for i := range g.Nodes {
			if g.Nodes[i].ID == id {
				n = &g.Nodes[i]
			}
		}
		if n.Located || n.Impossible || n.SetAside == "" || n.Why != "" {
			t.Fatalf("%s should be unplaced with a reason: %+v", id, n)
		}
	}
	if !g.Nodes[2].Located || !g.Nodes[2].Impossible {
		t.Fatal("a name-based placement stays on the map as an accusation to be read")
	}
	if !g.Nodes[3].Located || g.Nodes[3].Impossible {
		t.Fatal("a plausible placement is untouched")
	}
	if g.Rejected[0].Where != "Singapore, SG" || g.Rejected[0].Source != "database" || g.Rejected[0].FloorMS < 100 {
		t.Fatalf("the rejection should carry the evidence: %+v", g.Rejected[0])
	}
}

func TestDressedSiteCodesInHostnamesAreRead(t *testing.T) {
	m := &Module{}
	h := Home{Lat: 39.18, Lon: -96.57, OK: true}
	for _, c := range []struct {
		host string
		rtt  float64
		city string
	}{
		{"usdal2-vip-fx-103.a.aaplimg.com", 44, "Dallas"},
		{"usmes2-dns-001.ts.apple.com", 30, "Mesa"},
		{"dfw07.example.net", 18, "Dallas"},
	} {
		match, score, why := m.placeFromName(c.host, c.rtt, h)
		if score < 0.55 || !strings.HasPrefix(match.Pop.City, c.city) {
			t.Fatalf("%s -> %s %.2f (%s), want %s", c.host, match.Pop.City, score, why, c.city)
		}
	}
}

func TestAnEdgeAnsweringJustBeforeItsAnchorIsStillBesideIt(t *testing.T) {
	g := Graph{Nodes: []Node{
		{ID: "d", Index: 6, IPs: []string{"12.1.1.1"}, RTT: 18.3, Located: true, Lat: 32.78, Lon: -96.8, City: "Dallas", Source: "name"},
		{ID: "ak", Index: 7, IPs: []string{"23.221.22.75"}, RTT: 16.7, Anycast: true},
	}, Legs: []Leg{{From: "d", To: "ak", Destinations: []string{"23.221.22.75"}}}}
	interpolateGaps(&g)
	if !g.Nodes[1].Located || g.Nodes[1].City != "Dallas" {
		t.Fatalf("%+v", g.Nodes[1])
	}
}
