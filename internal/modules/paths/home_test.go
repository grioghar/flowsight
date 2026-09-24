package paths

import "testing"

// Three verdicts, not two. Under the floor is impossible; comfortably over it
// is unremarkable; and the band just above it is the interesting one, because
// the floor assumes a dead straight fibre with nothing attached to it and no
// real path is either.
func TestPlausibilityHasThreeVerdicts(t *testing.T) {
	// Kansas to London is about 7,000 km, so the floor is about 70 ms.
	home := Home{Lat: 39.1836, Lon: -96.5717, OK: true}
	london := func(rtt float64) Node {
		return Node{Located: true, Lat: 51.5072, Lon: -0.1276, RTT: rtt, IPs: []string{"1.2.3.4"}}
	}
	km := greatCircleKM(home.Lat, home.Lon, 51.5072, -0.1276)
	floor := floorMS(km)

	cases := []struct {
		name            string
		rtt             float64
		impossible, tig bool
	}{
		{"under the floor is impossible", floor * 0.5, true, false},
		{"a hair under is still impossible", floor * 0.99, true, false},
		{"just over the floor is doubtful", floor * 1.02, false, true},
		{"at the edge of the margin is doubtful", floor * 1.14, false, true},
		{"past the margin is accepted", floor * 1.40, false, false},
		{"a normal round trip is accepted", floor * 2.2, false, false},
	}
	for _, c := range cases {
		nodes := []Node{london(c.rtt)}
		m := &Module{}
		m.checkPlausible(nodes, home)
		n := nodes[0]
		if n.Impossible != c.impossible || n.Tight != c.tig {
			t.Errorf("%s (%.1f ms, floor %.1f): impossible=%v tight=%v, want %v/%v",
				c.name, c.rtt, floor, n.Impossible, n.Tight, c.impossible, c.tig)
		}
		// The two are verdicts about the same measurement and must never both
		// stand: one says the reading is disproved, the other that it is only
		// doubted.
		if n.Impossible && n.Tight {
			t.Errorf("%s: a placement cannot be both disproved and merely doubted", c.name)
		}
		if (n.Impossible || n.Tight) && n.Why == "" {
			t.Errorf("%s: a verdict against a placement has to say why", c.name)
		}
	}
}

// Every hop gets the distance and the floor, whatever the verdict, so a
// reader can check the arithmetic rather than take the label on trust.
func TestPlausibilityShowsItsWorking(t *testing.T) {
	m := &Module{}
	nodes := []Node{{Located: true, Lat: 51.5072, Lon: -0.1276, RTT: 400, IPs: []string{"1.2.3.4"}}}
	m.checkPlausible(nodes, Home{Lat: 39.1836, Lon: -96.5717, OK: true})
	if nodes[0].DistanceKM < 6000 || nodes[0].DistanceKM > 8000 {
		t.Errorf("distance looks wrong: %v km", nodes[0].DistanceKM)
	}
	if nodes[0].FloorMS <= 0 {
		t.Errorf("no floor recorded")
	}
}
