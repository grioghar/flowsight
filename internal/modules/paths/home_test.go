package paths

import "testing"

// Three verdicts, and the middle one is about being too fast, not too slow.
//
// The floor is what light forbids and is a proof. Above it, a reply is not
// disproved -- but it can still be quicker than any route anyone has built,
// and the only thing that makes a reply quicker is the place being nearer.
// That is evidence in the same direction as impossible, and weaker.
//
// Being slow is never evidence of anything. Congestion, queuing and indirect
// routing all make a reply late and all are ordinary.
func TestPlausibilityHasThreeVerdicts(t *testing.T) {
	home := Home{Lat: 39.1836, Lon: -96.5717, OK: true}
	london := func(rtt float64) Node {
		return Node{Located: true, Lat: 51.5072, Lon: -0.1276, RTT: rtt, IPs: []string{"1.2.3.4"}}
	}
	km := greatCircleKM(home.Lat, home.Lon, 51.5072, -0.1276)
	floor := floorMS(km)
	m := &Module{}
	built := floorMS(km * m.landDetour()) // what a real route would need

	cases := []struct {
		name            string
		rtt             float64
		impossible, tig bool
	}{
		{"under the floor is disproved", floor * 0.5, true, false},
		{"a hair under is still disproved", floor * 0.99, true, false},
		{"above the floor but faster than any built route", floor * 1.05, false, true},
		{"just under what a built route needs", built * 0.98, false, true},
		{"just over it is accepted", built * 1.02, false, false},
		{"slow is never suspicious", built * 4, false, false},
		{"very slow is still never suspicious", built * 40, false, false},
	}
	for _, c := range cases {
		nodes := []Node{london(c.rtt)}
		m.checkPlausible(nodes, home)
		n := nodes[0]
		if n.Impossible != c.impossible || n.Tight != c.tig {
			t.Errorf("%s (%.1f ms; floor %.1f, built route %.1f): impossible=%v tight=%v, want %v/%v",
				c.name, c.rtt, floor, built, n.Impossible, n.Tight, c.impossible, c.tig)
		}
		if n.Impossible && n.Tight {
			t.Errorf("%s: a placement cannot be both disproved and merely doubted", c.name)
		}
		if (n.Impossible || n.Tight) && n.Why == "" {
			t.Errorf("%s: a verdict against a placement has to say why", c.name)
		}
	}
}

// The expectation must never fall below the proof, or a hop could be accused
// of beating a built route while light itself allowed it comfortably.
func TestTheExpectationNeverFallsBelowTheFloor(t *testing.T) {
	m := &Module{}
	nodes := []Node{{Located: true, Lat: 51.5072, Lon: -0.1276, RTT: 400, IPs: []string{"1.2.3.4"}}}
	m.checkPlausible(nodes, Home{Lat: 39.1836, Lon: -96.5717, OK: true})
	n := nodes[0]
	if n.ExpectedMS < n.FloorMS {
		t.Fatalf("expectation %.1f ms is below the floor %.1f ms", n.ExpectedMS, n.FloorMS)
	}
	if n.ExpectedKM < n.DistanceKM {
		t.Fatalf("expected distance %.0f km is below the measured %.0f km", n.ExpectedKM, n.DistanceKM)
	}
}

// Every hop gets the distance and both thresholds, whatever the verdict, so a
// reader can check the arithmetic rather than take the label on trust.
func TestPlausibilityShowsItsWorking(t *testing.T) {
	m := &Module{}
	nodes := []Node{{Located: true, Lat: 51.5072, Lon: -0.1276, RTT: 400, IPs: []string{"1.2.3.4"}}}
	m.checkPlausible(nodes, Home{Lat: 39.1836, Lon: -96.5717, OK: true})
	n := nodes[0]
	if n.DistanceKM < 6000 || n.DistanceKM > 8000 {
		t.Errorf("distance looks wrong: %v km", n.DistanceKM)
	}
	if n.FloorMS <= 0 || n.ExpectedMS <= 0 {
		t.Errorf("both thresholds should be recorded, got floor %v expected %v", n.FloorMS, n.ExpectedMS)
	}
}

// Every router holds a packet for a moment before passing it on, and twenty
// of them are worth counting. A hop further along the route needs more time
// than the same distance would need one hop out.
func TestHopsOfTheirOwnCostTime(t *testing.T) {
	m := &Module{}
	home := Home{Lat: 39.1836, Lon: -96.5717, OK: true}
	near := []Node{{Located: true, Lat: 51.5072, Lon: -0.1276, RTT: 400, Index: 1, IPs: []string{"a"}}}
	far := []Node{{Located: true, Lat: 51.5072, Lon: -0.1276, RTT: 400, Index: 20, IPs: []string{"b"}}}
	m.checkPlausible(near, home)
	m.checkPlausible(far, home)
	if !(far[0].ExpectedMS > near[0].ExpectedMS) {
		t.Fatalf("twenty hops should cost more than one: %.2f vs %.2f", far[0].ExpectedMS, near[0].ExpectedMS)
	}
}
