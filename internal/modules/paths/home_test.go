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
		{"well under the floor is disproved", floor * 0.5, true, false},
		// A hair under is not disproved, because the origin is not known to a
		// hair. See TestAMarginThinnerThanTheOriginsOwnErrorIsNotAProof.
		{"a hair under is inside the origin's own error", floor * 0.99, false, true},
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

// Every floor is measured from the origin, and unless it was declared the
// origin came from the address database, which is routinely tens of
// kilometres out. Calling a placement impossible on a margin thinner than
// that claims a precision nobody has: the tightest such verdict on a real
// network missed its floor by 0.2 ms over 2,000 km, which is one per cent,
// and one per cent of the origin is a rounding error.
func TestAMarginThinnerThanTheOriginsOwnErrorIsNotAProof(t *testing.T) {
	m := &Module{}
	detected := Home{Lat: 39.1836, Lon: -96.5717, OK: true, Source: "public address"}
	declared := Home{Lat: 39.1836, Lon: -96.5717, OK: true, Source: "declared"}
	// Montreal: about 2,000 km, so a floor near 20 ms.
	at := func(rtt float64) []Node {
		return []Node{{Located: true, Lat: 45.5017, Lon: -73.5673, RTT: rtt, IPs: []string{"1.2.3.4"}}}
	}
	km := greatCircleKM(39.1836, -96.5717, 45.5017, -73.5673)
	floor := floorMS(km)

	// Missing by a fifth of a millisecond over two thousand kilometres.
	n := at(floor - 0.2)
	m.checkPlausible(n, detected)
	if n[0].Impossible {
		t.Errorf("a %.1f%% shortfall was called impossible from an origin that is only a guess",
			100*0.2/floor)
	}
	if !n[0].Tight {
		t.Error("it should still be doubted, just not disproved")
	}
	if n[0].SlackKM <= 0 {
		t.Error("the allowance should be recorded so a reader can see it was made")
	}

	// Declared, the reader has said where they are and gets no allowance.
	n = at(floor - 0.2)
	m.checkPlausible(n, declared)
	if !n[0].Impossible {
		t.Error("a declared origin should be taken at its word")
	}
	if n[0].SlackKM != 0 {
		t.Errorf("a declared origin needs no allowance, got %v km", n[0].SlackKM)
	}

	// And a shortfall far larger than any plausible origin error still stands.
	n = at(floor * 0.5)
	m.checkPlausible(n, detected)
	if !n[0].Impossible {
		t.Error("halving the floor is not an origin error")
	}
}
