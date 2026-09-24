package paths

import (
	"math"
	"testing"
)

// A hop that answered but could not be placed sits somewhere between the two
// that could, and where its round trip falls between theirs is a reasonable
// guess at where it falls on the ground.
func TestAnAnsweringHopIsPlacedByItsTiming(t *testing.T) {
	g := buildGraph([]hopRow{
		{Dst: "9.9.9.9", Index: 1, IP: "10.0.0.1", RTT: 10},
		{Dst: "9.9.9.9", Index: 2, IP: "10.0.0.2", RTT: 30}, // answered, no coordinates
		{Dst: "9.9.9.9", Index: 3, IP: "10.0.0.3", RTT: 50},
	})
	for i := range g.Nodes {
		n := &g.Nodes[i]
		switch n.Index {
		case 1:
			n.Located, n.Lat, n.Lon, n.Source = true, 0, 0, "database"
		case 3:
			n.Located, n.Lat, n.Lon, n.Source = true, 0, 40, "database"
		}
	}
	interpolateGaps(&g)

	var mid *Node
	for i := range g.Nodes {
		if g.Nodes[i].Index == 2 {
			mid = &g.Nodes[i]
		}
	}
	if mid == nil || !mid.Located {
		t.Fatal("the hop in the middle was not placed")
	}
	if mid.Source != "between" || !mid.Inferred {
		t.Errorf("it should be marked as inferred, got source %q inferred=%v", mid.Source, mid.Inferred)
	}
	// Half the time, so about half the way: 20 degrees of the 40.
	if math.Abs(mid.Lon-20) > 1.5 {
		t.Errorf("30 ms of a 10-to-50 ms interval should land near the middle, got lon %.1f", mid.Lon)
	}
	if len(mid.Between) != 2 || mid.Between[0] != "10.0.0.1" || mid.Between[1] != "10.0.0.3" {
		t.Errorf("it should name the two it was put between, got %v", mid.Between)
	}
	if mid.BetweenHow == "" {
		t.Error("it should say what decided the spot")
	}
}

// A hop that never answered has no time to place it by. Spacing those evenly
// would be drawing routers from nothing -- there are six thousand of them on
// a real network.
func TestASilentHopIsNotPlaced(t *testing.T) {
	g := buildGraph([]hopRow{
		{Dst: "9.9.9.9", Index: 1, IP: "10.0.0.1", RTT: 10},
		{Dst: "9.9.9.9", Index: 2, IP: "", RTT: -1},
		{Dst: "9.9.9.9", Index: 3, IP: "10.0.0.3", RTT: 50},
	})
	for i := range g.Nodes {
		if g.Nodes[i].Index != 2 {
			g.Nodes[i].Located, g.Nodes[i].Source = true, "database"
		}
	}
	interpolateGaps(&g)
	for _, n := range g.Nodes {
		if n.Index == 2 && n.Located {
			t.Error("a hop that never answered was given a position")
		}
	}
}

// An inference must never become the anchor for another, or the drift
// compounds invisibly.
func TestInferredHopsAreNotUsedAsAnchors(t *testing.T) {
	g := buildGraph([]hopRow{
		{Dst: "9.9.9.9", Index: 1, IP: "10.0.0.1", RTT: 10},
		{Dst: "9.9.9.9", Index: 2, IP: "10.0.0.2", RTT: 20},
		{Dst: "9.9.9.9", Index: 3, IP: "10.0.0.3", RTT: 30},
		{Dst: "9.9.9.9", Index: 4, IP: "10.0.0.4", RTT: 40},
	})
	for i := range g.Nodes {
		n := &g.Nodes[i]
		if n.Index == 1 || n.Index == 4 {
			n.Located, n.Lat, n.Lon, n.Source = true, 0, float64(n.Index)*10, "database"
		}
	}
	interpolateGaps(&g)
	for _, n := range g.Nodes {
		if n.Index == 2 || n.Index == 3 {
			if !n.Inferred {
				t.Errorf("hop %d should have been placed by inference", n.Index)
			}
			if len(n.Between) == 2 && (n.Between[0] == "10.0.0.2" || n.Between[0] == "10.0.0.3") {
				t.Errorf("hop %d was measured from another inference: %v", n.Index, n.Between)
			}
		}
	}
}

// The path between two places is the one over the sphere, not a straight line
// through the numbers: interpolating latitude and longitude drifts off the
// route, badly near the poles and across the antimeridian.
func TestInterpolationFollowsTheGreatCircle(t *testing.T) {
	// A quarter of the way from London to Tokyo passes well north of the
	// midpoint of the two latitudes.
	lat, _ := alongGreatCircle(51.5, -0.1, 35.7, 139.7, 0.5)
	if lat < 58 {
		t.Errorf("the halfway point should arc north, got latitude %.1f", lat)
	}
	// And the ends are the ends.
	if a, b := alongGreatCircle(10, 20, 30, 40, 0); math.Abs(a-10) > 0.001 || math.Abs(b-20) > 0.001 {
		t.Errorf("f=0 should be the start, got %.3f,%.3f", a, b)
	}
	if a, b := alongGreatCircle(10, 20, 30, 40, 1); math.Abs(a-30) > 0.001 || math.Abs(b-40) > 0.001 {
		t.Errorf("f=1 should be the end, got %.3f,%.3f", a, b)
	}
}
