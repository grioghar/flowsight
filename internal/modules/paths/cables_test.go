package paths

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
)

// A short, made-up cable running due east along the equator, so the distances
// are easy to reason about.
func fakeCables() []Cable {
	run := []LatLon{{0, 0}, {0, 10}, {0, 20}, {0, 30}}
	long := []LatLon{{0, 0}, {20, 5}, {40, 10}, {20, 20}, {0, 30}} // same ends, far longer
	mk := func(name string, pts []LatLon) Cable {
		return Cable{ID: name, Name: name, Legs: [][]LatLon{pts}, KM: runLengthKM(pts)}
	}
	return []Cable{mk("Direct", run), mk("Scenic", long)}
}

func TestCandidatesNeedBothEndsNearby(t *testing.T) {
	cs := fakeCables()
	// Both ends sit on the cables.
	got := candidates(cs, 0, 0, 0, 30, 400, 0)
	if len(got) != 2 {
		t.Fatalf("both cables serve both ends; got %d: %+v", len(got), got)
	}
	// The shorter one is offered first.
	if got[0].Name != "Direct" {
		t.Errorf("the shorter route should come first, got %q", got[0].Name)
	}
	// One end nowhere near anything.
	if n := len(candidates(cs, 0, 0, 80, 170, 400, 0)); n != 0 {
		t.Errorf("a leg ending nowhere near a cable has no candidates, got %d", n)
	}
}

// The only part of this that is not inference: a cable cannot carry a round
// trip faster than twice its length divided by the speed of light in fibre.
func TestLatencyDiscardsCablesThatAreTooLong(t *testing.T) {
	cs := fakeCables()
	all := candidates(cs, 0, 0, 0, 30, 400, 0)
	var direct, scenic Candidate
	for _, c := range all {
		if c.Name == "Direct" {
			direct = c
		} else {
			scenic = c
		}
	}
	if scenic.FloorMS <= direct.FloorMS {
		t.Fatalf("the scenic route is longer and must have a higher floor: %v vs %v", scenic.FloorMS, direct.FloorMS)
	}
	// A latency between the two floors leaves only the short one standing.
	between := (direct.FloorMS + scenic.FloorMS) / 2
	got := candidates(cs, 0, 0, 0, 30, 400, between)
	if len(got) != 1 || got[0].Name != "Direct" {
		t.Errorf("a round trip of %.1f ms rules the scenic route out; got %+v", between, got)
	}
	// Faster than either is impossible for both.
	if n := len(candidates(cs, 0, 0, 0, 30, 400, direct.FloorMS/2)); n != 0 {
		t.Errorf("a round trip below every floor leaves no candidate, got %d", n)
	}
	// With no measurement, nothing can be ruled out.
	if n := len(candidates(cs, 0, 0, 0, 30, 400, 0)); n != 2 {
		t.Errorf("without a measurement both stand, got %d", n)
	}
}

func TestRunLengthMatchesGreatCircle(t *testing.T) {
	// Three degrees of longitude at the equator, in one hop and in three.
	one := runLengthKM([]LatLon{{0, 0}, {0, 3}})
	three := runLengthKM([]LatLon{{0, 0}, {0, 1}, {0, 2}, {0, 3}})
	if math.Abs(one-three) > 1 {
		t.Errorf("splitting a straight run must not change its length: %v vs %v", one, three)
	}
	if one < 300 || one > 350 {
		t.Errorf("three degrees at the equator is about 334 km, got %v", one)
	}
}

// The published file is GeoJSON, which orders coordinates longitude first.
// Reading them the other way round puts every cable in the wrong hemisphere.
func TestLoadCablesReadsLonLatOrder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.json")
	doc := map[string]any{"features": []any{map[string]any{
		"properties": map[string]any{"id": "x", "name": "Test"},
		"geometry": map[string]any{"type": "MultiLineString",
			"coordinates": [][][]float64{{{-96.57, 39.18}, {-0.13, 51.51}}}},
	}}}
	b, _ := json.Marshal(doc)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	cs, err := loadCables(path)
	if err != nil || len(cs) != 1 {
		t.Fatalf("load: %v, %d cables", err, len(cs))
	}
	p := cs[0].Legs[0][0]
	if math.Abs(p.Lat-39.18) > 0.01 || math.Abs(p.Lon-(-96.57)) > 0.01 {
		t.Errorf("coordinates read in the wrong order: got lat %v lon %v", p.Lat, p.Lon)
	}
	// Kansas to London is roughly 7,000 km.
	if cs[0].KM < 6500 || cs[0].KM > 7500 {
		t.Errorf("length looks wrong: %v km", cs[0].KM)
	}
}

// A floor is only worth having if the distance behind it is one a packet
// could actually be asked to cover. These are laid out as a cable would be:
// out to the coast, across, and ashore.
func TestCableRouteMeasuresTheWholeJourney(t *testing.T) {
	// A crossing whose two ends are inland, so the runs ashore matter.
	cables := []Cable{{Name: "Test Atlantic", Legs: [][]LatLon{{
		{Lat: 40.7, Lon: -74.0}, // New York
		{Lat: 45.0, Lon: -50.0},
		{Lat: 50.0, Lon: -20.0},
		{Lat: 51.5, Lon: -5.0}, // Cornwall
	}}}}
	r := cableRouteKM(netsOf(cables), 40.7, -74.0, 51.5, -5.0, 3200)
	if !r.OK {
		t.Fatal("a cable joining both ends was not found")
	}
	straight := greatCircleKM(40.7, -74.0, 51.5, -5.0)
	if r.KM <= straight {
		t.Errorf("a cable route cannot be shorter than the straight line: %.0f vs %.0f", r.KM, straight)
	}
	if r.Name != "Test Atlantic" {
		t.Errorf("the route should name its cable, got %q", r.Name)
	}
	// The distance ashore at each end must be counted, or a cable landing a
	// hundred kilometres away looks free.
	inland := cableRouteKM(netsOf(cables), 41.5, -74.5, 51.5, -5.0, 3200)
	if !inland.OK || inland.KM <= r.KM {
		t.Errorf("moving an endpoint inland should lengthen the route: %.0f vs %.0f", inland.KM, r.KM)
	}
}

// Two places a cable happens to pass must not be joined by it when the trip
// is plainly overland, or a coastal cable would accuse perfectly good
// placements of being impossible.
func TestShortTripsIgnoreTheCables(t *testing.T) {
	m := withCables([]Cable{{Name: "Coastal", Legs: [][]LatLon{{
		{Lat: 34.0, Lon: -118.2}, {Lat: 30.0, Lon: -125.0}, {Lat: 37.8, Lon: -122.4},
	}}}})
	// Los Angeles to San Francisco: about 560 km, and the cable goes out to
	// sea and back.
	km, via := m.pathKM(34.0, -118.2, 37.8, -122.4)
	if via != "" {
		t.Errorf("a short overland trip should not be measured along a cable, got %q", via)
	}
	straight := greatCircleKM(34.0, -118.2, 37.8, -122.4)
	if math.Abs(km-straight) > 0.001 {
		t.Errorf("expected the straight line, got %.0f vs %.0f", km, straight)
	}
}

// A cable that wanders far enough is describing a different journey, not a
// longer version of this one, and must not set the bound.
func TestAbsurdlyLongCableRoutesAreRejected(t *testing.T) {
	m := withCables([]Cable{{Name: "The Long Way", Legs: [][]LatLon{{
		{Lat: 51.5, Lon: -0.1},  // London
		{Lat: -34.0, Lon: 18.4}, // ... via Cape Town
		{Lat: -33.9, Lon: 151.2},
		{Lat: 40.7, Lon: -74.0}, // ... to New York
	}}}})
	straight := greatCircleKM(51.5, -0.1, 40.7, -74.0)
	km, via := m.pathKM(51.5, -0.1, 40.7, -74.0)
	if via != "" {
		t.Errorf("a route round the world should be rejected, got %q at %.0f km", via, km)
	}
	if math.Abs(km-straight) > 0.001 {
		t.Errorf("should fall back to the straight line, got %.0f", km)
	}
}

// The bound must never drop below the straight line, whatever the cables say.
func TestTheFloorIsNeverLowered(t *testing.T) {
	m := withCables([]Cable{{Name: "Impossible Shortcut", Legs: [][]LatLon{{
		{Lat: 51.5, Lon: -0.1}, {Lat: 40.7, Lon: -74.0},
	}}}})
	straight := greatCircleKM(51.5, -0.1, 40.7, -74.0)
	km, _ := m.pathKM(51.5, -0.1, 40.7, -74.0)
	if km < straight-0.001 {
		t.Fatalf("the bound went below the straight line: %.0f < %.0f", km, straight)
	}
}

// The origin that found this bug: a gateway in Kansas, fifteen hundred
// kilometres from salt water. Requiring a cable to pass near both ends
// rejected every transatlantic crossing it makes, and nothing was measured
// along a cable at all. The run overland is part of the journey.
func TestAnInlandOriginStillReachesTheCables(t *testing.T) {
	atlantic := []Cable{{Name: "Test Atlantic", Legs: [][]LatLon{{
		{Lat: 40.7, Lon: -74.0}, // New York
		{Lat: 47.0, Lon: -45.0},
		{Lat: 50.5, Lon: -10.0},
		{Lat: 50.1, Lon: -5.5}, // Cornwall
	}}}}
	m := withCables(atlantic)
	// Manhattan, Kansas to London.
	km, via := m.pathKM(39.1836, -96.5717, 51.5072, -0.1276)
	if via == "" {
		t.Fatalf("an inland origin found no cable route; got %.0f km by the straight line", km)
	}
	straight := greatCircleKM(39.1836, -96.5717, 51.5072, -0.1276)
	if km <= straight {
		t.Errorf("the cable route should be longer than the straight line: %.0f vs %.0f", km, straight)
	}
	// And still a believable journey, not a trip round the world.
	if km > straight*1.5 {
		t.Errorf("route implausibly long: %.0f km against a straight line of %.0f", km, straight)
	}
}

// The run ashore is a straight line, and a straight line does not know about
// water. Without a check on how much of the journey is actually on the cable,
// the search joins two enormous imaginary overland legs to a short local
// cable and calls it the shortest way -- it picked Greenland Connect and a
// festoon off Colombia for crossings out of Kansas.
func TestAShortLocalCableCannotStandInForACrossing(t *testing.T) {
	decoy := Cable{Name: "Greenland Connect", Legs: [][]LatLon{{
		{Lat: 64.2, Lon: -51.7}, {Lat: 65.6, Lon: -37.6}, // a few hundred km
	}}}
	real := Cable{Name: "Real Atlantic", Legs: [][]LatLon{{
		{Lat: 40.7, Lon: -74.0}, {Lat: 47.0, Lon: -45.0},
		{Lat: 50.5, Lon: -10.0}, {Lat: 50.1, Lon: -5.5},
	}}}
	// The decoy alone must not be accepted for a Kansas-to-London trip.
	m := withCables([]Cable{decoy})
	if km, via := m.pathKM(39.1836, -96.5717, 51.5072, -0.1276); via != "" {
		t.Errorf("a short Arctic cable stood in for an Atlantic crossing: %q at %.0f km", via, km)
	}
	// With a real trunk present, that is the one chosen.
	m = withCables([]Cable{decoy, real})
	km, via := m.pathKM(39.1836, -96.5717, 51.5072, -0.1276)
	if via != "Real Atlantic" {
		t.Errorf("expected the trunk, got %q at %.0f km", via, km)
	}
}

// netsOf and withCables mirror what the module does when cables load: a cable
// is stitched into one connected system before anything searches it.
func netsOf(cables []Cable) []cableNet {
	out := make([]cableNet, 0, len(cables))
	for _, c := range cables {
		out = append(out, buildNet(c))
	}
	return out
}

func withCables(cables []Cable) *Module {
	return &Module{cables: cables, nets: netsOf(cables)}
}

// The bug this was written for. A cable is published as a set of runs --
// trans-Pacific systems come as five or seven -- and searching inside a
// single run could never get from the American landing to the Asian one. The
// Atlantic worked, because those cables are often a single run, so the fault
// looked like a tuning problem for months of ocean.
func TestACableSplitIntoRunsIsStillOneCable(t *testing.T) {
	// The same crossing, given as three runs that meet end to end.
	split := Cable{Name: "Split Pacific", Legs: [][]LatLon{
		{{Lat: 34.0, Lon: -118.2}, {Lat: 30.0, Lon: -140.0}},
		{{Lat: 30.0, Lon: -140.0}, {Lat: 25.0, Lon: 170.0}},
		{{Lat: 25.0, Lon: 170.0}, {Lat: 35.6, Lon: 139.6}},
	}}
	net := buildNet(split)
	ia, _ := net.nearestPoint(34.0, -118.2)
	ib, _ := net.nearestPoint(35.6, 139.6)
	km, path := net.shortest(ia, ib)
	if path == nil {
		t.Fatal("no path across a cable whose runs meet end to end")
	}
	if km < 9000 {
		t.Errorf("the crossing should span the Pacific, got %.0f km", km)
	}
	if len(path) < 4 {
		t.Errorf("the path should pass through every run, got %d points", len(path))
	}

	// And end to end, an inland origin reaches Tokyo along it.
	m := withCables([]Cable{split})
	total, via := m.pathKM(39.1836, -96.5717, 35.6762, 139.6503)
	if via != "Split Pacific" {
		t.Fatalf("an inland origin found no Pacific crossing, got %q at %.0f km", via, total)
	}
}

// Runs that do not meet are not one system, and must not be joined across
// open water as though they were.
func TestUnconnectedRunsAreNotJoined(t *testing.T) {
	apart := Cable{Name: "Two Unrelated Pieces", Legs: [][]LatLon{
		{{Lat: 34.0, Lon: -118.2}, {Lat: 33.0, Lon: -120.0}},
		{{Lat: 35.6, Lon: 139.6}, {Lat: 34.0, Lon: 138.0}},
	}}
	net := buildNet(apart)
	ia, _ := net.nearestPoint(34.0, -118.2)
	ib, _ := net.nearestPoint(35.6, 139.6)
	if _, path := net.shortest(ia, ib); path != nil {
		t.Error("two pieces thousands of kilometres apart were treated as one cable")
	}
}

// Three cables arrive from the published map with their punctuation mangled:
// UTF-8 that was read as Latin-1 somewhere upstream and encoded again. A
// reader who sees a name like that reasonably doubts the numbers beside it.
func TestMangledCableNamesAreRepaired(t *testing.T) {
	cases := []struct{ got, want string }{
		{"Staâ\u0080\u0099Oâ\u0080\u0099Nuk", "Sta’O’Nuk"},
		{"Sharm El Sheikhâ\u0080\u0093Taba", "Sharm El Sheikh–Taba"},
		{"Sir Abu Nuâ\u0080\u0099ayr Cable", "Sir Abu Nu’ayr Cable"},
	}
	for _, c := range cases {
		if out := repairMojibake(c.got); out != c.want {
			t.Errorf("repair(%q) = %q, want %q", c.got, out, c.want)
		}
	}
	// Names that are already right, or that were never this kind of damage,
	// must come back untouched.
	for _, ok := range []string{
		"Southern Cross NEXT", "Asia Africa Europe-1 (AAE-1)",
		"Sta’O’Nuk", // already repaired
		"東京ケーブル",    // never a Latin-1 round trip
		"", "2Africa",
	} {
		if out := repairMojibake(ok); out != ok {
			t.Errorf("repair(%q) changed it to %q", ok, out)
		}
	}
}
