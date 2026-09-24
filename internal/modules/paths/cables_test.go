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
