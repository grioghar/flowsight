package paths

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOverpassAnswerBecomesRoutesTheLoaderReads(t *testing.T) {
	raw := []byte(`{"elements":[
	 {"type":"way","id":101,"tags":{"telecom":"line","operator":"Openreach"},"geometry":[{"lat":51.5,"lon":-0.1},{"lat":51.6,"lon":-0.3},{"lat":51.7,"lon":-0.5}]},
	 {"type":"way","id":102,"tags":{"communication":"line","name":"Trunk A"},"geometry":[{"lat":52.0,"lon":0.0},{"lat":52.5,"lon":0.4}]},
	 {"type":"way","id":103,"tags":{"telecom":"line"},"geometry":[{"lat":0,"lon":0}]},
	 {"type":"node","id":9,"lat":1,"lon":1}]}`)
	gj, n, err := overpassToGeoJSON(raw)
	if err != nil || n != 2 {
		t.Fatalf("want 2 features, got %d (%v)", n, err)
	}
	dir := t.TempDir()
	f := filepath.Join(dir, "osm-test.geojson")
	if err := os.WriteFile(f, gj, 0o644); err != nil {
		t.Fatal(err)
	}
	routes, err := loadCables(f)
	if err != nil || len(routes) != 2 {
		t.Fatalf("loader read %d routes (%v)", len(routes), err)
	}
	names := map[string]bool{}
	for _, r := range routes {
		names[r.Name] = true
	}
	if !names["Openreach"] || !names["Trunk A"] {
		t.Fatalf("names lost: %v", names)
	}
	tiles := osmTiles()
	if len(tiles) < 200 || len(tiles) > 400 {
		t.Fatalf("expected a few hundred tiles, got %d", len(tiles))
	}
	for _, tl := range tiles {
		if tl.N-tl.S > 10.01 || tl.E-tl.W > 10.01 {
			t.Fatalf("tile too big: %+v", tl)
		}
	}
	if osmFile(tiles[0]) != "osm-north-america-east-p24-100.geojson" {
		t.Fatal(osmFile(tiles[0]))
	}
	if regionOf(39.18, -96.57) != "North America, east" || regionOf(37.77, -122.42) != "North America, central" || regionOf(51.5, -0.1) != "Europe, west" || boxOf(-70, 0) != "" {
		t.Fatal("regions misassigned")
	}
	if !strings.HasPrefix(boxOf(39.18, -96.57), "North America, east ") {
		t.Fatal(boxOf(39.18, -96.57))
	}
}

// A half-weight route moves the expectation halfway from the detour
// estimate towards the mapped length, and no further.
func TestSuggestiveLandRoutesCountAtHalfWeight(t *testing.T) {
	m := &Module{}
	// A mapped line that wanders: Lisbon to Warsaw by way of Rome. Long
	// enough to clear the gate below which no route is consulted.
	line := Cable{Name: "osm", Legs: [][]LatLon{{{Lat: 38.72, Lon: -9.14}, {Lat: 41.90, Lon: 12.50}, {Lat: 52.23, Lon: 21.01}}}}
	n := buildNet(line)
	n.Weight = osmWeight
	m.osmNets = []cableNet{n}
	straight := greatCircleKM(38.72, -9.14, 52.23, 21.01)
	detour := straight * m.landDetour()
	km, via := m.expectedKM(38.72, -9.14, 52.23, 21.01)
	if via != "osm" {
		t.Fatalf("the line should be used, via=%q", via)
	}
	full := m.overland(38.72, -9.14, 52.23, 21.01)
	along := full.AlongKM + full.AshoreKM*m.landDetour()
	want := along*osmWeight + detour*(1-osmWeight)
	if diff := km - want; diff > 1 || diff < -1 {
		t.Fatalf("expected %.0f km, want the half-way blend %.0f (along %.0f, detour %.0f)", km, want, along, detour)
	}
	lo, hi := along, detour
	if lo > hi {
		lo, hi = hi, lo
	}
	if km <= lo || km >= hi {
		t.Fatalf("a suggestive route is blended, not taken whole: %.0f should lie between %.0f and %.0f", km, lo, hi)
	}
	// The same line at full weight is taken as measured.
	m.osmNets = nil
	n.Weight = 1
	m.landNets = []cableNet{n}
	m.routes.reset()
	km2, _ := m.expectedKM(38.72, -9.14, 52.23, 21.01)
	if diff := km2 - along; diff > 1 || diff < -1 {
		t.Fatalf("a measured route should count in full: %.0f vs %.0f", km2, along)
	}
}

func TestPrivateURLDetection(t *testing.T) {
	if !isPrivateURL("http://192.168.1.56/api/interpreter") || !isPrivateURL("http://10.0.0.5:8080/x") {
		t.Fatal("RFC1918 hosts are private")
	}
	if isPrivateURL("https://overpass-api.de/api/interpreter") || isPrivateURL("ftp://192.168.1.1/") || isPrivateURL("http://127.0.0.1/") {
		t.Fatal("public hosts, other schemes and loopback are not the exception")
	}
}
