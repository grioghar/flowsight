package paths

import (
	"math"
	"os"
	"testing"
	"time"
)

// A road-traced run: many points a few hundred metres apart, gently curving.
func denseRun(n int, lat0, lon0, dLat, dLon float64) []LatLon {
	run := make([]LatLon, n)
	for i := range run {
		f := float64(i)
		run[i] = LatLon{Lat: lat0 + f*dLat + 0.002*math.Sin(f/40), Lon: lon0 + f*dLon}
	}
	return run
}

func runKM(run []LatLon) float64 {
	km := 0.0
	for i := 1; i < len(run); i++ {
		km += greatCircleKM(run[i-1].Lat, run[i-1].Lon, run[i].Lat, run[i].Lon)
	}
	return km
}

func TestThinRunKeepsLength(t *testing.T) {
	run := denseRun(6000, -1.3, 36.8, 0.003, 0.004) // Nairobi, heading north-east
	thin := thinRun(run, thinKM)
	if len(thin) >= len(run)/10 {
		t.Fatalf("thinning left %d of %d points", len(thin), len(run))
	}
	full, kept := runKM(run), runKM(thin)
	if diff := math.Abs(full-kept) / full; diff > 0.005 {
		t.Fatalf("thinning changed the length by %.2f%% (%.0f -> %.0f km)", diff*100, full, kept)
	}
	if thin[0] != run[0] || thin[len(thin)-1] != run[len(run)-1] {
		t.Fatal("thinning dropped an end")
	}
}

func TestBuildNetJoinsDenseRunsQuickly(t *testing.T) {
	// Two long runs that meet end to start, plus one that never comes close.
	a := denseRun(8000, -1.3, 36.8, 0.003, 0.004)
	last := a[len(a)-1]
	b := denseRun(8000, last.Lat+0.1, last.Lon+0.1, 0.003, -0.004)
	far := denseRun(8000, 40, -100, 0.003, 0.004)
	start := time.Now()
	n := buildNet(Cable{Name: "t", Legs: [][]LatLon{a, b, far}})
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("buildNet took %s on 24k points", el)
	}
	ia, _ := n.nearestPoint(a[0].Lat, a[0].Lon)
	ib, _ := n.nearestPoint(b[len(b)-1].Lat, b[len(b)-1].Lon)
	km, path := n.shortest(ia, ib)
	if path == nil {
		t.Fatal("runs that meet were not joined")
	}
	want := runKM(a) + runKM(b)
	if math.Abs(km-want)/want > 0.02 {
		t.Fatalf("along-cable distance %.0f km, want about %.0f", km, want)
	}
	ifar, _ := n.nearestPoint(far[0].Lat, far[0].Lon)
	if _, p := n.shortest(ia, ifar); p != nil {
		t.Fatal("a run on another continent was joined")
	}
}

func TestAfTerFibreBuildsInTime(t *testing.T) {
	p := os.Getenv("FLOWSIGHT_AFTERFIBRE")
	if p == "" {
		t.Skip("set FLOWSIGHT_AFTERFIBRE to the geojson to run")
	}
	routes, err := loadCables(p)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	pts := 0
	for _, r := range routes {
		pts += len(buildNet(r).Pts)
	}
	el := time.Since(start)
	t.Logf("%d routes, %d points after thinning, %s", len(routes), pts, el.Round(time.Millisecond))
	if el > 10*time.Second {
		t.Fatalf("too slow: %s", el)
	}
}
