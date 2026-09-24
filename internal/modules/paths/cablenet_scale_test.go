package paths

import (
	"math"
	"os"
	"runtime"
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

// Parallel runs a few kilometres apart -- a road traced twice, a route with
// its return leg -- must not be cross-linked point by point.
func TestBuildNetParallelRunsStaySparse(t *testing.T) {
	a := denseRun(4000, 10, 20, 0.004, 0.004)
	b := denseRun(4000, 10.02, 20.02, 0.004, 0.004)
	c := denseRun(4000, 10.04, 20.04, 0.004, 0.004)
	n := buildNet(Cable{Name: "p", Legs: [][]LatLon{a, b, c}})
	edges := 0
	for _, adj := range n.Adj {
		edges += len(adj)
	}
	// Along-run edges are two per point; between runs, at most two per run
	// end per other run.
	if limit := 2*len(n.Pts) + 2*2*3*3; edges > limit {
		t.Fatalf("%d edges for %d points; parallel runs were cross-linked", edges, len(n.Pts))
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
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	nets := make([]cableNet, 0, len(routes))
	for _, r := range routes {
		nets = append(nets, buildNet(r))
	}
	el := time.Since(start)
	runtime.GC()
	runtime.ReadMemStats(&after)
	pts, edges := 0, 0
	for _, n := range nets {
		pts += len(n.Pts)
		for _, adj := range n.Adj {
			edges += len(adj)
		}
	}
	held := int64(after.HeapInuse) - int64(before.HeapInuse)
	t.Logf("%d routes, %d points, %d edges, %s, %d MB held", len(routes), pts, edges, el.Round(time.Millisecond), held>>20)
	if el > 10*time.Second {
		t.Fatalf("too slow: %s", el)
	}
	if held > 64<<20 {
		t.Fatalf("holding %d MB for the land routes", held>>20)
	}
}

func TestChainRunsJoinsPiecesEitherWayRound(t *testing.T) {
	// A road drawn in four pieces: forwards, forwards, then one piece drawn
	// back to front, then a piece leading in before the first.
	p := func(lat, lon float64) LatLon { return LatLon{Lat: lat, Lon: lon} }
	a := []LatLon{p(0, 0), p(0, 0.1), p(0, 0.2)}
	b := []LatLon{p(0, 0.2), p(0, 0.3)}
	c := []LatLon{p(0, 0.5), p(0, 0.4), p(0, 0.3)} // reversed
	d := []LatLon{p(0, -0.1), p(0, 0)}             // leads into a
	far := []LatLon{p(5, 5), p(5, 5.1)}
	out := chainRuns([][]LatLon{a, b, c, d, far})
	if len(out) != 2 {
		t.Fatalf("want 2 runs, got %d", len(out))
	}
	var long []LatLon
	for _, r := range out {
		if len(r) > len(long) {
			long = r
		}
	}
	if len(long) != 7 {
		t.Fatalf("chained run has %d points, want 7: %v", len(long), long)
	}
	for i := 1; i < len(long); i++ {
		if step := long[i].Lon - long[i-1].Lon; math.Abs(step-0.1) > 1e-9 && math.Abs(step+0.1) > 1e-9 {
			t.Fatalf("chain is not monotonic at %d: %v", i, long)
		}
	}
}
