package paths

import "testing"

func TestRouteMemoAnswersOnceAndForgetsOnReset(t *testing.T) {
	var memo routeMemo
	nets := []cableNet{buildNet(Cable{Name: "t", Legs: [][]LatLon{{{Lat: 40, Lon: -74}, {Lat: 51, Lon: -1}}}})}
	a := memo.memoRoute('c', nets, 40.2, -74.1, 51.1, -0.9)
	b := memo.memoRoute('c', nets, 40.1, -74.1, 51.1, -0.9) // same half-degree cells
	if !a.OK || a.KM != b.KM {
		t.Fatalf("second ask should be the memo's answer: %+v vs %+v", a, b)
	}
	if n := len(memo.m); n != 1 {
		t.Fatalf("one key expected, %d stored", n)
	}
	if memo.key('c', 1, 2, 3, 4) == memo.key('l', 1, 2, 3, 4) {
		t.Fatal("cable and land answers share a key")
	}
	memo.reset()
	if memo.m != nil {
		t.Fatal("reset kept answers")
	}
	for i := 0; i < routeMemoMax+5; i++ {
		memo.put(memo.key('c', float64(i%180), float64(i/180), 0, 0), cableRoute{})
	}
	if len(memo.m) > routeMemoMax {
		t.Fatalf("memo grew to %d", len(memo.m))
	}
}
