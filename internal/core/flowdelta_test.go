package core

import "testing"

func TestFlowDeltaSplitsGrowthAndSeesOnlyRealResets(t *testing.T) {
	in, out := flowDelta(600, 400, 550, 550)
	if in+out != 100 || in != 50 || out != 50 {
		t.Fatalf("growth should be 100 split by the current mix: %d %d", in, out)
	}
	if in, out := flowDelta(600, 400, 600, 400); in != 0 || out != 0 {
		t.Fatalf("no growth: %d %d", in, out)
	}
	if in, out := flowDelta(600, 400, 10, 5); in != 10 || out != 5 {
		t.Fatalf("reset should credit the new counters: %d %d", in, out)
	}
	if in, out := flowDelta(0, 0, 30, 70); in != 30 || out != 70 {
		t.Fatalf("first sighting: %d %d", in, out)
	}
}
