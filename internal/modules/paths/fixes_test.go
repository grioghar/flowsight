package paths

import (
	"testing"

	"github.com/grioghar/flowsight/internal/core"
)

func TestCorrectionsAreLearnedAppliedAndKept(t *testing.T) {
	st, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	m := &Module{ctx: &core.Context{Store: st}}
	m.fixes.load(st)
	m.fixes.on = true
	cam := [2]float64{42.3649, -71.0888} // the registrant's address
	seoul := [2]float64{37.5665, 126.978}
	tokyo := [2]float64{35.6762, 139.6503}
	d := &Detail{ASN: "20940", Prefix: "104.119.40.0/21", Name: "ae10.r02.rio01.icn.netarch.akamai.com"}

	// One router of the prefix is shown to be in Seoul.
	m.learn("104.119.40.55", d, d.Name, cam[0], cam[1], "Cambridge, MA, US", seoul[0], seoul[1], "Seoul", "", "KR", 10000)
	c := m.correctionFor("104.119.40.200") // a sibling with no site in its name
	if c == nil || c.City != "Seoul" || c.By != d.Name {
		t.Fatalf("sibling not corrected: %+v", c)
	}
	if m.correctionFor("104.119.48.1") != nil {
		t.Fatal("an address outside the prefix was corrected")
	}
	// One contradiction is not yet a pattern.
	if m.distrusted(20940, cam[0], cam[1]) != nil {
		t.Fatal("distrusted after a single contradiction")
	}
	// A second router of the same network, another block, another city.
	m.learn("23.56.131.47", &Detail{ASN: "20940", Prefix: "23.56.128.0/19", Name: "tyo"}, "tyo", cam[0], cam[1], "Cambridge, MA, US", tokyo[0], tokyo[1], "Tokyo", "", "JP", 10800)
	x := m.distrusted(20940, cam[0]+0.01, cam[1]-0.01) // same spot to within the cell
	if x == nil || x.Count != 2 {
		t.Fatalf("coordinate not distrusted: %+v", x)
	}
	if m.distrusted(15169, cam[0], cam[1]) != nil {
		t.Fatal("another network's blocks at the same spot were distrusted")
	}
	cs, ds := m.fixCounts()
	if cs != 2 || ds != 1 {
		t.Fatalf("counts %d/%d, want 2/1", cs, ds)
	}

	// Survives a restart.
	m2 := &Module{ctx: &core.Context{Store: st}}
	m2.fixes.load(st)
	m2.fixes.on = true
	if m2.correctionFor("104.119.40.200") == nil || m2.distrusted(20940, cam[0], cam[1]) == nil {
		t.Fatal("learned items were not kept in the store")
	}

	// Can be forgotten.
	m2.fixes.mu.Lock()
	delete(m2.fixes.s.Corrections, "104.119.40.0/21")
	delete(m2.fixes.nets, "104.119.40.0/21")
	m2.fixes.mu.Unlock()
	if m2.correctionFor("104.119.40.200") != nil {
		t.Fatal("a forgotten correction still applies")
	}

	// Off means nothing is learned or applied.
	m2.fixes.on = false
	if m2.distrusted(20940, cam[0], cam[1]) != nil {
		t.Fatal("applied while off")
	}
}

func TestPrefixForFallsBackToRoutableBlocks(t *testing.T) {
	if p := prefixFor("104.119.40.55", "104.119.40.0/21"); p != "104.119.40.0/21" {
		t.Fatal(p)
	}
	if p := prefixFor("104.119.40.55", ""); p != "104.119.40.0/24" {
		t.Fatal(p)
	}
	if p := prefixFor("2600:1700:3ab0:f43f::1", ""); p != "2600:1700:3ab0::/48" {
		t.Fatal(p)
	}
}
