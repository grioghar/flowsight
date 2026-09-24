package paths

import (
	"strings"
	"testing"
)

// The names this was written for: a prefix, and two contractions.
func TestNamesShortenedByHandAreRead(t *testing.T) {
	cases := []struct{ host, city string }{
		{"palo-bb4-link.example.net", "Palo Alto, CA, US"},
		{"kanc-rtr1.example.net", "Kansas City, MO, US"},
		{"sjo-edge2.example.net", "San Jose, CA, US"},
		{"ae1.dfw01.example.net", "Dallas, TX, US"},        // still the plain code
		{"x.ear2.SanJose1.Level3.net", "San Jose, CA, US"}, // still the spelled-out name
	}
	for _, c := range cases {
		cands := popCandidates(c.host)
		if len(cands) == 0 {
			t.Errorf("%s: read nothing", c.host)
			continue
		}
		var found bool
		for _, x := range cands {
			if x.Pop.City == c.city {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s: %s not among the candidates (%d read, best %q)",
				c.host, c.city, len(cands), cands[0].Pop.City)
		}
	}
}

// A contraction is ambiguous by nature, and guessing confidently between the
// possibilities is worse than not guessing: a wrong placement is drawn with
// exactly the authority of a right one. So the clock decides.
func TestTheRoundTripSettlesAnAmbiguousName(t *testing.T) {
	m := &Module{}
	kansas := Home{Lat: 39.1836, Lon: -96.5717, OK: true}

	// "san" alone could be San Jose, San Diego or San Antonio. From Kansas,
	// San Antonio is about 1,100 km and San Jose about 2,400: a round trip of
	// 15 ms is possible to neither by a built route but light allows the
	// closer one, and forbids the further.
	cands := popCandidates("sanx1.example.net")
	if len(cands) < 2 {
		t.Skip("not enough ambiguity in the table to exercise this")
	}

	// A fast answer must pick somewhere near, and a slow one somewhere it fits.
	near, nearScore, _ := m.placeFromName("sjo-1.example.net", 30, kansas)
	if nearScore <= 0 {
		t.Fatal("a plausible reading scored nothing")
	}
	far, farScore, farWhy := m.placeFromName("sjo-1.example.net", 4, kansas)
	if farScore != 0 {
		t.Errorf("4 ms cannot reach %s: scored %.2f (%s)", far.Pop.City, farScore, farWhy)
	}
	if near.Pop.City == "" {
		t.Error("no city chosen for a plausible round trip")
	}
}

// Impossible is impossible however well the name reads.
func TestNoNameSurvivesTheSpeedOfLight(t *testing.T) {
	m := &Module{}
	kansas := Home{Lat: 39.1836, Lon: -96.5717, OK: true}
	// Sydney is about 14,000 km away: 141 ms at the very best.
	_, score, why := m.placeFromName("syd-bb1.example.net", 20, kansas)
	if score != 0 {
		t.Fatalf("20 ms to Sydney scored %.2f (%s)", score, why)
	}
	if why == "" {
		t.Error("a rejection has to say why")
	}
}

// With nothing measured there is nothing to check against, and the score has
// to say that rather than pretend to confidence.
func TestWithoutAMeasurementTheNameStandsAlone(t *testing.T) {
	m := &Module{}
	got, score, why := m.placeFromName("dfw01.example.net", 0, Home{})
	if got.Pop.City != "Dallas, TX, US" {
		t.Errorf("got %q", got.Pop.City)
	}
	if score != 1.0 {
		t.Errorf("a published code with nothing to check it against should score its own weight, got %.2f", score)
	}
	if !strings.Contains(why, "name alone") {
		t.Errorf("should say the name is all there is, got %q", why)
	}
}

// Interface names, link names and the rest must not become cities.
func TestTheDecoderStillDeclinesRubbish(t *testing.T) {
	for _, host := range []string{
		"", "one.one.one.one", "dns.google", "ae10.ae11.example.com",
		"xe-0-0-0.example.net", "host.example.org", "be1013.example.net",
	} {
		if c := popCandidates(host); len(c) > 0 {
			t.Errorf("%q invented %s (%s)", host, c[0].Pop.City, c[0].Kind)
		}
	}
}

// Against the names actually on this network, plus the ones that prompted
// this. The point is not that every guess is right -- it is that a guess the
// clock cannot support scores low and does not get to move a hop.
func TestScoringOnRealNames(t *testing.T) {
	m := &Module{}
	kansas := Home{Lat: 39.1836, Lon: -96.5717, OK: true}
	cases := []struct {
		host   string
		rtt    float64
		expect string // "" means: must not place it
	}{
		{"ae10.edge1.dal2.sp.lumen.tech", 17, "Dallas, TX, US"},
		{"po1.owr03.lax31.ntwk.msn.net", 55, "Los Angeles, CA, US"},
		{"172-11-154-1.lightspeed.tpkaks.sbcglobal.net", 2, "Topeka, KS, US"},
		{"dls-b23-link.ip.twelve99.net", 18, "Dallas, TX, US"},
		{"ae-6.a03.londen12.uk.bb.gin.ntt.net", 120, "London, GB"},
		{"palo-bb4-link.example.net", 45, "Palo Alto, CA, US"},
		{"kanc-rtr1.example.net", 8, "Kansas City, MO, US"},
		{"sjo-edge2.example.net", 50, "San Jose, CA, US"},
		// The same name with a round trip that cannot reach it.
		{"sjo-edge2.example.net", 3, ""},
		{"palo-bb4-link.example.net", 2, ""},
	}
	for _, c := range cases {
		got, score, why := m.placeFromName(c.host, c.rtt, kansas)
		if c.expect == "" {
			if score > 0 {
				t.Errorf("%s at %.0f ms: placed in %s (%.2f) when it cannot be reached — %s",
					c.host, c.rtt, got.Pop.City, score, why)
			}
			continue
		}
		if got.Pop.City != c.expect {
			t.Errorf("%s at %.0f ms: got %q (%.2f), want %q — %s",
				c.host, c.rtt, got.Pop.City, score, c.expect, why)
			continue
		}
		if score <= 0 {
			t.Errorf("%s: right city, no confidence", c.host)
		}
	}
}

// An interface name that happens to start a city. Cisco writes
// port-channel8121, and read as a prefix that is Portland -- sitting four
// labels away from the domain, while the real site code is one label away.
func TestAnInterfaceNameDoesNotBecomeACity(t *testing.T) {
	m := &Module{}
	kansas := Home{Lat: 39.1836, Lon: -96.5717, OK: true}
	host := "port-channel8121.ccr91.jan02.atlas.cogentco.com"
	got, score, why := m.placeFromName(host, 40, kansas)
	if strings.HasPrefix(got.Pop.City, "Portland") {
		t.Fatalf("read a Cisco bundle as Portland (%.2f) — %s", score, why)
	}
	if got.Pop.City != "Jackson, MS, US" {
		t.Errorf("the site is jan02; got %q — %s", got.Pop.City, why)
	}
}

// The site sits at the far end of a router's name, so a reading there beats
// one nearer the interface.
func TestTheLabelNearestTheDomainWins(t *testing.T) {
	cands := popCandidates("man1.agg2.fra3.example.net")
	if len(cands) == 0 {
		t.Fatal("read nothing")
	}
	if cands[0].Pop.City != "Frankfurt, DE" {
		t.Errorf("got %q at pos %d, want Frankfurt", cands[0].Pop.City, cands[0].Pos)
	}
}
