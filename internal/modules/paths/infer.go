package paths

// Reading a place out of a router's name, and then checking it against the
// clock.
//
// The first version of this matched a fixed list of codes. That gets dfw01
// and Dallas3 and misses palo-bb4, kanc and sjo -- which are Palo Alto,
// Kansas City and San Jose, written the way an engineer writes a name when
// the field is short: a prefix, or the front of each word run together.
// Generating those forms from the city list is easy.
//
// The difficulty is that generating them makes the answers ambiguous. "san"
// is three cities, "kan" could be Kansas City or Kanpur, and a decoder that
// guesses between them confidently is worse than one that does not guess at
// all, because a wrong placement is drawn with the same authority as a right
// one.
//
// So nothing is chosen on the text alone. Every reading is a candidate, and
// the candidates are settled against the measurement: a round trip of 19 ms
// cannot have reached a city 8,000 km away, whatever the name suggests, and
// one of 140 ms has no business claiming a city down the road. The name
// proposes and the clock disposes. What comes out carries a score and the
// reason for it, so a reader can see which of the two did the work.

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// popMatch is one possible reading of a label.
type popMatch struct {
	Code string
	Pop  pop
	Kind string  // how the text matched
	Base float64 // how much that kind of match is worth on its own
	// Pos is how far from the domain the label sat, counting from nought. A
	// name is built interface-first, so the site is at the far end: in
	// port-channel8121.ccr91.jan02.atlas.cogentco.com the site is jan, and
	// "port" is a Cisco bundle that happens to start Portland.
	Pos int
}

// How much each kind of textual match is worth before the clock is consulted.
// An exact code is what operators actually publish; a contraction is someone
// abbreviating in a field that was too short, and is a guess until something
// else supports it.
var matchWeight = map[string]float64{
	"code":        1.00, // dfw, lax -- in the published list
	"name":        0.95, // Dallas3, SanJose1 -- spelled out
	"prefix":      0.75, // palo -> Palo Alto
	"contraction": 0.70, // sjo -> San Jose, kanc -> Kansas City
}

var wordSplit = regexp.MustCompile(`[^a-z]+`)

// nearness discounts a reading for every label it sits away from the domain.
// Router names are written interface first and site last, so a match at the
// far end of the name is the one to believe.
func nearness(pos int) float64 {
	f := 1 - 0.12*float64(pos)
	if f < 0.4 {
		return 0.4
	}
	return f
}

// inferred holds every form a city's name can be shortened to, built once
// from the code table so the two can never disagree about where a place is.
var inferred = buildInferred()

type inferEntry struct {
	Pop  pop
	Kind string
}

func buildInferred() map[string][]inferEntry {
	out := map[string][]inferEntry{}
	add := func(form string, p pop, kind string) {
		if len(form) < 3 || skip[form] {
			return
		}
		for _, e := range out[form] {
			if e.Pop.City == p.City {
				return
			}
		}
		out[form] = append(out[form], inferEntry{Pop: p, Kind: kind})
	}
	seen := map[string]bool{}
	for _, p := range pops {
		if seen[p.City] {
			continue
		}
		seen[p.City] = true
		city := p.City
		if i := strings.IndexByte(city, ','); i >= 0 {
			city = city[:i]
		}
		words := wordSplit.Split(strings.ToLower(city), -1)
		var kept []string
		for _, w := range words {
			if w != "" {
				kept = append(kept, w)
			}
		}
		if len(kept) == 0 {
			continue
		}
		joined := strings.Join(kept, "")
		add(joined, p, "name")
		// A prefix of the whole name: "palo" for Palo Alto, "frank" for
		// Frankfurt. Four letters at least -- three would make "san" a city.
		for n := 4; n < len(joined); n++ {
			add(joined[:n], p, "prefix")
		}
		// The front of each word, run together: "sjo" for San Jose, "kanc"
		// for Kansas City, "losang" for Los Angeles.
		if len(kept) >= 2 {
			for i := 1; i <= len(kept[0]); i++ {
				for j := 1; j <= len(kept[1]); j++ {
					add(kept[0][:i]+kept[1][:j], p, "contraction")
				}
			}
		}
	}
	return out
}

// popCandidates is every place a hostname could be naming, best textual match
// first. It never decides; deciding is the clock's job.
func popCandidates(host string) []popMatch {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return nil
	}
	labels := strings.Split(host, ".")
	if len(labels) > 2 {
		labels = labels[:len(labels)-2]
	}
	var parts []string
	for _, l := range labels {
		for _, x := range labelSplit.Split(l, -1) {
			if x != "" {
				parts = append(parts, x)
			}
		}
	}

	var out []popMatch
	have := map[string]bool{}
	pos := 0
	take := func(code string, p pop, kind string) {
		key := code + "|" + p.City
		if have[key] {
			return
		}
		have[key] = true
		out = append(out, popMatch{Code: code, Pop: p, Kind: kind, Base: matchWeight[kind] * nearness(pos), Pos: pos})
	}

	// Back to front: the site sits nearer the domain than the interface does.
	for i := len(parts) - 1; i >= 0; i-- {
		x := parts[i]
		if skip[x] {
			continue
		}
		base := strings.TrimRight(x, "0123456789")
		if len(base) < 2 {
			continue
		}
		// Counting only the labels that could have been a place. "link" and
		// "bb2" are neither, and letting them push kanc-bb2-link two steps
		// from the domain discounted a reading for being preceded by words
		// that were never candidates.
		before := pos
		pos = before
		if p, ok := pops[base]; ok {
			take(base, p, "code")
		}
		for _, e := range inferred[base] {
			take(base, e.Pop, e.Kind)
		}
		// City plus a state or country run together, which is how NTT and the
		// telephone companies write it: dllstx14, tpkaks, sndgca.
		if len(base) >= 6 {
			for _, n := range []int{4, 3} {
				if p, ok := pops[base[:n]]; ok {
					take(base[:n], p, "code")
				}
			}
		}
		pos++
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Base > out[j].Base })
	return out
}

// fitness is what the round trip says about a candidate.
//
// Under the speed-of-light floor the candidate is not merely unlikely, it is
// impossible, and no amount of textual confidence rescues it. Above the floor
// but below what a built route manages is possible and suspect. Far above
// what the distance needs is weak support rather than a refutation: a slow
// path is ordinary, so being slower than expected only means the name is
// carrying the argument on its own.
func fitness(rtt, km, detour float64) (float64, string) {
	floor := floorMS(km)
	if floor <= 0 {
		return 1, ""
	}
	if rtt < floor {
		return 0, fmt.Sprintf("ruled out: %.0f km needs %.0f ms and it answered in %.1f", km, floor, rtt)
	}
	expected := floorMS(km * detour)
	if expected <= 0 {
		return 1, ""
	}
	switch ratio := rtt / expected; {
	case ratio < 1:
		return 0.55, fmt.Sprintf("quicker than a built route to %.0f km, though light allows it", km)
	case ratio <= 3:
		return 1, fmt.Sprintf("%.1f ms fits %.0f km", rtt, km)
	case ratio <= 20:
		// Slow says almost nothing. A packet can be queued, or sent the long
		// way round, or both, and none of that argues about where it ended
		// up. Treating it as evidence against buried real readings: Arelion's
		// kanc-bb2-link is Kansas City and answers in 30 ms from two hundred
		// kilometres away, because the path goes somewhere else first.
		return 0.8, fmt.Sprintf("%.1f ms is more than %.0f km needs, which an indirect path explains", rtt, km)
	default:
		return 0.6, fmt.Sprintf("%.1f ms is a long way over what %.0f km needs", rtt, km)
	}
}

// placeFromName settles the candidates against the clock and returns the one
// that survives best, with a score between nought and one and the reason.
func (m *Module) placeFromName(host string, rtt float64, h Home) (popMatch, float64, string) {
	cands := popCandidates(host)
	if len(cands) == 0 {
		return popMatch{}, 0, ""
	}
	// Nothing measured, or nowhere to measure from: the text is all there is.
	if !h.OK || rtt <= 0 {
		c := cands[0]
		return c, c.Base, "from the name alone; no round trip to check it against"
	}

	detour := m.landDetour()
	type scored struct {
		m    popMatch
		s    float64
		why  string
		dist float64
	}
	var all []scored
	for _, c := range cands {
		km := greatCircleKM(h.Lat, h.Lon, c.Pop.Lat, c.Pop.Lon)
		f, why := fitness(rtt, km, detour)
		all = append(all, scored{c, c.Base * f, why, km})
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].s > all[j].s })
	best := all[0]
	if best.s <= 0 {
		return popMatch{}, 0, "every reading of the name is ruled out by the round trip"
	}

	why := best.why
	// Say when the clock did the choosing, because that is the interesting
	// case: the name was ambiguous and the measurement settled it.
	if len(all) > 1 {
		var beaten []string
		for _, o := range all[1:] {
			if o.m.Pop.City != best.m.Pop.City && o.s < best.s {
				beaten = append(beaten, o.m.Pop.City)
			}
			if len(beaten) == 2 {
				break
			}
		}
		if len(beaten) > 0 {
			why += "; better than " + strings.Join(beaten, " and ")
		}
	}
	if best.m.Kind != "code" && best.m.Kind != "name" {
		why = "read as a " + best.m.Kind + " of " + best.m.Pop.City + "; " + why
	}
	return best.m, best.s, why
}
