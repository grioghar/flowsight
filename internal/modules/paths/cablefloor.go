package paths

// What the cables say the journey is really worth.
//
// The plausibility check asks whether a round trip could have covered the
// distance, and until now "the distance" was the straight line over the
// earth's surface. No packet travels that. Between continents it travels
// along a cable, and cables do not go straight: they follow continental
// shelves, skirt trenches and fishing grounds, come ashore where there is a
// station to land at, and are laid with slack. The Atlantic crossings run a
// tenth or more longer than the great circle, and the ones round Africa or
// through the Red Sea a great deal more than that.
//
// Measuring along the published routes instead gives a floor that is both
// higher and better founded, and every hop it moves is a hop that was being
// judged against a journey nobody can make.
//
// The care needed is in deciding when a cable applies at all. Two cities on
// one continent are joined by ground, and a coastal cable that happens to
// pass near both would give a long way round and a floor that accuses
// perfectly good placements. So a cable route is used only when it is a
// credible way to make the trip: far enough that a crossing is plausible, and
// not so much longer than the straight line that it is obviously a different
// journey. The value taken is the shortest such route, because the check
// needs a lower bound -- the fastest way the packet could have gone, not the
// likeliest.

import (
	"math"
	"strconv"
	"strings"
	"sync"

	"github.com/grioghar/flowsight/internal/core"
)

// cableFloorMinKM is the distance below which the cables are not consulted.
// Under this, a trip is made on land, where the straight line is the honest
// bound and no cable route describes it.
const cableFloorMinKM = 1200

// cableFloorMaxRatio caps how far a cable route may exceed the straight line
// before it is read as a different journey rather than a longer version of
// this one. A crossing that doubles the distance is not the route a packet
// took to get somewhere the straight line reaches in half.
const cableFloorMaxRatio = 2.0

// cableRoute is the shortest published path between two places, and the shape
// of it: the points a packet would pass through, ashore at each end and along
// the cable in between. The shape is what lets the map draw the journey
// rather than a straight line across an ocean the cable does not cross.
type cableRoute struct {
	KM    float64
	Name  string
	Route []LatLon
	// AlongKM is the part on the cable itself and AshoreKM the part overland
	// at either end. They are kept apart because they are different kinds of
	// distance: the cable's length is measured from its published route and
	// is what it is, while the run ashore is a straight line standing in for
	// a road nobody has given us.
	AlongKM  float64
	AshoreKM float64
	OK       bool
	// Weight is the network's, carried so an estimate can blend a
	// suggestive route with the plain detour rather than swallow it whole.
	Weight float64
}

// routeMemo remembers the answer to "shortest way between these two places
// over this set of networks". The graph asks the same few hundred questions
// every time it is rebuilt, and each one is a scan of every network's every
// point; answered once, the rebuild is a lookup.
//
// The zero value is ready to use. It is emptied when the networks it answered
// for are replaced, and when it grows past a bound nobody's graph should
// reach, so a long-running daemon cannot be walked into hoarding.
type routeMemo struct {
	mu sync.Mutex
	m  map[string]cableRoute
}

const routeMemoMax = 20000

func (f *routeMemo) key(kind byte, aLat, aLon, bLat, bLon float64) string {
	// Half a degree is about fifty kilometres, far finer than the placements
	// this is applied to, and coarse enough that a graph full of hops in one
	// city asks once.
	r := func(v float64) float64 { return math.Round(v*2) / 2 }
	var b strings.Builder
	b.WriteByte(kind)
	b.WriteByte(':')
	for _, v := range []float64{r(aLat), r(aLon), r(bLat), r(bLon)} {
		b.WriteString(ftoa(v))
		b.WriteByte(',')
	}
	return b.String()
}

func (f *routeMemo) get(key string) (cableRoute, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.m[key]
	return r, ok
}

func (f *routeMemo) put(key string, r cableRoute) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.m == nil || len(f.m) >= routeMemoMax {
		f.m = map[string]cableRoute{}
	}
	f.m[key] = r
}

// reset forgets everything; called when the networks change underneath.
func (f *routeMemo) reset() {
	f.mu.Lock()
	f.m = nil
	f.mu.Unlock()
}

// candidateMemo does for "which cables pass near both ends" what routeMemo
// does for the shortest crossing: the same pairs of places come up on every
// rebuild and the scan of every run of every cable is the same each time.
type candidateMemo struct {
	mu sync.Mutex
	m  map[string][]Candidate
}

func (f *candidateMemo) get(cables []Cable, aLat, aLon, bLat, bLon, nearKM float64) []Candidate {
	var rm routeMemo
	key := rm.key('n', aLat, aLon, bLat, bLon) + ftoa(nearKM)
	f.mu.Lock()
	if c, ok := f.m[key]; ok {
		f.mu.Unlock()
		return c
	}
	f.mu.Unlock()
	c := nearCables(cables, aLat, aLon, bLat, bLon, nearKM)
	f.mu.Lock()
	if f.m == nil || len(f.m) >= routeMemoMax {
		f.m = map[string][]Candidate{}
	}
	f.m[key] = c
	f.mu.Unlock()
	return c
}

func (f *candidateMemo) reset() {
	f.mu.Lock()
	f.m = nil
	f.mu.Unlock()
}

// memoRoute answers through the memo, computing on a miss.
func (f *routeMemo) memoRoute(kind byte, nets []cableNet, aLat, aLon, bLat, bLon float64) cableRoute {
	key := f.key(kind, aLat, aLon, bLat, bLon)
	if r, ok := f.get(key); ok {
		return r
	}
	r := cableRouteKM(nets, aLat, aLon, bLat, bLon, maxAshoreKM)
	f.put(key, r)
	return r
}

func ftoa(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) }

// maxAshoreKM is how far inland an end may be and still be served by a cable.
//
// It is deliberately generous. Asking a cable to pass close to both ends is
// the right question when you want to know which cable carried a leg, and the
// wrong one here: this asks how far the packet had to travel, and the run
// overland to reach the sea is part of that journey rather than a reason to
// discard the crossing. A gateway in Kansas is fifteen hundred kilometres
// from salt water and no cable comes near it; with a proximity gate, every
// transatlantic route it takes was rejected and nothing was measured along a
// cable at all.
const maxAshoreKM = 3200

const minCableShare = 0.55

// minCableShare is how much of the journey has to be on the cable before the
// route is believed.
//
// The run ashore is measured as a straight line, and a straight line does not
// know about water. Left unchecked, the search happily joins two enormous
// "overland" legs to a short local cable and calls it the shortest way: the
// first version picked Greenland Connect, Sunoque I and a festoon off
// Colombia for crossings out of Kansas, because a tiny cable with vast
// imaginary approaches beat a real transatlantic trunk. A crossing worth the
// name is mostly the crossing.

// cableRouteKM is the shortest way between two places that the cable record
// actually offers: overland to a cable, along it, and overland again at the
// far end, with both runs ashore counted.
//
// It is a minimum over every cable serving both ends, because the check it
// feeds needs a bound nothing can beat rather than a best guess at the path.
// The minimum does the work a proximity gate used to: a cable landing near
// both ends beats one that needs a thousand kilometres of driving, without
// having to rule the second out in advance.
func cableRouteKM(nets []cableNet, aLat, aLon, bLat, bLon, ashoreKM float64) cableRoute {
	best := cableRoute{KM: math.MaxFloat64}
	for i := range nets {
		n := &nets[i]
		ia, da := n.nearestPoint(aLat, aLon)
		ib, db := n.nearestPoint(bLat, bLon)
		if ia < 0 || ib < 0 || ia == ib || da > ashoreKM || db > ashoreKM {
			continue
		}
		along, path := n.shortest(ia, ib)
		if path == nil {
			continue // these runs are not joined; no way across this system
		}
		total := along + da + db
		if total <= 0 || along/total < minCableShare {
			continue // mostly imaginary overland; not this crossing
		}
		if total < best.KM {
			// The shape as well as the length: where the packet started, out
			// to the cable, along every point of the path, and ashore again.
			pts := make([]LatLon, 0, len(path)+2)
			pts = append(pts, LatLon{Lat: aLat, Lon: aLon})
			for _, ix := range path {
				pts = append(pts, n.Pts[ix])
			}
			pts = append(pts, LatLon{Lat: bLat, Lon: bLon})
			w := n.Weight
			if w <= 0 {
				w = 1
			}
			best = cableRoute{KM: total, Name: n.Name, Route: pts,
				AlongKM: along, AshoreKM: da + db, OK: true, Weight: w}
		}
	}
	if !best.OK {
		return cableRoute{}
	}
	return best
}

// pathKM is the distance the plausibility check should use between two
// places: the straight line, or the shortest cable route where one credibly
// describes the trip and is longer.
//
// Only ever longer. This raises floors, never lowers them, because the
// straight line is already the least any path can be and a cable cannot
// undercut it.
func (m *Module) pathKM(aLat, aLon, bLat, bLon float64) (km float64, via string) {
	km = greatCircleKM(aLat, aLon, bLat, bLon)
	if km < cableFloorMinKM {
		return km, ""
	}
	m.mu.Lock()
	nets := m.nets
	m.mu.Unlock()
	if len(nets) == 0 {
		return km, ""
	}
	// Not cable_near_km: that setting answers "did this cable carry the
	// leg", where being close matters. Here the overland run is part of
	// the distance, and the shortest total decides.
	r := m.routes.memoRoute('c', nets, aLat, aLon, bLat, bLon)
	if !r.OK || r.KM <= km || r.KM > km*cableFloorMaxRatio {
		return km, ""
	}
	return r.KM, r.Name
}

// drawRoute gives a leg the shape of the crossing it most likely made, so the
// map can follow the cable instead of ruling a straight line through water no
// cable goes near.
func (m *Module) drawRoute(aLat, aLon, bLat, bLon float64) cableRoute {
	return m.crossing(aLat, aLon, bLat, bLon)
}

// A floor and an expectation are different questions.
//
// The floor asks what light forbids: nothing answers sooner than twice the
// distance divided by the speed of light in glass, and a hop that does is not
// where it is said to be. That is a proof, and it is rigorous precisely
// because it assumes a perfect path -- dead straight, no equipment on it.
//
// The trouble is that no path is like that, so the floor is a long way below
// what anything real achieves, and a placement can be comfortably above it
// and still be nonsense. What was needed was a second number: not what
// physics forbids, but what a route that actually exists could manage.
//
// Overland that means accepting fibre does not go straight. It follows roads,
// railways and rights of way, it detours around whatever could not be dug
// through, and it comes out around a third longer than the crow flies. Over
// water it means the cable's own published length, which is already the real
// distance and needs no such allowance. And every hop on the way adds a
// little for the time a router spends receiving a packet before it can start
// sending it on.
//
// A hop below that second number is not disproved. It is doing better than
// any route anyone has built, which is worth saying out loud and is not the
// same claim as impossible.

// expectedKM is the distance a route that exists would have to cover.
func (m *Module) expectedKM(aLat, aLon, bLat, bLon float64) (km float64, via string) {
	straight := greatCircleKM(aLat, aLon, bLat, bLon)
	detour := m.landDetour()

	// A sea crossing is measured, not estimated: the cable's published length
	// is the distance, and only the runs ashore need the allowance.
	if r := m.crossing(aLat, aLon, bLat, bLon); r.OK {
		return r.AlongKM + r.AshoreKM*detour, r.Name
	}
	// Overland, a mapped route beats an estimate where we have one. A
	// suggestive source -- OpenStreetMap's lines -- is blended with the
	// estimate by its weight rather than trusted outright.
	if r := m.overland(aLat, aLon, bLat, bLon); r.OK {
		along := r.AlongKM + r.AshoreKM*detour
		if r.Weight > 0 && r.Weight < 1 {
			return along*r.Weight + straight*detour*(1-r.Weight), r.Name
		}
		return along, r.Name
	}
	return straight * detour, ""
}

func (m *Module) landDetour() float64 {
	pct := 35
	if m.ctx != nil {
		pct = core.Int(m.ctx.Settings(), "land_detour_pct", 35)
	}
	if pct < 0 {
		pct = 0
	}
	return 1 + float64(pct)/100
}

func (m *Module) hopDelayMS() float64 {
	if m.ctx == nil {
		return 0.2
	}
	v := core.Int(m.ctx.Settings(), "hop_delay_us", 200)
	if v < 0 {
		v = 0
	}
	return float64(v) / 1000
}

// crossing is the submarine route between two places, if one applies.
func (m *Module) crossing(aLat, aLon, bLat, bLon float64) cableRoute {
	if greatCircleKM(aLat, aLon, bLat, bLon) < cableFloorMinKM {
		return cableRoute{}
	}
	m.mu.Lock()
	nets := m.nets
	m.mu.Unlock()
	if len(nets) == 0 {
		return cableRoute{}
	}
	r := m.routes.memoRoute('c', nets, aLat, aLon, bLat, bLon)
	straight := greatCircleKM(aLat, aLon, bLat, bLon)
	if !r.OK || r.KM <= straight || r.KM > straight*cableFloorMaxRatio {
		return cableRoute{}
	}
	return r
}

// overland is the mapped terrestrial route between two places, if one exists.
//
// This never touches the floor. Over water there is no straight line to be
// had, so a cable's length is a genuine bound; on land a straight line is
// merely something nobody built, and treating "unbuilt" as "impossible" would
// convict a placement of a crime it has not committed.
func (m *Module) overland(aLat, aLon, bLat, bLon float64) cableRoute {
	if greatCircleKM(aLat, aLon, bLat, bLon) < cableFloorMinKM {
		return cableRoute{}
	}
	m.mu.Lock()
	nets, osm := m.landNets, m.osmNets
	m.mu.Unlock()
	straight := greatCircleKM(aLat, aLon, bLat, bLon)
	// Measured sets first; the suggestive one only where they say nothing.
	if len(nets) > 0 {
		r := m.routes.memoRoute('l', nets, aLat, aLon, bLat, bLon)
		if r.OK && r.KM > straight && r.KM <= straight*cableFloorMaxRatio {
			return r
		}
	}
	if len(osm) > 0 {
		r := m.routes.memoRoute('o', osm, aLat, aLon, bLat, bLon)
		if r.OK && r.KM > straight && r.KM <= straight*cableFloorMaxRatio {
			return r
		}
	}
	return cableRoute{}
}
