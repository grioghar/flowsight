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
	OK    bool
}

type floorMemo struct {
	mu sync.Mutex
	m  map[string]cableRoute
}

func (f *floorMemo) key(aLat, aLon, bLat, bLon float64) string {
	// Half a degree is about fifty kilometres, far finer than the placements
	// this is applied to, and coarse enough that a graph full of hops in one
	// city asks once.
	r := func(v float64) float64 { return math.Round(v*2) / 2 }
	var b strings.Builder
	for _, v := range []float64{r(aLat), r(aLon), r(bLat), r(bLon)} {
		b.WriteString(ftoa(v))
		b.WriteByte(',')
	}
	return b.String()
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
const maxAshoreKM = 2500

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
func cableRouteKM(cables []Cable, aLat, aLon, bLat, bLon, nearKM float64) cableRoute {
	best := cableRoute{KM: math.MaxFloat64}
	for _, c := range cables {
		for _, run := range c.Legs {
			ia, da := nearestOn(run, aLat, aLon)
			ib, db := nearestOn(run, bLat, bLon)
			if ia < 0 || ib < 0 || da > nearKM || db > nearKM || ia == ib {
				continue
			}
			lo, hi := ia, ib
			if lo > hi {
				lo, hi = hi, lo
			}
			// The whole journey: the run ashore at each end counts, or a
			// cable that lands a hundred kilometres away looks free.
			along := runLengthKM(run[lo : hi+1])
			total := along + da + db
			if total <= 0 || along/total < minCableShare {
				continue // mostly imaginary overland; not this crossing
			}
			if total < best.KM {
				// The shape as well as the length: from where the packet
				// started, out to the cable, along every point of it in the
				// right direction, and ashore at the far end.
				pts := make([]LatLon, 0, hi-lo+3)
				pts = append(pts, LatLon{Lat: aLat, Lon: aLon})
				seg := run[lo : hi+1]
				if ia > ib {
					for i := len(seg) - 1; i >= 0; i-- {
						pts = append(pts, seg[i])
					}
				} else {
					pts = append(pts, seg...)
				}
				pts = append(pts, LatLon{Lat: bLat, Lon: bLon})
				best = cableRoute{KM: total, Name: c.Name, Route: pts, OK: true}
			}
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
	cables := m.cables
	m.mu.Unlock()
	if len(cables) == 0 {
		return km, ""
	}
	if m.floors == nil {
		m.floors = &floorMemo{m: map[string]cableRoute{}}
	}
	key := m.floors.key(aLat, aLon, bLat, bLon)
	m.floors.mu.Lock()
	r, seen := m.floors.m[key]
	m.floors.mu.Unlock()
	if !seen {
		// Not cable_near_km: that setting answers "did this cable carry the
		// leg", where being close matters. Here the overland run is part of
		// the distance, and the shortest total decides.
		r = cableRouteKM(cables, aLat, aLon, bLat, bLon, maxAshoreKM)
		m.floors.mu.Lock()
		m.floors.m[key] = r
		m.floors.mu.Unlock()
	}
	if !r.OK || r.KM <= km || r.KM > km*cableFloorMaxRatio {
		return km, ""
	}
	return r.KM, r.Name
}

// drawRoute gives a leg the shape of the crossing it most likely made, so the
// map can follow the cable instead of ruling a straight line through water no
// cable goes near.
func (m *Module) drawRoute(aLat, aLon, bLat, bLon float64) cableRoute {
	if greatCircleKM(aLat, aLon, bLat, bLon) < cableFloorMinKM {
		return cableRoute{}
	}
	m.mu.Lock()
	cables := m.cables
	m.mu.Unlock()
	if len(cables) == 0 {
		return cableRoute{}
	}
	r := cableRouteKM(cables, aLat, aLon, bLat, bLon, maxAshoreKM)
	straight := greatCircleKM(aLat, aLon, bLat, bLon)
	if !r.OK || r.KM <= straight || r.KM > straight*cableFloorMaxRatio {
		return cableRoute{}
	}
	return r
}
