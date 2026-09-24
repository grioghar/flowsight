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

// cableRoute is the shortest published path between two places.
type cableRoute struct {
	KM   float64
	Name string
	OK   bool
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

// cableRouteKM is the shortest way between two places that the cable record
// actually offers: out to a cable, along it, and ashore at the other end.
//
// It is a minimum over every cable serving both ends, because the check it
// feeds needs a bound nothing can beat rather than a best guess at the path.
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
			total := runLengthKM(run[lo:hi+1]) + da + db
			if total < best.KM {
				best = cableRoute{KM: total, Name: c.Name, OK: true}
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
		near := float64(500)
		if m.ctx != nil {
			near = float64(core.Int(m.ctx.Settings(), "cable_near_km", 400))
		}
		r = cableRouteKM(cables, aLat, aLon, bLat, bLon, near)
		m.floors.mu.Lock()
		m.floors.m[key] = r
		m.floors.mu.Unlock()
	}
	if !r.OK || r.KM <= km || r.KM > km*cableFloorMaxRatio {
		return km, ""
	}
	return r.KM, r.Name
}
