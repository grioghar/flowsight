package paths

// Putting a hop between the two that surround it.
//
// A great many routers answer a traceroute and then cannot be placed: the
// address is in a block no database has coordinates for, and the name gives
// nothing away. On this network that is 338 hops, against 628 that could be
// placed. They were listed underneath the map and left off it, which is
// honest but not very useful -- the route appeared to jump from one country
// to the next with nothing in between.
//
// Their position is not unknown, though. The hop before and the hop after are
// placed, and the hop in question answered, so its round trip sits somewhere
// between theirs. Where it sits in time is a reasonable guess at where it sits
// on the ground: a router that answers a third of the way through the interval
// is, more often than not, about a third of the way along.
//
// More often than not is the whole of the claim. The time between two hops is
// distance plus queueing plus whatever the path did in between, and only the
// first of those is what is being measured here. So these are drawn
// differently, marked as placed by inference, carry the two hops they were put
// between, and are never allowed to overrule anything that was actually
// located.
//
// What this deliberately does not do is place the hops that never answered.
// There are 6,197 of those and no measurement behind any of them; spacing them
// evenly along a line would be drawing six thousand routers from nothing.

import (
	"fmt"
	"math"
	"sort"
)

// interpolateGaps places hops that answered but have no coordinates, between
// the placed hops either side of them.
func interpolateGaps(g *Graph) {
	byID := make(map[string]*Node, len(g.Nodes))
	for i := range g.Nodes {
		byID[g.Nodes[i].ID] = &g.Nodes[i]
	}
	onRoute := map[string]map[string]bool{}
	for _, l := range g.Legs {
		for _, d := range l.Destinations {
			if onRoute[d] == nil {
				onRoute[d] = map[string]bool{}
			}
			onRoute[d][l.From] = true
			onRoute[d][l.To] = true
		}
	}

	for _, dst := range sortedKeys(onRoute) {
		ids := make([]string, 0, len(onRoute[dst]))
		for id := range onRoute[dst] {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool {
			a, b := byID[ids[i]], byID[ids[j]]
			if a == nil || b == nil {
				return ids[i] < ids[j]
			}
			if a.Index != b.Index {
				return a.Index < b.Index
			}
			return a.ID < b.ID
		})

		var anchor *Node
		var waiting []*Node
		for _, id := range ids {
			n := byID[id]
			if n == nil {
				continue
			}
			// Only ever measured from hops that were really placed, never
			// from one of these guesses: a chain of inferences drifts, and
			// the drift would be invisible.
			if n.Located && n.Source != "between" {
				if anchor != nil && len(waiting) > 0 {
					placeBetween(anchor, n, waiting)
				}
				anchor, waiting = n, nil
				continue
			}
			if n.Located || n.Silent || n.RTT <= 0 {
				continue // nothing measured, or already placed
			}
			if anchor != nil {
				waiting = append(waiting, n)
			}
		}
		// Past the last placed hop there is nothing to interpolate towards,
		// but there is still the clock. A hop that answers within a couple
		// of milliseconds of the last placed one is beside it: this is where
		// an anycast address ends up -- Google's or Cloudflare's resolver
		// answering from the Dallas site the route just reached -- and where
		// a final hop the database put on another continent belongs.
		if anchor != nil {
			placeNear(anchor, waiting)
		}
	}
}

// nearMS is how much later than its anchor a hop may answer and still be
// counted as beside it: a couple of milliseconds is a metro, not a journey.
const nearMS = 3.0

// placeNear puts trailing unplaced hops beside the last placed one when the
// timing says they are there, and leaves the rest alone.
func placeNear(a *Node, run []*Node) {
	for i, n := range run {
		if n.Located || n.RTT <= 0 {
			continue
		}
		extra := n.RTT - a.RTT
		if extra < -0.5 || extra > nearMS+a.RTT*0.1 {
			continue // genuinely further on; nothing honest can be said
		}
		// A hair to one side, so several such hops do not stack on the anchor.
		n.Lat, n.Lon = a.Lat+0.15*float64(i%3-1), a.Lon+0.35*float64(i/3+1)
		n.Located, n.Source, n.Inferred = true, "near", true
		n.Between = []string{firstIP(a)}
		what := "the last hop the route reached"
		if n.Anycast {
			what = "an anycast address: the instance reached is the one beside " + firstIP(a)
		}
		n.BetweenHow = fmt.Sprintf("%s; answers %.1f ms after %s, which is the same metro, not a journey", what, extra, firstIP(a))
		n.City, n.Region, n.Country = a.City, a.Region, a.Country
	}
}

// placeBetween spreads a run of unplaced hops along the line from a to b.
func placeBetween(a, b *Node, run []*Node) {
	span := b.RTT - a.RTT
	for i, n := range run {
		if n.Located {
			continue // another route got there first
		}
		var f float64
		var how string
		if span > 0.05 && n.RTT >= a.RTT && n.RTT <= b.RTT {
			f = (n.RTT - a.RTT) / span
			how = fmt.Sprintf("%.1f ms of the %.1f ms between them", n.RTT-a.RTT, span)
		} else {
			// The clock is no help: the interval is too short to divide, or
			// the round trips are out of order, which happens when a router
			// is slow to answer rather than far away. Spacing by position is
			// the weaker answer and says so.
			f = float64(i+1) / float64(len(run)+1)
			how = fmt.Sprintf("hop %d of the %d between them; the round trips did not separate them", i+1, len(run))
		}
		if f < 0.03 {
			f = 0.03
		}
		if f > 0.97 {
			f = 0.97
		}
		lat, lon := alongGreatCircle(a.Lat, a.Lon, b.Lat, b.Lon, f)
		n.Lat, n.Lon, n.Located, n.Source = lat, lon, true, "between"
		n.Inferred = true
		n.Between = []string{firstIP(a), firstIP(b)}
		n.BetweenHow = how
		n.City, n.Region, n.Country = "", "", ""
	}
}

func firstIP(n *Node) string {
	if len(n.IPs) > 0 {
		return n.IPs[0]
	}
	return n.ID
}

// alongGreatCircle is the point a fraction of the way from one place to
// another, along the shortest path over the sphere. Interpolating the
// latitude and longitude instead would drift off the route, badly at high
// latitudes and across the antimeridian.
func alongGreatCircle(lat1, lon1, lat2, lon2, f float64) (float64, float64) {
	φ1, λ1 := lat1*math.Pi/180, lon1*math.Pi/180
	φ2, λ2 := lat2*math.Pi/180, lon2*math.Pi/180
	d := 2 * math.Asin(math.Sqrt(math.Pow(math.Sin((φ2-φ1)/2), 2)+
		math.Cos(φ1)*math.Cos(φ2)*math.Pow(math.Sin((λ2-λ1)/2), 2)))
	if d < 1e-9 {
		return lat1, lon1
	}
	A := math.Sin((1-f)*d) / math.Sin(d)
	B := math.Sin(f*d) / math.Sin(d)
	x := A*math.Cos(φ1)*math.Cos(λ1) + B*math.Cos(φ2)*math.Cos(λ2)
	y := A*math.Cos(φ1)*math.Sin(λ1) + B*math.Cos(φ2)*math.Sin(λ2)
	z := A*math.Sin(φ1) + B*math.Sin(φ2)
	return math.Atan2(z, math.Sqrt(x*x+y*y)) * 180 / math.Pi,
		math.Atan2(y, x) * 180 / math.Pi
}
