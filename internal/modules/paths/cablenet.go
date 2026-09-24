package paths

// A cable is a system, not a line.
//
// The published data gives each cable as a set of separate runs, because that
// is what a cable is: a trunk with branching units, spurs to extra landing
// points, and segments recorded apart from one another. Trans-Pacific systems
// come as five or seven runs; the Atlantic ones often as one or two.
//
// Searching inside a single run therefore worked across the Atlantic and
// could not work across the Pacific at all. The nearest point to Kansas was
// on one run and the nearest to Seoul on another, and no path existed between
// them, so every Pacific crossing fell back to the straight line -- or, worse,
// to whatever unrelated cable happened to produce a shorter nonsense.
//
// So the runs are stitched back into the network they came from: points
// joined along each run, and runs joined to each other where their ends meet.
// Then the question "how far along this cable" is a shortest path, which is
// what it always was.

import (
	"container/heap"
	"math"
)

// joinKM is how close two runs have to come to count as connected. Branch
// points are recorded separately in each run and rarely land on exactly the
// same coordinate.
const joinKM = 75

type cableEdge struct {
	to int
	km float64
}

// cableNet is one cable's runs as a single connected thing.
type cableNet struct {
	Name string
	Pts  []LatLon
	Adj  [][]cableEdge
}

// buildNet stitches a cable's runs together.
//
// Submarine runs are tens of points each and any method works. Terrestrial
// data is not like that: AfTerFibre traces roads, and one run can be six
// thousand points a few hundred metres apart. Two things keep that tractable.
// Each run is first thinned to the points that change its shape by more than
// thinKM -- the length along it is unchanged to within that -- and the
// cross-run join walks a grid of one-degree cells instead of comparing every
// point with every other, which on the full African set was twenty-five
// billion great-circle distances and never finished.
func buildNet(c Cable) cableNet {
	n := cableNet{Name: c.Name}
	runOf := []int{}
	for ri, run := range c.Legs {
		for _, p := range thinRun(run, thinKM) {
			n.Pts = append(n.Pts, p)
			runOf = append(runOf, ri)
		}
	}
	n.Adj = make([][]cableEdge, len(n.Pts))
	// Along each run.
	for i := 1; i < len(n.Pts); i++ {
		if runOf[i] != runOf[i-1] {
			continue
		}
		a, b := i-1, i
		km := greatCircleKM(n.Pts[a].Lat, n.Pts[a].Lon, n.Pts[b].Lat, n.Pts[b].Lon)
		n.Adj[a] = append(n.Adj[a], cableEdge{b, km})
		n.Adj[b] = append(n.Adj[b], cableEdge{a, km})
	}
	if len(c.Legs) < 2 {
		return n
	}
	// Between runs, wherever they meet. Points are bucketed by whole degree;
	// joinKM is under a degree of latitude, so a neighbour is always in the
	// same or an adjacent row, and within a few columns depending on how far
	// north the row is.
	cells := map[[2]int][]int{}
	for i, p := range n.Pts {
		cells[cellOf(p)] = append(cells[cellOf(p)], i)
	}
	for i, p := range n.Pts {
		c0 := cellOf(p)
		span := lonSpan(p.Lat)
		for dr := -1; dr <= 1; dr++ {
			for dc := -span; dc <= span; dc++ {
				col := ((c0[1]+dc)%360 + 360) % 360
				for _, j := range cells[[2]int{c0[0] + dr, col}] {
					if j <= i || runOf[i] == runOf[j] {
						continue
					}
					km := greatCircleKM(p.Lat, p.Lon, n.Pts[j].Lat, n.Pts[j].Lon)
					if km > joinKM {
						continue
					}
					n.Adj[i] = append(n.Adj[i], cableEdge{j, km})
					n.Adj[j] = append(n.Adj[j], cableEdge{i, km})
				}
			}
		}
	}
	return n
}

// thinKM is how far a point may sit off the line between its neighbours
// before it is worth keeping. A kilometre is far below anything else measured
// here -- the join tolerance is 75 -- and it turns road tracings into the few
// hundred vertices that matter.
const thinKM = 1.0

// cellOf is the one-degree grid cell a point falls in: row by latitude,
// column by longitude, both shifted to be non-negative.
func cellOf(p LatLon) [2]int {
	return [2]int{int(math.Floor(p.Lat)) + 90, ((int(math.Floor(p.Lon)) % 360) + 360) % 360}
}

// lonSpan is how many columns either side of a cell can hold a point within
// joinKM at this latitude. Columns narrow towards the poles.
func lonSpan(lat float64) int {
	cosLat := math.Cos(lat * math.Pi / 180)
	if cosLat < 0.05 {
		return 180
	}
	span := int(math.Ceil(joinKM/(111.32*cosLat))) + 1
	if span > 180 {
		span = 180
	}
	return span
}

// thinRun is Ramer-Douglas-Peucker on a run: keep the ends, then keep any
// point further than tolKM off the chord between kept points, and repeat on
// each side of it. Iterative, because a six-thousand-point run is a poor
// place for recursion.
func thinRun(run []LatLon, tolKM float64) []LatLon {
	if len(run) <= 2 {
		return run
	}
	keep := make([]bool, len(run))
	keep[0], keep[len(run)-1] = true, true
	type span struct{ a, b int }
	stack := []span{{0, len(run) - 1}}
	for len(stack) > 0 {
		s := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if s.b-s.a < 2 {
			continue
		}
		far, farKM := -1, tolKM
		for i := s.a + 1; i < s.b; i++ {
			if d := offChordKM(run[s.a], run[s.b], run[i]); d > farKM {
				far, farKM = i, d
			}
		}
		if far < 0 {
			continue
		}
		keep[far] = true
		stack = append(stack, span{s.a, far}, span{far, s.b})
	}
	out := make([]LatLon, 0, 64)
	for i, k := range keep {
		if k {
			out = append(out, run[i])
		}
	}
	return out
}

// offChordKM is how far a point sits from the segment between two others. At
// the scales thinning cares about -- a kilometre over segments of at most a
// few hundred -- a local flat projection is exact enough.
func offChordKM(a, b, p LatLon) float64 {
	cosLat := math.Cos((a.Lat + b.Lat) / 2 * math.Pi / 180)
	ax, ay := 0.0, 0.0
	bx, by := wrapDeg(b.Lon-a.Lon)*cosLat, b.Lat-a.Lat
	px, py := wrapDeg(p.Lon-a.Lon)*cosLat, p.Lat-a.Lat
	dx, dy := bx-ax, by-ay
	l2 := dx*dx + dy*dy
	t := 0.0
	if l2 > 0 {
		t = ((px-ax)*dx + (py-ay)*dy) / l2
		if t < 0 {
			t = 0
		} else if t > 1 {
			t = 1
		}
	}
	cx, cy := ax+t*dx, ay+t*dy
	return math.Hypot(px-cx, py-cy) * 111.32
}

// wrapDeg brings a longitude difference into [-180, 180).
func wrapDeg(d float64) float64 {
	for d >= 180 {
		d -= 360
	}
	for d < -180 {
		d += 360
	}
	return d
}

// nearestPoint is the point of the network closest to a place, and how far
// off it is.
func (n *cableNet) nearestPoint(lat, lon float64) (int, float64) {
	best, bestKM := -1, math.MaxFloat64
	for i, p := range n.Pts {
		if km := greatCircleKM(lat, lon, p.Lat, p.Lon); km < bestKM {
			best, bestKM = i, km
		}
	}
	return best, bestKM
}

type pqItem struct {
	node int
	km   float64
}
type pq []pqItem

func (p pq) Len() int           { return len(p) }
func (p pq) Less(i, j int) bool { return p[i].km < p[j].km }
func (p pq) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p *pq) Push(x any)        { *p = append(*p, x.(pqItem)) }
func (p *pq) Pop() (x any)      { old := *p; x = old[len(old)-1]; *p = old[:len(old)-1]; return }

// shortest is the distance along the cable between two of its points, and the
// points passed through, so the map can draw the shape the packet took.
func (n *cableNet) shortest(from, to int) (float64, []int) {
	if from < 0 || to < 0 || from >= len(n.Pts) || to >= len(n.Pts) {
		return 0, nil
	}
	if from == to {
		return 0, []int{from}
	}
	dist := make([]float64, len(n.Pts))
	prev := make([]int, len(n.Pts))
	done := make([]bool, len(n.Pts))
	for i := range dist {
		dist[i], prev[i] = math.MaxFloat64, -1
	}
	dist[from] = 0
	q := &pq{{from, 0}}
	for q.Len() > 0 {
		it := heap.Pop(q).(pqItem)
		if done[it.node] {
			continue
		}
		done[it.node] = true
		if it.node == to {
			break
		}
		for _, e := range n.Adj[it.node] {
			if nd := dist[it.node] + e.km; nd < dist[e.to] {
				dist[e.to], prev[e.to] = nd, it.node
				heap.Push(q, pqItem{e.to, nd})
			}
		}
	}
	if dist[to] == math.MaxFloat64 {
		return 0, nil // the runs do not connect; not one system after all
	}
	var path []int
	for at := to; at != -1; at = prev[at] {
		path = append(path, at)
	}
	for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
		path[i], path[j] = path[j], path[i]
	}
	return dist[to], path
}
