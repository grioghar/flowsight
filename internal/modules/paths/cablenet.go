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
// Submarine data is tens of runs of tens of points and any method works.
// Terrestrial data is not like that. AfTerFibre traces roads: one route is
// nearly five thousand runs with a median of five points, more than half of
// them ending exactly where the next begins, and a few of them six thousand
// points a few hundred metres apart. Three steps make that tractable, and
// each is a no-op on data that does not need it.
//
// Runs that end where another starts are chained into one, so a road drawn
// in a thousand pieces is one run. Each run is then thinned to the points
// that change its shape by more than thinKM, which leaves its length
// unchanged to within that. Finally each run's two ends are joined to the
// nearest point of the few closest other runs within joinKM -- that is what
// "runs meet" means: a spur starts on the trunk, a segment recorded apart
// ends where the next begins. The first version joined every point to every
// point within that distance, which for parallel road-traced runs made fifty
// million edges and a gigabyte of heap for a connectivity two edges per run
// end gives just as well.
func buildNet(c Cable) cableNet {
	n := cableNet{Name: c.Name}
	var runs [][]LatLon
	starts := []int{}
	for _, run := range chainRuns(c.Legs) {
		run = thinRun(run, thinKM)
		if len(run) == 0 {
			continue
		}
		starts = append(starts, len(n.Pts))
		runs = append(runs, run)
		n.Pts = append(n.Pts, run...)
	}
	n.Adj = make([][]cableEdge, len(n.Pts))
	link := func(a, b int, km float64) {
		n.Adj[a] = append(n.Adj[a], cableEdge{b, km})
		n.Adj[b] = append(n.Adj[b], cableEdge{a, km})
	}
	// Along each run.
	for ri, run := range runs {
		base := starts[ri]
		for i := 1; i < len(run); i++ {
			link(base+i-1, base+i, greatCircleKM(run[i-1].Lat, run[i-1].Lon, run[i].Lat, run[i].Lon))
		}
	}
	// Between runs: each end to the nearest point of its few closest
	// neighbours.
	for ri, run := range runs {
		ends := []int{0, len(run) - 1}
		if len(run) == 1 {
			ends = ends[:1]
		}
		for _, ei := range ends {
			e := run[ei]
			from := starts[ri] + ei
			var best []nearRun
			for rj, other := range runs {
				if rj == ri {
					continue
				}
				ix, km := nearestOn(other, e.Lat, e.Lon)
				if ix < 0 || km > joinKM {
					continue
				}
				best = insertNear(best, nearRun{starts[rj] + ix, km}, joinFanout)
			}
			for _, b := range best {
				link(from, b.at, b.km)
			}
		}
	}
	return n
}

// joinFanout is how many other runs an end may be joined to. Two keeps a
// chain connected through a break; three covers a junction.
const joinFanout = 3

// nearRun is a candidate join: a point index and how far away it is.
type nearRun struct {
	at int
	km float64
}

// insertNear keeps the k closest, sorted.
func insertNear(xs []nearRun, x nearRun, k int) []nearRun {
	i := len(xs)
	for i > 0 && xs[i-1].km > x.km {
		i--
	}
	if i >= k {
		return xs
	}
	xs = append(xs, x)
	copy(xs[i+1:], xs[i:])
	xs[i] = x
	if len(xs) > k {
		xs = xs[:k]
	}
	return xs
}

// chainKM is how close a run's end must be to another's for the two to be
// one line drawn in pieces. Half a kilometre is far below the join distance
// and far above the coordinate noise of a road tracing.
const chainKM = 0.5

// chainRuns merges runs end to end. A run whose last point sits on another
// run's first is continued by it; on another run's last, continued by it
// reversed. Ends are indexed by rounded coordinate so the search is a map
// lookup, and the result is at most as many runs as it was given.
func chainRuns(runs [][]LatLon) [][]LatLon {
	if len(runs) < 2 {
		return runs
	}
	type endRef struct {
		run  int
		head bool // true for the first point, false for the last
	}
	key := func(p LatLon) [2]int { return [2]int{int(math.Round(p.Lat * 200)), int(math.Round(p.Lon * 200))} } // ~500 m cells
	ends := map[[2]int][]endRef{}
	for i, r := range runs {
		if len(r) == 0 {
			continue
		}
		ends[key(r[0])] = append(ends[key(r[0])], endRef{i, true})
		ends[key(r[len(r)-1])] = append(ends[key(r[len(r)-1])], endRef{i, false})
	}
	used := make([]bool, len(runs))
	// A neighbour whose end lies within chainKM of p, in this or an adjacent
	// cell, not yet used and not run i itself.
	findNext := func(p LatLon, self int) (endRef, bool) {
		k := key(p)
		for dr := -1; dr <= 1; dr++ {
			for dc := -1; dc <= 1; dc++ {
				for _, ref := range ends[[2]int{k[0] + dr, k[1] + dc}] {
					if ref.run == self || used[ref.run] {
						continue
					}
					r := runs[ref.run]
					q := r[0]
					if !ref.head {
						q = r[len(r)-1]
					}
					if greatCircleKM(p.Lat, p.Lon, q.Lat, q.Lon) <= chainKM {
						return ref, true
					}
				}
			}
		}
		return endRef{}, false
	}
	var out [][]LatLon
	for i := range runs {
		if used[i] || len(runs[i]) == 0 {
			continue
		}
		used[i] = true
		chain := append([]LatLon(nil), runs[i]...)
		// Extend forwards from the tail, then backwards from the head.
		for {
			ref, ok := findNext(chain[len(chain)-1], -1)
			if !ok {
				break
			}
			used[ref.run] = true
			r := runs[ref.run]
			if ref.head {
				chain = append(chain, r[1:]...)
			} else {
				for j := len(r) - 2; j >= 0; j-- {
					chain = append(chain, r[j])
				}
			}
		}
		for {
			ref, ok := findNext(chain[0], -1)
			if !ok {
				break
			}
			used[ref.run] = true
			r := runs[ref.run]
			var prefix []LatLon
			if ref.head {
				// The other run starts here; it runs away from us, so it is
				// reversed to lead in.
				for j := len(r) - 1; j >= 1; j-- {
					prefix = append(prefix, r[j])
				}
			} else {
				prefix = append(prefix, r[:len(r)-1]...)
			}
			chain = append(prefix, chain...)
		}
		out = append(out, chain)
	}
	return out
}

// thinKM is how far a point may sit off the line between its neighbours
// before it is worth keeping. A kilometre is far below anything else measured
// here -- the join tolerance is 75 -- and it turns road tracings into the few
// hundred vertices that matter.
const thinKM = 1.0

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

// maxNetEdges is the most a set of networks may hold before it is refused.
// Two million edges is forty times the whole submarine map and thirty times
// the African land set after chaining; a file that produces more is either
// not a route map or is one this code cannot afford, and either way the
// answer is to leave it on disk and say so rather than hold it in memory on
// a firewall. The operator chose the URL; the operator gets the message.
const maxNetEdges = 2_000_000

// netSize is how much a set of networks holds.
func netSize(nets []cableNet) (pts, edges int) {
	for i := range nets {
		pts += len(nets[i].Pts)
		for _, adj := range nets[i].Adj {
			edges += len(adj)
		}
	}
	return pts, edges
}
