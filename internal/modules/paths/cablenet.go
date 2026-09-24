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

// buildNet stitches a cable's runs together. The point counts are small --
// tens, not thousands -- so joining every run end to every other is cheap and
// there is no need for anything cleverer.
func buildNet(c Cable) cableNet {
	n := cableNet{Name: c.Name}
	runOf := []int{}
	for ri, run := range c.Legs {
		for _, p := range run {
			n.Pts = append(n.Pts, p)
			runOf = append(runOf, ri)
		}
	}
	n.Adj = make([][]cableEdge, len(n.Pts))
	// Along each run.
	base := 0
	for _, run := range c.Legs {
		for i := 1; i < len(run); i++ {
			a, b := base+i-1, base+i
			km := greatCircleKM(run[i-1].Lat, run[i-1].Lon, run[i].Lat, run[i].Lon)
			n.Adj[a] = append(n.Adj[a], cableEdge{b, km})
			n.Adj[b] = append(n.Adj[b], cableEdge{a, km})
		}
		base += len(run)
	}
	// Between runs, wherever they meet.
	for i := range n.Pts {
		for j := i + 1; j < len(n.Pts); j++ {
			if runOf[i] == runOf[j] {
				continue
			}
			km := greatCircleKM(n.Pts[i].Lat, n.Pts[i].Lon, n.Pts[j].Lat, n.Pts[j].Lon)
			if km > joinKM {
				continue
			}
			n.Adj[i] = append(n.Adj[i], cableEdge{j, km})
			n.Adj[j] = append(n.Adj[j], cableEdge{i, km})
		}
	}
	return n
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
