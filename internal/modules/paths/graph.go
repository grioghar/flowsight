package paths

// Turning many routes into one picture.
//
// Every destination's route starts the same way: this gateway, the modem, the
// carrier's first few routers. Drawn literally, that is two hundred lines on
// top of each other and nothing readable. So the routes are folded into a
// graph, where a leg carries the set of destinations that use it, and only
// diverges where the routes do.
//
// Two kinds of sharing happen and they are not the same thing. Different
// destinations sharing the same router is one: that leg is drawn once and
// carries both. A single position answering from several addresses is the
// other, because carriers balance traffic across parallel links; those are
// one node with several addresses, not several nodes.

import (
	"fmt"
	"sort"
	"strings"
)

// Node is one position on the map: a router, or a group of routers that stand
// in the same place on the same leg.
type Node struct {
	ID      string   `json:"id"`
	IPs     []string `json:"ips"`
	Names   []string `json:"names,omitempty"`
	Country string   `json:"country,omitempty"`
	Region  string   `json:"region,omitempty"`
	City    string   `json:"city,omitempty"`
	Lat     float64  `json:"lat,omitempty"`
	Lon     float64  `json:"lon,omitempty"`
	// Located says whether the coordinates mean anything. A great many hops
	// have none, and a map that silently places them at zero puts a cluster of
	// routers in the Gulf of Guinea.
	Located bool    `json:"located"`
	Source  string  `json:"location_source,omitempty"` // "database", "name", or empty
	Index   int     `json:"index"`                     // distance from here, in hops
	RTT     float64 `json:"rtt_ms,omitempty"`
	Silent  bool    `json:"silent,omitempty"` // nothing answered at this position
	// Impossible marks a placement the measured latency rules out: the point
	// is too far away to have answered as quickly as it did. The location is
	// wrong, not the measurement.
	Impossible bool `json:"impossible,omitempty"`
	// Tight marks a placement the latency does not forbid but comes close
	// enough to that it would need a perfect path. Kept apart from Impossible
	// because "provably wrong" and "probably wrong" are different claims and
	// collapsing them would either overstate the one or hide the other.
	Tight      bool    `json:"tight,omitempty"`
	DistanceKM float64 `json:"distance_km,omitempty"`
	FloorMS    float64 `json:"floor_ms,omitempty"`
	Why        string  `json:"why,omitempty"`
	// DatabaseSaid records where the address database put this hop, kept only
	// when the router's own name contradicted it. A reader who trusts the
	// database more than the naming convention can see both and judge.
	DatabaseSaid string  `json:"database_said,omitempty"`
	MovedKM      float64 `json:"moved_km,omitempty"`
	DBLat        float64 `json:"db_lat,omitempty"`
	DBLon        float64 `json:"db_lon,omitempty"`
	// Detail is who runs this hop and, where it can be told, which building.
	// Kept as a pointer so a hop nothing is known about costs nothing in the
	// payload rather than carrying a page of empty fields.
	Detail *Detail `json:"detail,omitempty"`
}

// Leg is one step from one node to the next, and everything that uses it.
type Leg struct {
	From         string   `json:"from"`
	To           string   `json:"to"`
	Destinations []string `json:"destinations"`
	Shared       bool     `json:"shared"` // used by more than one destination
	// Cables a leg could have crossed, once the ones too long to have
	// produced the measured latency are discarded. Never one answer: a
	// traceroute cannot say which cable carried a packet.
	Cables     []Candidate `json:"cables,omitempty"`
	StraightKM float64     `json:"straight_km,omitempty"`
	// Gap marks a leg that stands in for a stretch of route whose hops could
	// not be placed. The traffic certainly went this way; what is unknown is
	// where it was in between, so the leg is drawn differently rather than
	// presented as one hop to the next.
	Gap     bool `json:"gap,omitempty"`
	Through int  `json:"through,omitempty"` // hops crossed that have no position
}

// Graph is what the map draws.
type Graph struct {
	Nodes []Node `json:"nodes"`
	Legs  []Leg  `json:"legs"`
	Home  *Home  `json:"home,omitempty"`
	Note  string `json:"note"`
}

// hopRow is one stored hop.
type hopRow struct {
	Dst   string
	Index int
	IP    string
	RTT   float64
}

// buildGraph folds routes into nodes and legs.
//
// A node's identity is its position and its addresses together, not the
// address alone: the same router can appear at different distances on
// different routes, and merging those would draw a path that doubles back on
// itself.
func buildGraph(rows []hopRow) Graph {
	// Group by destination, then by hop index, keeping addresses together.
	byDst := map[string]map[int][]hopRow{}
	for _, r := range rows {
		if byDst[r.Dst] == nil {
			byDst[r.Dst] = map[int][]hopRow{}
		}
		byDst[r.Dst][r.Index] = append(byDst[r.Dst][r.Index], r)
	}

	nodes := map[string]*Node{}
	legs := map[string]*Leg{}

	for _, dst := range sortedKeys(byDst) {
		hops := byDst[dst]
		idxs := make([]int, 0, len(hops))
		for i := range hops {
			idxs = append(idxs, i)
		}
		sort.Ints(idxs)

		prev := ""
		for _, i := range idxs {
			id, n := nodeFor(i, hops[i])
			n.ID = id // the legs refer to nodes by this; leaving it empty drops every leg
			if existing, ok := nodes[id]; ok {
				mergeAddresses(existing, n)
			} else {
				nodes[id] = n
			}
			if prev != "" && prev != id {
				key := prev + ">" + id
				l := legs[key]
				if l == nil {
					l = &Leg{From: prev, To: id}
					legs[key] = l
				}
				if !contains(l.Destinations, dst) {
					l.Destinations = append(l.Destinations, dst)
				}
			}
			prev = id
		}
	}

	g := Graph{Note: "A leg shared by several destinations is drawn once. A position answering from several addresses is one node with several addresses, which is what load balancing across parallel links looks like. Hops that never answered are kept in place so the numbering stays honest."}
	for _, id := range sortedKeys(nodes) {
		g.Nodes = append(g.Nodes, *nodes[id])
	}
	for _, k := range sortedKeys(legs) {
		l := legs[k]
		sort.Strings(l.Destinations)
		l.Shared = len(l.Destinations) > 1
		g.Legs = append(g.Legs, *l)
	}
	return g
}

// nodeFor builds the node for one position on one route.
func nodeFor(index int, rows []hopRow) (string, *Node) {
	n := &Node{Index: index}
	var ips []string
	best := -1.0
	for _, r := range rows {
		if r.IP == "" {
			continue
		}
		if !contains(ips, r.IP) {
			ips = append(ips, r.IP)
		}
		if r.RTT >= 0 && (best < 0 || r.RTT < best) {
			best = r.RTT
		}
	}
	sort.Strings(ips)
	n.IPs = ips
	if best >= 0 {
		n.RTT = best
	}
	if len(ips) == 0 {
		n.Silent = true
		// Silent positions are per route: two routes both going quiet at hop
		// seven are not passing through the same router, and pretending
		// otherwise would join paths that have nothing to do with each other.
		return fmt.Sprintf("silent@%d@%s", index, rows[0].Dst), n
	}
	return fmt.Sprintf("h%d:%s", index, strings.Join(ips, ",")), n
}

func mergeAddresses(into, from *Node) {
	for i, ip := range from.IPs {
		if !contains(into.IPs, ip) {
			into.IPs = append(into.IPs, ip)
			if i < len(from.IPs) && from.RTT > 0 && (into.RTT == 0 || from.RTT < into.RTT) {
				into.RTT = from.RTT
			}
		}
	}
	sort.Strings(into.IPs)
}

// bridgeGaps joins placed hops across the ones that could not be placed.
//
// Most hops have no usable position -- a great many never answer at all, and
// plenty that do sit in address blocks no database can locate. A leg is only
// drawable when both of its ends are placed, so a placed hop whose neighbours
// are not becomes a dot on the map with nothing attached to it. On this
// network that was one placed dot in five: a scatter of points that look
// unreachable, when in truth every one of them is on a route that arrives
// somewhere.
//
// So where a placed hop is followed, further along the same route, by another
// placed hop, they are joined. The leg is marked as a gap and carries how many
// unplaced hops it covers, because it is not the same claim as a leg between
// adjacent routers and must not be drawn as though it were.
func bridgeGaps(g *Graph) {
	byID := make(map[string]*Node, len(g.Nodes))
	for i := range g.Nodes {
		byID[g.Nodes[i].ID] = &g.Nodes[i]
	}
	// What each destination's route passes through, and what is already joined.
	onRoute := map[string]map[string]bool{}
	direct := map[string]bool{}
	for _, l := range g.Legs {
		direct[l.From+">"+l.To] = true
		for _, d := range l.Destinations {
			if onRoute[d] == nil {
				onRoute[d] = map[string]bool{}
			}
			onRoute[d][l.From] = true
			onRoute[d][l.To] = true
		}
	}

	added := map[string]*Leg{}
	for _, dst := range sortedKeys(onRoute) {
		ids := make([]string, 0, len(onRoute[dst]))
		for id := range onRoute[dst] {
			ids = append(ids, id)
		}
		// Hop number is the order of travel, and it is the only ordering that
		// means anything here: two hops can share an address and a route never
		// visits the same distance twice.
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

		prev, skipped := "", 0
		for _, id := range ids {
			n := byID[id]
			if n == nil {
				continue
			}
			if !n.Located {
				if prev != "" {
					skipped++
				}
				continue
			}
			if prev != "" && skipped > 0 && !direct[prev+">"+id] {
				key := prev + ">" + id
				l := added[key]
				if l == nil {
					l = &Leg{From: prev, To: id, Gap: true, Through: skipped}
					added[key] = l
				}
				if skipped > l.Through {
					l.Through = skipped
				}
				if !contains(l.Destinations, dst) {
					l.Destinations = append(l.Destinations, dst)
				}
			}
			prev, skipped = id, 0
		}
	}

	for _, k := range sortedKeys(added) {
		l := added[k]
		sort.Strings(l.Destinations)
		l.Shared = len(l.Destinations) > 1
		g.Legs = append(g.Legs, *l)
	}
}
