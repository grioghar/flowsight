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
}

// Leg is one step from one node to the next, and everything that uses it.
type Leg struct {
	From         string   `json:"from"`
	To           string   `json:"to"`
	Destinations []string `json:"destinations"`
	Shared       bool     `json:"shared"` // used by more than one destination
}

// Graph is what the map draws.
type Graph struct {
	Nodes []Node `json:"nodes"`
	Legs  []Leg  `json:"legs"`
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
