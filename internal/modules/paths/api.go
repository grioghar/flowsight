package paths

// What the page asks for.
//
// Enrichment happens here rather than at trace time. Names and locations
// change, databases get updated, and a route measured last week should be
// read with today's answers rather than the ones that were current when the
// probe went out.

import (
	"sort"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
	"github.com/grioghar/flowsight/internal/modules/enrich"
)

func (m *Module) apiStatus(r *core.Req) (any, error) {
	m.mu.Lock()
	last, traced, err := m.lastRun, m.traced, m.lastErr
	m.mu.Unlock()
	var dsts, hops int64
	if rows, e := m.ctx.Store.Rows(`SELECT COUNT(*) AS n FROM path_runs`); e == nil && len(rows) > 0 {
		dsts = asInt(rows[0]["n"])
	}
	if rows, e := m.ctx.Store.Rows(`SELECT COUNT(*) AS n FROM path_hops WHERE ip <> ''`); e == nil && len(rows) > 0 {
		hops = asInt(rows[0]["n"])
	}
	return map[string]any{
		"active":   core.Bool(m.ctx.Settings(), "active", false),
		"last_run": epoch(last), "traced_this_session": traced,
		"destinations": dsts, "hops": hops, "error": err,
		"note": "Routes are measured to destinations this network has already contacted. Nothing else is probed.",
	}, nil
}

func (m *Module) apiDestinations(r *core.Req) (any, error) {
	rows, err := m.ctx.Store.Rows(`
		SELECT r.dst AS dst, r.ts AS ts, r.hops AS hops, r.complete AS complete, r.err AS err,
		       (SELECT COUNT(*) FROM path_hops h WHERE h.dst = r.dst AND h.ip <> '') AS answered
		FROM path_runs r ORDER BY r.ts DESC LIMIT ?`, r.QInt("limit", 200, 1, 2000))
	if err != nil {
		return nil, err
	}
	ips := make([]string, 0, len(rows))
	for _, x := range rows {
		if s, _ := x["dst"].(string); s != "" {
			ips = append(ips, s)
		}
	}
	info := m.enrich(ips)
	for _, x := range rows {
		if s, _ := x["dst"].(string); s != "" {
			if i, ok := info[s]; ok {
				x["name"], x["country"], x["city"] = i.Name, i.Country, i.City
			}
		}
	}
	return map[string]any{"destinations": rows}, nil
}

func (m *Module) apiPath(r *core.Req) (any, error) {
	dst := strings.TrimSpace(r.Q("dst", ""))
	if dst == "" {
		return nil, core.BadRequest("dst is required")
	}
	rows, err := m.hops(`WHERE dst = ?`, dst)
	if err != nil {
		return nil, err
	}
	g := buildGraph(rows)
	m.locate(g.Nodes)
	sort.Slice(g.Nodes, func(i, j int) bool { return g.Nodes[i].Index < g.Nodes[j].Index })
	return map[string]any{"destination": dst, "hops": g.Nodes,
		"note": "A hop with several addresses answered from more than one router, which is how a carrier balances across parallel links. A silent hop did not answer; the traffic still passed through it."}, nil
}

func (m *Module) apiGraph(r *core.Req) (any, error) {
	where, args := "", []any{}
	// A device filter is a join: the device's flows name destinations, and
	// those destinations have routes. No device is ever traced.
	if dev := strings.TrimSpace(r.Q("device", "")); dev != "" {
		where = `WHERE dst IN (SELECT DISTINCT dst_ip FROM flows WHERE src_ip = ? AND dst_ip <> '')`
		args = append(args, dev)
	}
	rows, err := m.hops(where, args...)
	if err != nil {
		return nil, err
	}
	g := buildGraph(rows)
	m.locate(g.Nodes)
	g = filterGraph(g, r.Q("country", ""), float64(r.QInt("max_latency", 0, 0, 100000)), r.QInt("max_hops", 0, 0, 64))
	return g, nil
}

// hops reads stored hops, optionally narrowed.
func (m *Module) hops(where string, args ...any) ([]hopRow, error) {
	rows, err := m.ctx.Store.Rows(`SELECT dst, idx, ip, rtt_ms FROM path_hops `+where+` ORDER BY dst, idx`, args...)
	if err != nil {
		return nil, err
	}
	out := make([]hopRow, 0, len(rows))
	for _, x := range rows {
		dst, _ := x["dst"].(string)
		ip, _ := x["ip"].(string)
		rtt := -1.0
		if v, ok := x["rtt_ms"].(float64); ok {
			rtt = v
		}
		out = append(out, hopRow{Dst: dst, Index: int(asInt(x["idx"])), IP: ip, RTT: rtt})
	}
	return out, nil
}

// locate fills in names and coordinates for every node.
func (m *Module) locate(nodes []Node) {
	var ips []string
	for _, n := range nodes {
		ips = append(ips, n.IPs...)
	}
	info := m.enrich(ips)
	for i := range nodes {
		n := &nodes[i]
		for _, ip := range n.IPs {
			x, ok := info[ip]
			if !ok {
				continue
			}
			if x.Name != "" && !contains(n.Names, x.Name) {
				n.Names = append(n.Names, x.Name)
			}
			// The first address that has a location speaks for the node. They
			// are parallel links in the same place; if they disagree, one of
			// them is wrong and averaging would invent a third answer.
			if !n.Located && (x.Lat != 0 || x.Lon != 0) {
				n.Lat, n.Lon, n.Located, n.Source = x.Lat, x.Lon, true, "database"
			}
			if n.Country == "" {
				n.Country, n.Region, n.City = x.Country, x.Region, x.City
			}
		}
	}
}

func (m *Module) enrich(ips []string) map[string]enrich.Info {
	if m.rdns == nil || len(ips) == 0 {
		return map[string]enrich.Info{}
	}
	if len(ips) > 500 {
		ips = ips[:500]
	}
	return m.rdns.Lookup(ips)
}

// filterGraph narrows a graph, then drops legs whose ends no longer exist.
func filterGraph(g Graph, country string, maxLatency float64, maxHops int) Graph {
	country = strings.ToUpper(strings.TrimSpace(country))
	keep := map[string]bool{}
	var nodes []Node
	for _, n := range g.Nodes {
		if country != "" && strings.ToUpper(n.Country) != country {
			continue
		}
		if maxLatency > 0 && n.RTT > maxLatency {
			continue
		}
		if maxHops > 0 && n.Index > maxHops {
			continue
		}
		keep[n.ID] = true
		nodes = append(nodes, n)
	}
	var legs []Leg
	for _, l := range g.Legs {
		if keep[l.From] && keep[l.To] {
			legs = append(legs, l)
		}
	}
	g.Nodes, g.Legs = nodes, legs
	return g
}

// epoch reports a zero time as zero rather than as the year 1, which is what
// Unix() does with it and what a page then has to special-case.
func epoch(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func asInt(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int:
		return int64(x)
	case float64:
		return int64(x)
	}
	return 0
}
