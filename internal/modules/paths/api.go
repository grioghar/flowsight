package paths

// What the page asks for.
//
// Enrichment happens here rather than at trace time. Names and locations
// change, databases get updated, and a route measured last week should be
// read with today's answers rather than the ones that were current when the
// probe went out.

import (
	"math"
	"sort"
	"strconv"
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
	//
	// The filter takes every address the device holds, not the one that was
	// clicked. A laptop answers to an IPv4 lease and a fistful of rotating
	// IPv6 privacy addresses, and filtering on one of them would show a
	// fraction of where that laptop has actually been.
	if dev := strings.TrimSpace(r.Q("device", "")); dev != "" {
		addrs := m.addressesOf(dev)
		ph := make([]string, len(addrs))
		for i, a := range addrs {
			ph[i] = "?"
			args = append(args, a)
		}
		where = `WHERE dst IN (SELECT DISTINCT dst_ip FROM flows WHERE dst_ip <> '' AND src_ip IN (` +
			strings.Join(ph, ",") + `))`
	}
	rows, err := m.hops(where, args...)
	if err != nil {
		return nil, err
	}
	g := buildGraph(rows)
	m.locate(g.Nodes)
	h := m.home()
	m.checkPlausible(g.Nodes, h)
	m.annotateCables(g)
	g = filterGraph(g, r.Q("country", ""), float64(r.QInt("max_latency", 0, 0, 100000)), r.QInt("max_hops", 0, 0, 64))
	g.Home = &h
	return g, nil
}

// apiCables hands the map over for drawing, thinned to the number of points
// asked for. The full file carries far more detail than a line a few hundred
// pixels long can show.
func (m *Module) apiCables(r *core.Req) (any, error) {
	m.mu.Lock()
	cables, cerr := m.cables, m.cableErr
	m.mu.Unlock()
	detail := r.QInt("detail", 40, 4, 400)
	type outCable struct {
		Name string         `json:"name"`
		KM   float64        `json:"km"`
		Runs [][][2]float64 `json:"runs"` // lon,lat, as GeoJSON has it
	}
	out := make([]outCable, 0, len(cables))
	for _, c := range cables {
		oc := outCable{Name: c.Name, KM: math.Round(c.KM)}
		for _, run := range c.Legs {
			step := len(run) / detail
			if step < 1 {
				step = 1
			}
			pts := make([][2]float64, 0, len(run)/step+2)
			for i := 0; i < len(run); i += step {
				pts = append(pts, [2]float64{run[i].Lon, run[i].Lat})
			}
			last := run[len(run)-1]
			if len(pts) == 0 || pts[len(pts)-1] != [2]float64{last.Lon, last.Lat} {
				pts = append(pts, [2]float64{last.Lon, last.Lat})
			}
			if len(pts) >= 2 {
				oc.Runs = append(oc.Runs, pts)
			}
		}
		if len(oc.Runs) > 0 {
			out = append(out, oc)
		}
	}
	return map[string]any{"cables": out, "error": cerr,
		"attribution": "Submarine cable routes from TeleGeography's public cable map.",
		"note":        "Drawn for context. A traceroute never names a cable, so no leg is claimed to follow one."}, nil
}

func (m *Module) apiGetHome(r *core.Req) (any, error) {
	h := m.home()
	out := map[string]any{
		"configured": core.Str(m.ctx.Settings(), "home", ""),
		"ok":         h.OK, "lat": h.Lat, "lon": h.Lon, "source": h.Source,
		"note": "Declaring this matters more than it looks: it is the reference for deciding whether a hop could be where the database claims. An origin that is out by a few hundred kilometres turns correct placements into impossible ones and back again.",
	}
	// What the public address would give, offered as a starting point.
	if ip := m.publicAddress(); ip != "" {
		out["public_address"] = ip
		if m.rdns != nil {
			if info, ok := m.rdns.Lookup([]string{ip})[ip]; ok {
				out["detected"] = map[string]any{
					"lat": info.Lat, "lon": info.Lon, "city": info.City,
					"region": info.Region, "country": info.Country,
				}
			}
		}
	}
	return out, nil
}

func (m *Module) apiSetHome(r *core.Req) (any, error) {
	var in struct {
		Lat   float64 `json:"lat"`
		Lon   float64 `json:"lon"`
		Clear bool    `json:"clear"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	value := ""
	if !in.Clear {
		v := strconv.FormatFloat(in.Lat, 'f', 4, 64) + "," + strconv.FormatFloat(in.Lon, 'f', 4, 64)
		if _, _, ok := parseLatLon(v); !ok {
			return nil, core.BadRequest("latitude must be between -90 and 90, longitude between -180 and 180")
		}
		value = v
	}
	if err := m.ctx.Config.SetModule("paths", map[string]any{"home": value}); err != nil {
		return nil, err
	}
	h := m.home()
	return map[string]any{"ok": true, "lat": h.Lat, "lon": h.Lon, "source": h.Source}, nil
}

// addressesOf expands one address into every address the same device holds,
// found through its hardware address. An address with no device behind it,
// or one FlowSight has never seen, stands for itself.
func (m *Module) addressesOf(addr string) []string {
	rows, err := m.ctx.Store.Rows(
		`SELECT ip FROM hosts WHERE mac <> '' AND mac = (SELECT mac FROM hosts WHERE ip = ? LIMIT 1)`, addr)
	if err != nil || len(rows) == 0 {
		return []string{addr}
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		if ip, _ := r["ip"].(string); ip != "" {
			out = append(out, ip)
		}
	}
	if len(out) == 0 {
		return []string{addr}
	}
	return out
}

// apiDevices lists the devices whose traffic has a measured route, one entry
// per device rather than one per address: a laptop with an IPv4 lease and six
// rotating IPv6 addresses is one thing to filter by, not seven.
func (m *Module) apiDevices(r *core.Req) (any, error) {
	rows, err := m.ctx.Store.Rows(`
		SELECT f.src_ip AS ip, COUNT(DISTINCT f.dst_ip) AS destinations
		FROM flows f JOIN path_runs p ON p.dst = f.dst_ip
		WHERE f.src_ip <> '' GROUP BY f.src_ip`)
	if err != nil {
		return nil, err
	}
	type dev struct {
		Key          string   `json:"key"`
		Name         string   `json:"name,omitempty"`
		Addresses    []string `json:"addresses"`
		Destinations int      `json:"destinations"`
	}
	byKey := map[string]*dev{}
	for _, row := range rows {
		ip, _ := row["ip"].(string)
		if ip == "" {
			continue
		}
		key, name := ip, ""
		if m.identity != nil {
			if mac := m.identity.MAC(ip); mac != "" {
				key = mac
			}
			name = m.identity.Name(ip)
		}
		d := byKey[key]
		if d == nil {
			d = &dev{Key: ip, Name: name} // the key the filter uses is an address
			byKey[key] = d
		}
		if d.Name == "" {
			d.Name = name
		}
		d.Addresses = append(d.Addresses, ip)
		d.Destinations += int(asInt(row["destinations"]))
	}
	out := make([]dev, 0, len(byKey))
	for _, k := range sortedKeys(byKey) {
		d := byKey[k]
		sort.Strings(d.Addresses)
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Destinations > out[j].Destinations })
	return map[string]any{"devices": out,
		"note": "One entry per device. Filtering by one covers every address it holds, which for anything speaking IPv6 is several."}, nil
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
