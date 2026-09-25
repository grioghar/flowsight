package policy

// What a policy's country rule is matching, from two sources that answer
// different questions. The sessions table says which devices talked to
// which far ends in denied countries, with names, domains and bytes: that is
// what the rule matches, computed the way the rule is compiled (members
// after exclusions, denied countries, anycast left out). The firewall's own
// log says which packets the rule really counted: exact, but bare addresses.
// Both are returned; the page shows the first with the second beside it.

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

type matchDest struct {
	IP       string `json:"ip"`
	Name     string `json:"name,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Country  string `json:"country"`
	Port     int    `json:"port,omitempty"`
	App      string `json:"app,omitempty"`
	Sessions int64  `json:"sessions"`
	BytesIn  int64  `json:"bytes_in"`
	BytesOut int64  `json:"bytes_out"`
	LastSeen int64  `json:"last_seen"`
}

type matchDevice struct {
	IP        string       `json:"ip"`
	Name      string       `json:"name,omitempty"`
	MAC       string       `json:"mac,omitempty"`
	Sessions  int64        `json:"sessions"`
	BytesOut  int64        `json:"bytes_out"`
	Countries []string     `json:"countries"`
	Dests     []*matchDest `json:"destinations"`
	byDest    map[string]*matchDest
	byCC      map[string]int64
}

type hitDest struct {
	IP      string `json:"ip"`
	Port    int    `json:"port,omitempty"`
	Proto   string `json:"proto,omitempty"`
	Name    string `json:"name,omitempty"`
	Domain  string `json:"domain,omitempty"`
	Country string `json:"country,omitempty"`
	Packets int64  `json:"packets"`
	Last    int64  `json:"last"`
}

type hitDevice struct {
	IP      string     `json:"ip"`
	Name    string     `json:"name,omitempty"`
	Packets int64      `json:"packets"`
	Dests   []*hitDest `json:"destinations"`
	byDest  map[string]*hitDest
}

func (m *Module) apiMatches(r *core.Req) (any, error) {
	name := r.Q("name", "")
	doc := m.Doc()
	var pol *core.Policy
	for i := range doc.Policies {
		if doc.Policies[i].Name == name {
			pol = &doc.Policies[i]
		}
	}
	if pol == nil {
		return nil, fmt.Errorf("no policy named %q", name)
	}
	hours := r.QInt("hours", 24, 1, 24*30)
	since := time.Now().Add(-time.Duration(hours) * time.Hour).Unix()
	res, _ := m.ctx.Service("member_resolver").(core.MemberResolver)
	identity, _ := m.ctx.Service("identity").(core.Identity)

	// Members as the firewall sees them.
	excl := map[string]bool{}
	for _, c := range doc.ExcludedCIDRs(res) {
		excl[c] = true
	}
	var nets []*net.IPNet
	for _, mm := range doc.Members(pol, res) {
		if excl[mm] && !pol.Match.EvenExcluded {
			continue
		}
		if _, n, err := net.ParseCIDR(mm); err == nil {
			nets = append(nets, n)
		}
	}
	inMembers := func(ip string) bool {
		a := net.ParseIP(ip)
		if a == nil {
			return false
		}
		for _, n := range nets {
			if n.Contains(a) {
				return true
			}
		}
		return false
	}

	// The denied set.
	home := ""
	if h, ok := m.ctx.Service("home").(core.HomeService); ok {
		home = h.HomeCountry()
	}
	deny := map[string]bool{}
	for _, c := range pol.Deny.Countries {
		deny[strings.ToUpper(c)] = true
	}
	allow := map[string]bool{}
	for _, c := range pol.Deny.CountriesExcept {
		allow[strings.ToUpper(c)] = true
	}
	except := len(pol.Deny.CountriesExcept) > 0
	if except && home != "" {
		allow[home] = true
	}
	denied := func(cc string) bool {
		cc = strings.ToUpper(cc)
		if cc == "" || cc == "-" {
			return false
		}
		if except {
			return !allow[cc]
		}
		return deny[cc]
	}
	countryRule := except || len(deny) > 0

	out := map[string]any{"policy": pol.Name, "action": pol.Action, "hours": hours, "since": since, "home_country": home,
		"members": len(nets), "country_rule": countryRule, "countries": pol.Deny.Countries, "countries_except": pol.Deny.CountriesExcept}

	// Sessions the rule matches.
	devs := map[string]*matchDevice{}
	var order []string
	nameOf := func(ip string) string {
		if identity != nil {
			return identity.Name(ip)
		}
		return ""
	}
	if countryRule && len(nets) > 0 {
		// Aggregate flows in SQL by (src_ip, dst_ip, dst_port, app, domain, country).
		// This eliminates the LIMIT 60000 truncation and pushes aggregation to SQL.
		rows, err := m.ctx.Store.Rows(`SELECT src_ip, dst_ip, dst_port, app, domain, upper(country) AS cc,
			COUNT(*) AS sessions, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out, MAX(COALESCE(end_ts,ts)) AS seen
			FROM flows WHERE COALESCE(end_ts,ts)>=? AND country<>'' AND country<>'-' AND COALESCE(anycast,0)=0
			GROUP BY src_ip, dst_ip, dst_port, app, domain, cc
			ORDER BY src_ip, sessions DESC`, since)
		if err != nil {
			return nil, err
		}
		memberMemo := map[string]bool{}
		for _, row := range rows {
			src, _ := row["src_ip"].(string)
			cc, _ := row["cc"].(string)
			if !denied(cc) {
				continue
			}
			ok, seen := memberMemo[src]
			if !seen {
				ok = inMembers(src)
				memberMemo[src] = ok
			}
			if !ok {
				continue
			}
			mac := ""
			if identity != nil {
				mac = identity.MAC(src)
			}
			key := src
			if mac != "" {
				key = mac
			}
			d := devs[key]
			if d == nil {
				d = &matchDevice{IP: src, Name: nameOf(src), MAC: mac, byDest: map[string]*matchDest{}, byCC: map[string]int64{}}
				devs[key] = d
				order = append(order, key)
			}
			dst, _ := row["dst_ip"].(string)
			port := int(toI(row["dst_port"]))
			x := d.byDest[dst]
			if x == nil {
				dom, _ := row["domain"].(string)
				app, _ := row["app"].(string)
				x = &matchDest{IP: dst, Name: nameOf(dst), Domain: dom, Country: cc, Port: port, App: app}
				d.byDest[dst] = x
				d.Dests = append(d.Dests, x)
			}
			x.Sessions += toI(row["sessions"])
			x.BytesIn += toI(row["bytes_in"])
			x.BytesOut += toI(row["bytes_out"])
			if s := toI(row["seen"]); s > x.LastSeen {
				x.LastSeen = s
			}
			d.Sessions += toI(row["sessions"])
			d.BytesOut += toI(row["bytes_out"])
			d.byCC[cc] += toI(row["sessions"])
		}
	}
	devices := make([]*matchDevice, 0, len(order))
	for _, k := range order {
		d := devs[k]
		for cc := range d.byCC {
			d.Countries = append(d.Countries, cc)
		}
		sort.Slice(d.Countries, func(i, j int) bool { return d.byCC[d.Countries[i]] > d.byCC[d.Countries[j]] })
		sort.Slice(d.Dests, func(i, j int) bool { return d.Dests[i].Sessions > d.Dests[j].Sessions })
		if len(d.Dests) > 40 {
			d.Dests = d.Dests[:40]
		}
		devices = append(devices, d)
	}
	sort.Slice(devices, func(i, j int) bool { return devices[i].Sessions > devices[j].Sessions })
	out["devices"] = devices

	// What the firewall logged for this policy's rules.
	hrows, err := m.ctx.Store.Rows(`SELECT ts, src_ip, dst_ip, dst_port, proto FROM policy_hits WHERE policy=? AND ts>=? ORDER BY ts DESC LIMIT 20000`, pol.Name, since)
	hdevs := map[string]*hitDevice{}
	var horder []string
	var total int64
	look, _ := m.ctx.Service("enrich").(core.CountryLookup)
	if err == nil {
		for _, row := range hrows {
			src, _ := row["src_ip"].(string)
			dst, _ := row["dst_ip"].(string)
			h := hdevs[src]
			if h == nil {
				h = &hitDevice{IP: src, Name: nameOf(src), byDest: map[string]*hitDest{}}
				hdevs[src] = h
				horder = append(horder, src)
			}
			port := int(toI(row["dst_port"]))
			proto, _ := row["proto"].(string)
			k := fmt.Sprintf("%s/%d/%s", dst, port, proto)
			x := h.byDest[k]
			if x == nil {
				x = &hitDest{IP: dst, Port: port, Proto: proto, Name: nameOf(dst)}
				// The session table usually knows the domain and country.
				if fr, err := m.ctx.Store.Rows(`SELECT domain, upper(country) AS cc FROM flows WHERE dst_ip=? AND COALESCE(end_ts,ts)>=? ORDER BY id DESC LIMIT 1`, dst, since); err == nil && len(fr) > 0 {
					x.Domain, _ = fr[0]["domain"].(string)
					x.Country, _ = fr[0]["cc"].(string)
				}
				// A packet the session table never saw (a lone NTP query,
				// say) still has a registered country in the database.
				if x.Country == "" && look != nil {
					x.Country = look.CountryOf(dst)
				}
				h.byDest[k] = x
				h.Dests = append(h.Dests, x)
			}
			x.Packets++
			if ts := toI(row["ts"]); ts > x.Last {
				x.Last = ts
			}
			h.Packets++
			total++
		}
	}
	hdevices := make([]*hitDevice, 0, len(horder))
	for _, k := range horder {
		h := hdevs[k]
		sort.Slice(h.Dests, func(i, j int) bool { return h.Dests[i].Packets > h.Dests[j].Packets })
		hdevices = append(hdevices, h)
	}
	sort.Slice(hdevices, func(i, j int) bool { return hdevices[i].Packets > hdevices[j].Packets })
	logStatus := map[string]any{}
	if fw, ok := m.ctx.Service("firewall").(interface{ LogStatus() map[string]any }); ok {
		logStatus = fw.LogStatus()
	}
	out["logged"] = map[string]any{"packets": total, "devices": hdevices, "log": logStatus}
	return out, nil
}

func toI(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int:
		return int64(x)
	case float64:
		return int64(x)
	case []byte:
		var n int64
		fmt.Sscan(string(x), &n)
		return n
	case string:
		var n int64
		fmt.Sscan(x, &n)
		return n
	}
	return 0
}
