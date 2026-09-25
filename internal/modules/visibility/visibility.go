// Package visibility reads flows, hosts and application identity from ntopng
// (nDPI underneath) and keeps them in the store. It publishes a flow bus so
// enforcement modules react to what was just seen without polling.
package visibility

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

// FlowBus lets modules subscribe to flows as they are observed.
type FlowBus struct {
	mu   sync.RWMutex
	subs []func([]core.Flow)
}

func (b *FlowBus) Subscribe(fn func([]core.Flow)) {
	b.mu.Lock()
	b.subs = append(b.subs, fn)
	b.mu.Unlock()
}

func (b *FlowBus) publish(fl []core.Flow) {
	b.mu.RLock()
	subs := make([]func([]core.Flow), len(b.subs))
	copy(subs, b.subs)
	b.mu.RUnlock()
	for _, s := range subs {
		func() {
			defer func() { recover() }()
			s(fl)
		}()
	}
}

type Module struct {
	epMu     sync.Mutex              // guards the site->endpoint memo below
	epBest   map[string]endpointPick // site -> endpoint, from the last join
	epKey    string                  // what that join was for
	epAt     time.Time               // and when
	ctx      *core.Context
	nt       *ntopng
	bus      *FlowBus
	mu       sync.Mutex
	seen     map[string]flowState // flow key -> last cumulative counters
	apps     map[string]appInfo   // l7 name -> category/breed
	ifs      []iface
	lastErr  string
	lastOK   time.Time
	identity core.Identity

	lastProvision time.Time
}

type flowState struct {
	bytesIn, bytesOut int64
	seenAt            time.Time
}

type appInfo = core.AppInfo

type iface struct {
	ID   int    `json:"ifid"`
	Name string `json:"ifname"`
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name: "visibility", Version: "1.0",
		Description:  "Flows, hosts, applications and throughput from ntopng/nDPI.",
		Capabilities: []string{core.CapTrafficObserve, core.CapAppObserve, core.CapHostInventory},
		Requires:     []string{"ntopng"},
		After:        []string{"identity"},
		Defaults: map[string]any{
			"ntopng_url":      "",
			"ntopng_user":     "admin",
			"ntopng_password": "admin",
			"ntopng_token":    "",
			"redis_addr":      "127.0.0.1:6379",
			"auto_account":    true,
			"poll_seconds":    10,
			"max_flows":       2000,
			"timeout_seconds": 15,
		},
		Schema: []core.SettingField{
			{Key: "ntopng_url", Label: "ntopng URL", Type: "string", Placeholder: "http://127.0.0.1:3000",
				Help: "Empty uses the platform default."},
			{Key: "ntopng_user", Label: "ntopng user", Type: "string"},
			{Key: "ntopng_password", Label: "ntopng password", Type: "secret"},
			{Key: "ntopng_token", Label: "ntopng API token", Type: "secret",
				Help: "Preferred over a password when set."},
			{Key: "auto_account", Label: "Create an ntopng account automatically", Type: "bool",
				Help: "When ntopng refuses the configured credentials, provision a 'flowsight' user through redis."},
			{Key: "redis_addr", Label: "ntopng redis address", Type: "string"},
			{Key: "poll_seconds", Label: "Poll interval (s)", Type: "int"},
			{Key: "max_flows", Label: "Flows per poll", Type: "int"},
		},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	m.bus = &FlowBus{}
	m.seen = map[string]flowState{}
	m.apps = map[string]appInfo{}
	m.identity, _ = ctx.Service("identity").(core.Identity)
	m.configure(ctx.Settings())
	ctx.Publish("flow_bus", m.bus)
	ctx.Publish("app_catalog", m)
	every := time.Duration(core.Int(ctx.Settings(), "poll_seconds", 10)) * time.Second
	if every < 3*time.Second {
		every = 3 * time.Second
	}
	ctx.Every("poll", every, m.poll)
	ctx.Every("catalog", time.Hour, m.loadCatalog)

	ctx.Route("GET", "/api/visibility/summary", m.apiSummary, core.Doc("Throughput, active flows and hosts right now"))
	ctx.Route("GET", "/api/visibility/flows", m.apiFlows, core.Doc("Recent flows"),
		core.Params("minutes", "window", "ip", "filter by either end", "app", "filter", "limit", "rows"))
	ctx.Route("GET", "/api/visibility/apps", m.apiApps, core.Doc("Application breakdown over a window"),
		core.Params("hours", "window", "ip", "one host"))
	ctx.Route("GET", "/api/visibility/top", m.apiTop, core.Doc("Top hosts, applications, categories, destinations"),
		core.Params("hours", "window", "limit", "rows"))
	ctx.Route("GET", "/api/visibility/timeseries", m.apiTimeseries, core.Doc("Metric series for charts"),
		core.Params("hours", "window", "metric", "name", "step", "seconds"))
	ctx.Route("GET", "/api/visibility/host", m.apiHost, core.Doc("Everything about one host"),
		core.Params("ip", "address", "hours", "window"))
	ctx.Route("GET", "/api/visibility/catalog", m.apiCatalog, core.Doc("Known applications and categories"))
	ctx.Panel(core.Panel{ID: "overview", Title: "Overview", Group: "Monitor", Order: 1, Icon: "overview"})
	ctx.Panel(core.Panel{ID: "flows", Title: "Sessions", Group: "Monitor", Order: 30, Icon: "flows"})
	ctx.Panel(core.Panel{ID: "apps", Title: "Applications", Group: "Monitor", Order: 40, Icon: "apps"})
	return nil
}

func (m *Module) configure(s map[string]any) {
	base := core.Str(s, "ntopng_url", "")
	if base == "" {
		base = m.ctx.Platform.NtopngURL
	}
	to := time.Duration(core.Int(s, "timeout_seconds", 15)) * time.Second
	m.mu.Lock()
	m.nt = newNtopng(base, core.Str(s, "ntopng_user", ""), core.Str(s, "ntopng_password", ""),
		core.Str(s, "ntopng_token", ""), to)
	m.mu.Unlock()
}

func (m *Module) OnConfigChange(s map[string]any) error { m.configure(s); return nil }

func (m *Module) Health() core.Health {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastErr != "" {
		return core.Health{OK: false, Detail: m.lastErr}
	}
	if m.lastOK.IsZero() {
		return core.Health{OK: true, Detail: "waiting for first poll"}
	}
	return core.Health{OK: true, Detail: fmt.Sprintf("%d interfaces, %d flows tracked", len(m.ifs), len(m.seen))}
}

// AppCategory implements the catalog service: nDPI category for an app name.
func (m *Module) AppCategory(app string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.apps[app].Category
}

// Apps returns the catalog.
func (m *Module) Apps() map[string]appInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]appInfo, len(m.apps))
	for k, v := range m.apps {
		out[k] = v
	}
	return out
}

// ---------------------------------------------------------------- polling

func (m *Module) loadCatalog() error {
	var rawCats json.RawMessage
	catNames := map[int]string{}
	if err := m.nt.get("l7/category/consts.lua", nil, &rawCats); err == nil {
		for _, c := range asList(rawCats) {
			if n := c.str("name", "cat_name"); n != "" {
				catNames[int(c.num("cat_id", "id"))] = n
			}
		}
	}
	var raw json.RawMessage
	if err := m.nt.get("l7/application/consts.lua", nil, &raw); err != nil {
		return err
	}
	apps := map[string]appInfo{}
	for _, a := range asList(raw) {
		name := a.str("name", "application")
		if name == "" {
			continue
		}
		cat := a.str("cat_name")
		if c := a.sub("category"); c != nil {
			cat = c.str("name", "cat_name")
		}
		if cat == "" {
			cat = catNames[int(a.num("cat_id"))]
		}
		apps[name] = appInfo{Category: cat, Breed: a.str("breed"), ID: int(a.num("appl_id", "id", "app_id"))}
	}
	// Breeds (Safe/Acceptable/Fun/Unsafe/Dangerous) come from the interface
	// l7 breakdown, which lists only apps seen so far; merge what it knows.
	var rawL7 json.RawMessage
	if err := m.nt.get("interface/l7/data.lua", url.Values{"ifid": {"0"}}, &rawL7); err == nil {
		for _, a := range asList(rawL7) {
			app := a.sub("application")
			if app == nil {
				continue
			}
			if ai, ok := apps[app.str("name")]; ok {
				ai.Breed = a.str("breed")
				apps[app.str("name")] = ai
			}
		}
	}
	if len(apps) == 0 {
		return fmt.Errorf("ntopng returned an empty application catalog")
	}
	m.mu.Lock()
	m.apps = apps
	m.mu.Unlock()
	return nil
}

// recoverAuth provisions a dedicated ntopng account when the configured one
// is refused. ntopng's default admin password cannot be used until it is
// changed interactively, which is the state every fresh install is in.
func (m *Module) recoverAuth() bool {
	s := m.ctx.Settings()
	if !core.Bool(s, "auto_account", true) {
		return false
	}
	m.mu.Lock()
	if time.Since(m.lastProvision) < 10*time.Minute {
		m.mu.Unlock()
		return false
	}
	m.lastProvision = time.Now()
	m.mu.Unlock()
	addr := core.Str(s, "redis_addr", "127.0.0.1:6379")
	pw, err := provisionNtopngUser(addr, "flowsight")
	if err != nil {
		m.ctx.Log.Warn("could not provision ntopng account", "error", err.Error())
		return false
	}
	if err := m.ctx.Config.SetModule(m.ctx.Name, map[string]any{"ntopng_user": "flowsight",
		"ntopng_password": pw, "ntopng_token": ""}); err != nil {
		m.ctx.Log.Warn("could not save ntopng credentials", "error", err.Error())
		return false
	}
	m.configure(m.ctx.Settings())
	m.ctx.Log.Info("provisioned ntopng account 'flowsight' through redis")
	m.ctx.Event("config", "provisioned an ntopng account for FlowSight", nil)
	return true
}

func (m *Module) fail(err error) error {
	m.mu.Lock()
	m.lastErr = err.Error()
	m.mu.Unlock()
	return err
}

func (m *Module) poll() error {
	var rawIfs json.RawMessage
	if err := m.nt.get("ntopng/interfaces.lua", nil, &rawIfs); err != nil {
		if errors.Is(err, errAuth) && m.recoverAuth() {
			err = m.nt.get("ntopng/interfaces.lua", nil, &rawIfs)
		}
		if err != nil {
			return m.fail(err)
		}
	}
	var ifs []iface
	for _, o := range asList(rawIfs) {
		ifs = append(ifs, iface{ID: int(o.num("ifid")), Name: o.str("ifname", "name")})
	}
	if len(ifs) == 0 {
		return m.fail(fmt.Errorf("ntopng reports no interfaces"))
	}
	m.mu.Lock()
	m.ifs = ifs
	if len(m.apps) == 0 {
		m.mu.Unlock()
		_ = m.loadCatalog()
	} else {
		m.mu.Unlock()
	}

	now := time.Now().Unix()
	var metrics []core.Metric
	var flows []core.Flow
	hostAgg := map[string]*core.HostUpdate{}
	maxFlows := core.Int(m.ctx.Settings(), "max_flows", 2000)

	for _, ifc := range ifs {
		q := url.Values{"ifid": {fmt.Sprint(ifc.ID)}}
		var data map[string]any
		if err := m.nt.get("interface/data.lua", q, &data); err != nil {
			return m.fail(err)
		}
		d := obj(data)
		lab := map[string]string{"interface": ifc.Name}
		bps, pps := d.num("throughput_bps"), d.num("throughput_pps")
		if th := d.sub("throughput"); th != nil {
			for _, dir := range []string{"upload", "download"} {
				if x := th.sub(dir); x != nil {
					bps += x.num("bps")
					pps += x.num("pps")
				}
			}
			if up := th.sub("upload"); up != nil {
				metrics = append(metrics, core.Metric{Name: "throughput_upload_bps", Labels: lab, Value: up.num("bps")})
			}
			if dn := th.sub("download"); dn != nil {
				metrics = append(metrics, core.Metric{Name: "throughput_download_bps", Labels: lab, Value: dn.num("bps")})
			}
		}
		metrics = append(metrics,
			core.Metric{Name: "throughput_bps", Labels: lab, Value: bps},
			core.Metric{Name: "throughput_pps", Labels: lab, Value: pps},
			core.Metric{Name: "active_flows", Labels: lab, Value: d.num("num_flows")},
			core.Metric{Name: "active_hosts", Labels: lab, Value: d.num("num_hosts", "num_local_hosts")},
			core.Metric{Name: "active_devices", Labels: lab, Value: d.num("num_devices")},
			core.Metric{Name: "bytes_total", Labels: lab, Value: d.num("bytes")},
			core.Metric{Name: "packets_total", Labels: lab, Value: d.num("packets")},
			core.Metric{Name: "drops_total", Labels: lab, Value: d.num("drops")},
			core.Metric{Name: "alerted_flows", Labels: lab, Value: d.num("alerted_flows")},
		)
		if v := d.num("bytes_upload"); v > 0 {
			metrics = append(metrics, core.Metric{Name: "bytes_upload_total", Labels: lab, Value: v},
				core.Metric{Name: "bytes_download_total", Labels: lab, Value: d.num("bytes_download")})
		}

		fq := url.Values{"ifid": {fmt.Sprint(ifc.ID)}, "perPage": {fmt.Sprint(maxFlows)},
			"currentPage": {"1"}, "sortColumn": {"column_last_seen"}, "sortOrder": {"desc"}}
		var rawFlows json.RawMessage
		if err := m.nt.get("flow/active.lua", fq, &rawFlows); err != nil {
			return m.fail(err)
		}
		for _, f := range asList(rawFlows) {
			fl, ok := m.decodeFlow(f, ifc.Name, now)
			if !ok {
				continue
			}
			flows = append(flows, fl)
		}
	}

	// Byte deltas per flow feed the host counters; cumulative totals feed the
	// flow row itself (upserted by key).
	m.mu.Lock()
	cutoff := time.Now().Add(-10 * time.Minute)
	for k, st := range m.seen {
		if st.seenAt.Before(cutoff) {
			delete(m.seen, k)
		}
	}
	for i := range flows {
		f := &flows[i]
		prev, had := m.seen[f.Key]
		dIn, dOut := f.BytesIn, f.BytesOut
		if had {
			// Judge growth by the total: the per-direction split comes from
			// a shifting percentage and one side can read lower while the
			// flow grew (see core.FlowDelta).
			dIn, dOut = core.FlowDelta(prev.bytesIn, prev.bytesOut, f.BytesIn, f.BytesOut)
		}
		m.seen[f.Key] = flowState{bytesIn: f.BytesIn, bytesOut: f.BytesOut, seenAt: time.Now()}
		for _, ip := range []string{f.SrcIP, f.DstIP} {
			if ip == "" || m.identity == nil || !m.identity.IsLocal(ip) {
				continue
			}
			h := hostAgg[ip]
			if h == nil {
				h = &core.HostUpdate{IP: ip, Source: "visibility"}
				hostAgg[ip] = h
			}
			if ip == f.SrcIP {
				h.BytesOut += dOut
				h.BytesIn += dIn
			} else {
				h.BytesIn += dOut
				h.BytesOut += dIn
			}
			if !had {
				h.Flows++
			}
		}
	}
	m.lastErr = ""
	m.lastOK = time.Now()
	m.mu.Unlock()

	if err := m.ctx.Store.AddMetrics(now, metrics); err != nil {
		return err
	}
	if err := m.ctx.Store.AddFlows(flows); err != nil {
		return err
	}
	ups := make([]core.HostUpdate, 0, len(hostAgg))
	for _, h := range hostAgg {
		ups = append(ups, *h)
	}
	if err := m.ctx.Store.UpsertHosts(ups); err != nil {
		return err
	}
	m.bus.publish(flows)
	return nil
}

// decodeFlow turns one ntopng flow record into a core.Flow. The client is
// treated as the source: on a gateway that is the device that opened the
// connection, which is what policy and reports care about.
func (m *Module) decodeFlow(f obj, ifname string, now int64) (core.Flow, bool) {
	cli, srv := f.sub("client", "cli"), f.sub("server", "srv")
	if cli == nil || srv == nil {
		return core.Flow{}, false
	}
	proto := f.sub("protocol", "proto")
	l7, l4 := "", ""
	if proto != nil {
		l7 = proto.str("l7", "l7_proto", "ndpi")
		l4 = proto.str("l4", "l4_proto")
	} else {
		l7 = f.str("l7_proto_name", "l7proto", "application")
		l4 = f.str("l4_proto_name", "l4proto")
	}
	// "TLS.Google" -> app Google, master TLS. Keep the specific name.
	app := l7
	if i := strings.Index(app, "."); i > 0 && i < len(app)-1 {
		app = app[i+1:]
	}
	var in, out int64
	if bytes := f.sub("bytes"); bytes != nil {
		out = bytes.i64("sent", "cli2srv")
		in = bytes.i64("rcvd", "srv2cli")
		if in == 0 && out == 0 {
			out = bytes.i64("total")
		}
	} else if total := f.i64("bytes"); total > 0 {
		// ntopng 6 gives a total plus a percentage breakdown per direction.
		if bd := f.sub("breakdown"); bd != nil {
			out = total * bd.i64("cli2srv") / 100
			in = total - out
		} else {
			out = total
		}
	} else {
		out = f.i64("cli2srv_bytes", "bytes_sent")
		in = f.i64("srv2cli_bytes", "bytes_rcvd")
	}
	first := f.i64("first_seen", "seen.first")
	if first == 0 {
		first = now - int64(f.num("duration"))
	}
	key := f.str("key", "hash_id", "flow_key")
	srcIP, dstIP := hostIP(cli), hostIP(srv)
	if key == "" {
		key = fmt.Sprintf("%s:%d-%s:%d/%s@%d", srcIP, int(cli.num("port")), dstIP, int(srv.num("port")), l4, first)
	} else {
		key = ifname + "/" + key
	}
	domain := strings.TrimSpace(f.str("info", "server_name", "host_server_name", "sni"))
	if domain == "" {
		if n := srv.str("name"); n != "" && n != dstIP && net.ParseIP(n) == nil && !strings.Contains(n, "@") {
			domain = strings.ToLower(strings.TrimSuffix(n, "."))
		}
	}
	if strings.HasPrefix(domain, "http") {
		if u, err := url.Parse(domain); err == nil {
			domain = u.Host
		}
	}
	if domain != "" && (net.ParseIP(domain) != nil || strings.ContainsAny(domain, " /")) {
		domain = ""
	}
	if domain == "" && m.identity != nil {
		// nothing from ntopng; the resolver's answers may still name the far end
	}
	m.mu.Lock()
	cat := m.apps[app].Category
	if cat == "" {
		cat = m.apps[l7].Category
	}
	m.mu.Unlock()
	if c := f.sub("category"); c != nil && cat == "" {
		cat = c.str("name")
	}
	if cat == "" {
		cat = f.str("category_name", "cat_name")
	}
	fl := core.Flow{
		TS: first, Key: key, SrcIP: srcIP, SrcPort: int(cli.num("port")), DstIP: dstIP,
		DstPort: int(srv.num("port")), Proto: strings.ToLower(l4), App: app, Category: cat, Domain: domain,
		BytesIn: in, BytesOut: out, Packets: f.i64("packets", "num_packets"),
		Duration: f.num("duration"), Source: "ntopng", Iface: ifname,
		Country: srv.str("country"), TLSVersion: f.str("tls_version"),
	}
	if e := f.str("encrypted"); e == "true" && fl.TLSVersion == "" {
		fl.TLSVersion = "TLS"
	}
	if fl.SrcIP == "" || fl.DstIP == "" {
		return core.Flow{}, false
	}
	return fl, true
}

// ---------------------------------------------------------------- API

func (m *Module) name(ip string) string {
	if m.identity == nil {
		return ""
	}
	return m.identity.Name(ip)
}

func (m *Module) apiSummary(r *core.Req) (any, error) {
	st := m.ctx.Store
	now := time.Now().Unix()
	latest := func(name string) float64 {
		return st.Float(`SELECT SUM(value) FROM metrics WHERE name=? AND ts=(SELECT MAX(ts) FROM metrics WHERE name=?)`,
			name, name)
	}
	m.mu.Lock()
	ifs := append([]iface(nil), m.ifs...)
	lastErr, lastOK := m.lastErr, m.lastOK
	m.mu.Unlock()
	return map[string]any{
		"throughput_bps": latest("throughput_bps"), "throughput_pps": latest("throughput_pps"),
		"throughput_download_bps": latest("throughput_download_bps"), "throughput_upload_bps": latest("throughput_upload_bps"),
		"active_flows": latest("active_flows"), "active_hosts": latest("active_hosts"),
		"active_devices":        latest("active_devices"),
		"flows_last_hour":       st.Int(`SELECT COUNT(*) FROM flows WHERE ts>=?`, now-3600),
		"hosts_last_hour":       st.Int(`SELECT COUNT(*) FROM hosts WHERE is_local=1 AND last_seen>=?`, now-3600),
		"blocked_last_hour":     st.Int(`SELECT COUNT(*) FROM flows WHERE ts>=? AND verdict='blocked'`, now-3600),
		"alerts_last_hour":      st.Int(`SELECT COUNT(*) FROM alerts WHERE ts>=?`, now-3600),
		"dns_last_hour":         st.Int(`SELECT COUNT(*) FROM dns WHERE ts>=?`, now-3600),
		"dns_blocked_last_hour": st.Int(`SELECT COUNT(*) FROM dns WHERE ts>=? AND action<>'pass'`, now-3600),
		"interfaces":            ifs, "source_ok": lastErr == "", "source_error": lastErr, "source_updated": lastOK.Unix(),
	}, nil
}

func (m *Module) apiFlows(r *core.Req) (any, error) {
	minutes := r.QInt("minutes", 15, 1, 24*60*7)
	limit := r.QInt("limit", 200, 1, 5000)
	ip, err := r.QSafe("ip", "", 64)
	if err != nil {
		return nil, err
	}
	app, err := r.QSafe("app", "", 64)
	if err != nil {
		return nil, err
	}
	q := `SELECT id,ts,end_ts,src_ip,src_port,dst_ip,dst_port,proto,app,category,domain,bytes_in,bytes_out,
		duration,verdict,policy,source,iface,tls_version,tls_sni,country FROM flows WHERE COALESCE(end_ts,ts)>=?`
	args := []any{time.Now().Unix() - int64(minutes)*60}
	if ip != "" {
		q += ` AND (src_ip=? OR dst_ip=?)`
		args = append(args, ip, ip)
	}
	if app != "" {
		q += ` AND app=?`
		args = append(args, app)
	}
	if r.Q("blocked", "") != "" {
		q += ` AND verdict='blocked'`
	}
	q += ` ORDER BY COALESCE(end_ts,ts) DESC LIMIT ?`
	args = append(args, limit)
	rows, err := m.ctx.Store.Rows(q, args...)
	if err != nil {
		return nil, err
	}
	m.decorate(rows, "src_ip", "src_name")
	m.decorate(rows, "dst_ip", "dst_name")
	return map[string]any{"flows": rows}, nil
}

func (m *Module) decorate(rows []map[string]any, ipKey, nameKey string) {
	for _, row := range rows {
		ip, _ := row[ipKey].(string)
		if n := m.name(ip); n != "" {
			row[nameKey] = n
		}
	}
}

func (m *Module) apiApps(r *core.Req) (any, error) {
	since := r.Since(24)
	ip, err := r.QSafe("ip", "", 64)
	if err != nil {
		return nil, err
	}
	q := `SELECT app, MAX(category) AS category, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out,
		SUM(flows) AS flows, SUM(CASE WHEN verdict='blocked' THEN flows ELSE 0 END) AS blocked,
		COUNT(DISTINCT src_ip) AS hosts FROM rollup_app WHERE bucket>=?`
	args := []any{since}
	if ip != "" {
		q += ` AND src_ip=?`
		args = append(args, ip)
	}
	q += ` GROUP BY app ORDER BY bytes_in+bytes_out DESC LIMIT 500`
	rows, err := m.ctx.Store.Rows(q, args...)
	if err != nil {
		return nil, err
	}
	// The current, unrolled bucket adds what happened in the last few minutes.
	live, _ := m.ctx.Store.Rows(`SELECT app, MAX(category) AS category, SUM(bytes_in) AS bytes_in,
		SUM(bytes_out) AS bytes_out, COUNT(*) AS flows FROM flows WHERE ts>=? `+
		func() string {
			if ip != "" {
				return "AND src_ip=? "
			}
			return ""
		}()+`GROUP BY app`, append([]any{time.Now().Unix() - time.Now().Unix()%300}, func() []any {
		if ip != "" {
			return []any{ip}
		}
		return nil
	}()...)...)
	idx := map[string]map[string]any{}
	for _, row := range rows {
		idx[row["app"].(string)] = row
	}
	for _, l := range live {
		a, _ := l["app"].(string)
		if row, ok := idx[a]; ok {
			row["bytes_in"] = toI(row["bytes_in"]) + toI(l["bytes_in"])
			row["bytes_out"] = toI(row["bytes_out"]) + toI(l["bytes_out"])
			row["flows"] = toI(row["flows"]) + toI(l["flows"])
		} else {
			l["blocked"], l["hosts"] = 0, 1
			rows = append(rows, l)
		}
	}
	m.mu.Lock()
	for _, row := range rows {
		a, _ := row["app"].(string)
		row["breed"] = m.apps[a].Breed
		if row["category"] == nil || row["category"] == "" {
			row["category"] = m.apps[a].Category
		}
	}
	m.mu.Unlock()
	sort.Slice(rows, func(i, j int) bool {
		return toI(rows[i]["bytes_in"])+toI(rows[i]["bytes_out"]) > toI(rows[j]["bytes_in"])+toI(rows[j]["bytes_out"])
	})
	return map[string]any{"apps": rows}, nil
}

func toI(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case float64:
		return int64(x)
	case int:
		return int64(x)
	}
	return 0
}

func (m *Module) apiTop(r *core.Req) (any, error) {
	since := r.Since(24)
	limit := r.QInt("limit", 15, 1, 200)
	st := m.ctx.Store
	hosts, err := st.Rows(`SELECT src_ip AS ip, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out,
		SUM(flows) AS flows, SUM(CASE WHEN verdict='blocked' THEN flows ELSE 0 END) AS blocked
		FROM rollup_app WHERE bucket>=? GROUP BY src_ip ORDER BY bytes_in+bytes_out DESC LIMIT ?`, since, limit)
	if err != nil {
		return nil, err
	}
	m.decorate(hosts, "ip", "name")
	apps, _ := st.Rows(`SELECT app, MAX(category) AS category, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out,
		SUM(flows) AS flows FROM rollup_app WHERE bucket>=? GROUP BY app ORDER BY bytes_in+bytes_out DESC LIMIT ?`,
		since, limit)
	cats, _ := st.Rows(`SELECT COALESCE(NULLIF(category,''),'Unknown') AS category, SUM(bytes_in) AS bytes_in,
		SUM(bytes_out) AS bytes_out, SUM(flows) AS flows FROM rollup_app WHERE bucket>=? GROUP BY 1
		ORDER BY bytes_in+bytes_out DESC LIMIT ?`, since, limit)
	domains, _ := st.Rows(`SELECT domain, MAX(category) AS category, SUM(bytes_in) AS bytes_in,
		SUM(bytes_out) AS bytes_out, SUM(flows) AS flows, COUNT(DISTINCT src_ip) AS hosts
		FROM rollup_domain WHERE bucket>=? GROUP BY domain ORDER BY bytes_in+bytes_out DESC LIMIT ?`, since, limit)
	m.endpointsFor(domains, since)
	dsts, _ := st.Rows(`SELECT dst_ip AS ip, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out,
		SUM(flows) AS flows, COUNT(DISTINCT src_ip) AS hosts FROM rollup_dst WHERE bucket>=?
		GROUP BY dst_ip ORDER BY bytes_in+bytes_out DESC LIMIT ?`, since, limit)
	m.decorate(dsts, "ip", "name")
	for _, d := range dsts {
		if d["name"] == nil {
			ip, _ := d["ip"].(string)
			if n, _ := st.Row(`SELECT name FROM dns_names WHERE ip=?`, ip); n != nil {
				d["name"] = n["name"]
			}
		}
	}
	blocked, _ := st.Rows(`SELECT src_ip AS ip, app, SUM(flows) AS flows FROM rollup_app WHERE bucket>=? AND
		verdict='blocked' GROUP BY src_ip, app ORDER BY flows DESC LIMIT ?`, since, limit)
	m.decorate(blocked, "ip", "name")
	return map[string]any{"hosts": hosts, "apps": apps, "categories": cats, "domains": domains,
		"destinations": dsts, "blocked": blocked}, nil
}

// endpointsFor puts, on each top site, the address that site's traffic
// actually went to -- the endpoint the Map page can show the route to. A
// site is a name and a route is to an address; the flows join the two. Where
// several addresses served the name, one with a measured route wins, then
// the busiest. Rows gain dst_ip and traced; a site nothing can be found for
// gains nothing.
func (m *Module) endpointsFor(domains []map[string]any, since int64) {
	if len(domains) == 0 {
		return
	}
	names := make([]string, 0, len(domains))
	args := []any{since}
	ph := make([]string, 0, len(domains))
	for _, d := range domains {
		if n, _ := d["domain"].(string); n != "" {
			names = append(names, n)
			args = append(args, n)
			ph = append(ph, "?")
		}
	}
	if len(names) == 0 {
		return
	}
	// The Overview asks every couple of minutes and the answer moves slower
	// than that; the join is remembered briefly against the sites asked
	// about, so a page refresh is a lookup rather than a pass over the day.
	memoKey := fmt.Sprintf("%d|%s", since-since%300, strings.Join(names, ","))
	m.epMu.Lock()
	if m.epAt.Add(2*time.Minute).After(time.Now()) && m.epKey == memoKey {
		for _, d := range domains {
			if n, _ := d["domain"].(string); n != "" {
				if p, ok := m.epBest[n]; ok {
					d["dst_ip"], d["traced"] = p.ip, p.traced
				}
			}
		}
		m.epMu.Unlock()
		return
	}
	m.epMu.Unlock()
	in := strings.Join(ph, ",")
	rows, err := m.ctx.Store.Rows(`SELECT f.domain AS domain, f.dst_ip AS ip, SUM(f.bytes_in+f.bytes_out) AS b,
		MAX(CASE WHEN p.dst IS NULL THEN 0 ELSE 1 END) AS traced
		FROM flows f LEFT JOIN path_runs p ON p.dst = f.dst_ip
		WHERE f.ts > ? AND f.dst_ip <> '' AND f.domain IN (`+in+`) GROUP BY f.domain, f.dst_ip`, args...)
	if err != nil {
		// Without the paths module there is no path_runs table; the busiest
		// address still answers the question.
		rows, err = m.ctx.Store.Rows(`SELECT domain, dst_ip AS ip, SUM(bytes_in+bytes_out) AS b, 0 AS traced
			FROM flows WHERE ts > ? AND dst_ip <> '' AND domain IN (`+in+`) GROUP BY domain, dst_ip`, args...)
		if err != nil {
			return
		}
	}
	best := map[string]endpointPick{}
	for _, r := range rows {
		dom, _ := r["domain"].(string)
		ip, _ := r["ip"].(string)
		b := asInt64(r["b"])
		traced := asInt64(r["traced"]) > 0
		cur, ok := best[dom]
		if !ok || (traced && !cur.traced) || (traced == cur.traced && b > cur.b) {
			best[dom] = endpointPick{ip, b, traced}
		}
	}
	m.epMu.Lock()
	m.epBest, m.epKey, m.epAt = best, memoKey, time.Now()
	m.epMu.Unlock()
	for _, d := range domains {
		if n, _ := d["domain"].(string); n != "" {
			if p, ok := best[n]; ok {
				d["dst_ip"], d["traced"] = p.ip, p.traced
			}
		}
	}
}

// endpointPick is one site's endpoint: the address, how much went there,
// and whether the map has a route to it.
type endpointPick struct {
	ip     string
	b      int64
	traced bool
}

func asInt64(v any) int64 {
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

func (m *Module) apiTimeseries(r *core.Req) (any, error) {
	hours := r.Hours(24)
	since := time.Now().Unix() - int64(hours)*3600
	step := r.QInt("step", 0, 0, 86400)
	if step == 0 {
		switch {
		case hours <= 3:
			step = 60
		case hours <= 24:
			step = 300
		case hours <= 24*7:
			step = 1800
		default:
			step = 3600
		}
	}
	metric, err := r.QSafe("metric", "", 40)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"step": step, "since": since}
	series := func(name string) []map[string]any {
		rows, _ := m.ctx.Store.Rows(`SELECT (ts/?)*? AS t, AVG(v) AS v FROM (SELECT ts, SUM(value) AS v FROM metrics
			WHERE name=? AND ts>=? GROUP BY ts) GROUP BY t ORDER BY t`, step, step, name, since)
		return rows
	}
	names := []string{"throughput_bps", "throughput_download_bps", "throughput_upload_bps", "active_flows", "active_hosts"}
	if metric != "" {
		names = []string{metric}
	}
	for _, n := range names {
		out[n] = series(n)
	}
	if metric == "" || metric == "traffic" {
		out["traffic"], _ = m.ctx.Store.Rows(`SELECT (bucket/?)*? AS t, SUM(bytes_in) AS bytes_in,
			SUM(bytes_out) AS bytes_out, SUM(flows) AS flows,
			SUM(CASE WHEN verdict='blocked' THEN flows ELSE 0 END) AS blocked
			FROM rollup_app WHERE bucket>=? GROUP BY t ORDER BY t`, step, step, since)
	}
	if metric == "" || metric == "dns" {
		out["dns"], _ = m.ctx.Store.Rows(`SELECT (bucket/?)*? AS t, SUM(queries) AS queries,
			SUM(CASE WHEN action<>'pass' THEN queries ELSE 0 END) AS blocked FROM rollup_dns
			WHERE bucket>=? GROUP BY t ORDER BY t`, step, step, since)
	}
	if metric == "" || metric == "alerts" {
		out["alerts"], _ = m.ctx.Store.Rows(`SELECT (ts/?)*? AS t, COUNT(*) AS alerts FROM alerts
			WHERE ts>=? GROUP BY t ORDER BY t`, step, step, since)
	}
	return out, nil
}

func (m *Module) apiHost(r *core.Req) (any, error) {
	ip := r.Q("ip", "")
	if net.ParseIP(ip) == nil {
		return nil, core.BadRequest("ip must be an address")
	}
	since := r.Since(24)
	st := m.ctx.Store
	host, _ := st.Row(`SELECT * FROM hosts WHERE ip=?`, ip)
	if host == nil {
		host = map[string]any{"ip": ip}
	}
	if m.identity != nil {
		if n := m.identity.Name(ip); n != "" {
			host["name"] = n
		}
		mac, _ := host["mac"].(string)
		if mac == "" {
			mac = m.identity.MAC(ip)
			host["mac"] = mac
		}
		host["vendor"] = m.identity.Vendor(mac)
	}
	device, _ := st.Row(`SELECT * FROM devices WHERE mac=?`, host["mac"])

	// Get proxmox reference if available
	type ProxmoxGuestRef interface {
		GuestFor(macOrIP string) (any, bool)
	}
	if proxmoxSvc, ok := m.ctx.Service("proxmox").(ProxmoxGuestRef); ok {
		mac, _ := host["mac"].(string)
		if ref, found := proxmoxSvc.GuestFor(mac); found {
			if refMap, ok := ref.(map[string]interface{}); ok {
				device["proxmox"] = refMap
			}
		} else if ref, found := proxmoxSvc.GuestFor(ip); found {
			if refMap, ok := ref.(map[string]interface{}); ok {
				device["proxmox"] = refMap
			}
		}
	}

	apps, _ := st.Rows(`SELECT app, MAX(category) AS category, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out,
		SUM(flows) AS flows, SUM(CASE WHEN verdict='blocked' THEN flows ELSE 0 END) AS blocked FROM rollup_app
		WHERE bucket>=? AND src_ip=? GROUP BY app ORDER BY bytes_in+bytes_out DESC LIMIT 50`, since, ip)
	domains, _ := st.Rows(`SELECT domain, MAX(category) AS category, SUM(bytes_in) AS bytes_in,
		SUM(bytes_out) AS bytes_out, SUM(flows) AS flows FROM rollup_domain WHERE bucket>=? AND src_ip=?
		GROUP BY domain ORDER BY bytes_in+bytes_out DESC LIMIT 50`, since, ip)
	dsts, _ := st.Rows(`SELECT dst_ip AS ip, dst_port AS port, proto, SUM(bytes_in) AS bytes_in,
		SUM(bytes_out) AS bytes_out, SUM(flows) AS flows FROM rollup_dst WHERE bucket>=? AND src_ip=?
		GROUP BY dst_ip, dst_port, proto ORDER BY bytes_in+bytes_out DESC LIMIT 50`, since, ip)
	for _, d := range dsts {
		dip, _ := d["ip"].(string)
		if n, _ := st.Row(`SELECT name FROM dns_names WHERE ip=?`, dip); n != nil {
			d["name"] = n["name"]
		}
	}
	timeline, _ := st.Rows(`SELECT bucket AS t, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out, SUM(flows) AS flows,
		SUM(CASE WHEN verdict='blocked' THEN flows ELSE 0 END) AS blocked FROM rollup_app WHERE bucket>=? AND src_ip=?
		GROUP BY bucket ORDER BY bucket`, since, ip)
	dns, _ := st.Rows(`SELECT domain, action, MAX(list) AS list, SUM(queries) AS queries FROM rollup_dns
		WHERE bucket>=? AND client=? GROUP BY domain, action ORDER BY queries DESC LIMIT 50`, since, ip)
	dnsBlocked, _ := st.Rows(`SELECT ts, domain, qtype, list, rcode, source FROM dns WHERE client=? AND action<>'pass' AND ts>=?
		ORDER BY ts DESC LIMIT 100`, ip, since)
	dnsTotals, _ := st.Row(`SELECT SUM(queries) AS queries, SUM(CASE WHEN action<>'pass' THEN queries ELSE 0 END) AS blocked,
		COUNT(DISTINCT domain) AS domains FROM rollup_dns WHERE bucket>=? AND client=?`, since, ip)
	alerts, _ := st.Rows(`SELECT * FROM alerts WHERE ts>=? AND (src_ip=? OR dst_ip=?) ORDER BY ts DESC LIMIT 50`,
		since, ip, ip)
	flows, _ := st.Rows(`SELECT ts,end_ts,dst_ip,dst_port,proto,app,category,domain,bytes_in,bytes_out,duration,verdict,policy
		FROM flows WHERE src_ip=? ORDER BY COALESCE(end_ts,ts) DESC LIMIT 100`, ip)
	m.decorate(flows, "dst_ip", "dst_name")
	tls, _ := st.Rows(`SELECT sni, version, mode, COUNT(*) AS sessions FROM tls_sessions WHERE ts>=? AND src_ip=?
		GROUP BY sni, version, mode ORDER BY sessions DESC LIMIT 50`, since, ip)
	totals, _ := st.Row(`SELECT SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out, SUM(flows) AS flows,
		SUM(CASE WHEN verdict='blocked' THEN flows ELSE 0 END) AS blocked FROM rollup_app WHERE bucket>=? AND src_ip=?`,
		since, ip)
	findings, _ := st.Rows(`SELECT * FROM findings WHERE resolved_ts IS NULL AND subject=? ORDER BY ts DESC LIMIT 20`, ip)
	return map[string]any{"host": host, "device": device, "apps": apps, "domains": domains, "destinations": dsts,
		"timeline": timeline, "dns": dns, "dns_blocked": dnsBlocked, "dns_totals": dnsTotals, "alerts": alerts, "flows": flows, "tls": tls,
		"addresses": m.addressesOf(ip),
		"totals":    totals, "findings": findings, "hours": r.Hours(24)}, nil
}

func (m *Module) apiCatalog(r *core.Req) (any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cats := map[string]int{}
	apps := make([]map[string]any, 0, len(m.apps))
	for name, a := range m.apps {
		apps = append(apps, map[string]any{"app": name, "category": a.Category, "breed": a.Breed, "id": a.ID})
		cats[a.Category]++
	}
	sort.Slice(apps, func(i, j int) bool { return apps[i]["app"].(string) < apps[j]["app"].(string) })
	var catList []map[string]any
	for c, n := range cats {
		catList = append(catList, map[string]any{"category": c, "apps": n})
	}
	sort.Slice(catList, func(i, j int) bool { return catList[i]["category"].(string) < catList[j]["category"].(string) })
	return map[string]any{"apps": apps, "categories": catList, "host": hostname()}, nil
}

func hostname() string { h, _ := os.Hostname(); return h }

// EffectiveSettings reports the ntopng endpoint in use when the setting is empty.
func (m *Module) EffectiveSettings() map[string]any {
	base := core.Str(m.ctx.Settings(), "ntopng_url", "")
	if base == "" {
		base = "http://127.0.0.1:3000"
	}
	return map[string]any{"ntopng_url": base}
}

// addressesOf lists every address the device at ip holds, so a host page
// says so and links them; IPv6 is treated exactly like IPv4.
func (m *Module) addressesOf(ip string) []string {
	if ab, ok := m.ctx.Service("identity").(core.AddressBook); ok {
		list := ab.Addresses(ip)
		if len(list) > 1 {
			return list
		}
	}
	return nil
}
