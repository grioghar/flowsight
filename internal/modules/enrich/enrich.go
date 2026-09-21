// Package enrich turns bare addresses into something a person can read:
// a reverse-DNS name and a country. Both are off by default because they
// cost lookups (PTR queries leave a trace in the resolver log, the country
// database is downloaded from a third party) and because plenty of
// operators do not want either. The UI asks for enrichment in batches and
// decorates addresses in place; nothing else in the daemon depends on it.
package enrich

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
	"github.com/oschwald/maxminddb-golang"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

// Default country database: DB-IP's free country database (CC BY 4.0,
// attribution shown in the UI while it is in use). {YYYY-MM} is replaced by
// the current month, and the previous month is tried when the current one
// is not published yet. Any MaxMind-format country database works here,
// including GeoLite2-Country with your own licence key in the URL.
const defaultGeoURL = "https://download.db-ip.com/free/dbip-country-lite-{YYYY-MM}.mmdb.gz"

// Info is what a lookup returns for one address.
type Info struct {
	IP      string `json:"ip"`
	Name    string `json:"name,omitempty"`    // reverse DNS, without the trailing dot
	Country string `json:"country,omitempty"` // ISO 3166-1 alpha-2
	Local   bool   `json:"local,omitempty"`
}

// Enricher is the service other modules and the UI use.
type Enricher interface {
	Lookup(ips []string) map[string]Info
	Enabled() (reverseDNS, geo bool)
}

type entry struct {
	name    string
	country string
	at      time.Time
	pending bool
}

// Module implements core.Module and Enricher.
type Module struct {
	ctx      *core.Context
	identity core.Identity
	resolver *net.Resolver
	client   *http.Client

	mu     sync.Mutex
	cache  map[string]*entry
	queue  chan string
	geo    *maxminddb.Reader
	geoAt  time.Time
	geoErr string
	geoTag string // the database's build epoch, for the status page
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name:        "enrich",
		Version:     "1.0",
		Description: "Names and countries for bare addresses: reverse DNS and an IP geolocation database. Both off by default.",
		After:       []string{"identity"},
		Defaults: map[string]any{
			"enabled":     true,
			"reverse_dns": false,
			"geoip":       false,
			"geoip_url":   defaultGeoURL,
			"cache_hours": 24,
		},
		Schema: []core.SettingField{
			{Key: "reverse_dns", Label: "Reverse DNS names", Type: "bool",
				Help: "Look up PTR records for addresses shown without a name, through the gateway's own resolver. Results are cached."},
			{Key: "geoip", Label: "Country lookup", Type: "bool",
				Help: "Show the country of public addresses. Downloads a country database (DB-IP Lite by default, refreshed monthly) into the data directory."},
			{Key: "geoip_url", Label: "Country database URL", Type: "string",
				Help: "A MaxMind-format (.mmdb, optionally .gz) country database. {YYYY-MM} is replaced by the current month. Empty: DB-IP Lite."},
			{Key: "cache_hours", Label: "Name cache (hours)", Type: "int"},
		},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	m.identity, _ = ctx.Service("identity").(core.Identity)
	m.resolver = &net.Resolver{PreferGo: false}
	m.client = &http.Client{Timeout: 5 * time.Minute}
	m.cache = map[string]*entry{}
	m.queue = make(chan string, 4096)
	for i := 0; i < 4; i++ {
		go m.worker()
	}
	ctx.Publish("enrich", m)
	ctx.Every("geoip", 6*time.Hour, m.refreshGeo)
	ctx.Every("prune", 1*time.Hour, m.prune, core.Delayed())
	ctx.Route("POST", "/api/enrich/lookup", m.apiLookup, core.Write(),
		core.Doc("Names and countries for a list of addresses (up to 500); unknown names are resolved in the background and answered on the next call"))
	ctx.Route("GET", "/api/enrich/status", m.apiStatus, core.Doc("What is enabled, cache size, country database state"))
	return nil
}

// OnConfigChange makes a switch take effect at once: turning country lookup
// on fetches the database now instead of at the next six-hourly run.
func (m *Module) OnConfigChange(settings map[string]any) error {
	go func() { _ = m.refreshGeo() }()
	return nil
}

func (m *Module) Health() core.Health {
	rd, geo := m.Enabled()
	m.mu.Lock()
	defer m.mu.Unlock()
	var parts []string
	if rd {
		parts = append(parts, fmt.Sprintf("reverse DNS on, %d names cached", len(m.cache)))
	}
	if geo {
		if m.geo == nil {
			return core.Health{OK: false, Detail: "country lookup on but no database yet: " + m.geoErr}
		}
		parts = append(parts, "country database "+m.geoTag)
	}
	if len(parts) == 0 {
		return core.Health{OK: true, Detail: "off (reverse DNS and country lookup are opt-in)"}
	}
	return core.Health{OK: true, Detail: strings.Join(parts, "; ")}
}

// Enabled reports the two switches as currently configured.
func (m *Module) Enabled() (bool, bool) {
	s := m.ctx.Settings()
	return core.Bool(s, "reverse_dns", false), core.Bool(s, "geoip", false)
}

// ---------------------------------------------------------------- lookup

// Lookup answers from the cache and the database at once, and queues
// reverse lookups for names it does not have yet. It never blocks on the
// network, so a page render stays fast; the next call has the names.
func (m *Module) Lookup(ips []string) map[string]Info {
	rd, geo := m.Enabled()
	out := make(map[string]Info, len(ips))
	if !rd && !geo {
		return out
	}
	ttl := time.Duration(core.Int(m.ctx.Settings(), "cache_hours", 24)) * time.Hour
	if ttl < time.Minute {
		ttl = time.Minute
	}
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ip := range ips {
		addr := net.ParseIP(strings.TrimSpace(ip))
		if addr == nil {
			continue
		}
		key := addr.String()
		info := Info{IP: key}
		local := addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified()
		if !local && m.identity != nil && m.identity.IsLocal(key) {
			local = true
		}
		info.Local = local
		if geo && !local && m.geo != nil {
			info.Country = m.country(addr)
		}
		if rd {
			e := m.cache[key]
			if e != nil && now.Sub(e.at) < ttl {
				info.Name = e.name
			} else if e == nil || !e.pending {
				if e == nil {
					e = &entry{}
					m.cache[key] = e
				}
				e.pending = true
				select {
				case m.queue <- key:
				default:
					e.pending = false // queue full; try again next time
				}
			}
		}
		out[key] = info
	}
	return out
}

func (m *Module) worker() {
	for ip := range m.queue {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		names, err := m.resolver.LookupAddr(ctx, ip)
		cancel()
		name := ""
		if err == nil && len(names) > 0 {
			name = strings.TrimSuffix(names[0], ".")
		}
		m.mu.Lock()
		e := m.cache[ip]
		if e == nil {
			e = &entry{}
			m.cache[ip] = e
		}
		e.name, e.at, e.pending = name, time.Now(), false
		m.mu.Unlock()
	}
}

func (m *Module) prune() error {
	ttl := time.Duration(core.Int(m.ctx.Settings(), "cache_hours", 24)) * time.Hour
	cut := time.Now().Add(-2 * ttl)
	m.mu.Lock()
	for ip, e := range m.cache {
		if !e.pending && e.at.Before(cut) {
			delete(m.cache, ip)
		}
	}
	if len(m.cache) > 50000 { // hard cap: drop everything and start over
		m.cache = map[string]*entry{}
	}
	m.mu.Unlock()
	return nil
}

// ---------------------------------------------------------------- country

type countryRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

func (m *Module) country(ip net.IP) string {
	var rec countryRecord
	if err := m.geo.Lookup(ip, &rec); err != nil {
		return ""
	}
	return rec.Country.ISOCode
}

func (m *Module) dbPath() string { return filepath.Join(m.ctx.Platform.DataDir, "geoip-country.mmdb") }

// refreshGeo opens the database on disk and downloads a fresh one when the
// switch is on and the file is missing or older than 25 days.
func (m *Module) refreshGeo() error {
	_, geo := m.Enabled()
	if !geo {
		m.mu.Lock()
		if m.geo != nil {
			m.geo.Close()
			m.geo = nil
		}
		m.mu.Unlock()
		return nil
	}
	path := m.dbPath()
	st, err := os.Stat(path)
	fresh := err == nil && time.Since(st.ModTime()) < 25*24*time.Hour
	if !fresh {
		if derr := m.download(path); derr != nil {
			m.mu.Lock()
			m.geoErr = derr.Error()
			m.mu.Unlock()
			if err != nil {
				return derr // nothing on disk to fall back to
			}
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.geo != nil && m.geoAt.Equal(modTime(path)) {
		return nil
	}
	r, err := maxminddb.Open(path)
	if err != nil {
		m.geoErr = "cannot open database: " + err.Error()
		return err
	}
	if m.geo != nil {
		m.geo.Close()
	}
	m.geo, m.geoAt, m.geoErr = r, modTime(path), ""
	m.geoTag = time.Unix(int64(r.Metadata.BuildEpoch), 0).UTC().Format("2006-01-02") + " (" + r.Metadata.DatabaseType + ")"
	return nil
}

func modTime(p string) time.Time {
	st, err := os.Stat(p)
	if err != nil {
		return time.Time{}
	}
	return st.ModTime()
}

func (m *Module) download(dest string) error {
	tmpl := strings.TrimSpace(core.Str(m.ctx.Settings(), "geoip_url", defaultGeoURL))
	if tmpl == "" {
		tmpl = defaultGeoURL
	}
	now := time.Now().UTC()
	var last error
	for _, month := range []time.Time{now, now.AddDate(0, -1, 0)} {
		url := strings.ReplaceAll(tmpl, "{YYYY-MM}", month.Format("2006-01"))
		if err := m.fetch(url, dest); err != nil {
			last = err
			if !strings.Contains(tmpl, "{YYYY-MM}") {
				break
			}
			continue
		}
		m.ctx.Event("enrich", "country database downloaded", map[string]any{"url": url})
		return nil
	}
	return last
}

func (m *Module) fetch(url, dest string) error {
	resp, err := m.client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	var body io.Reader = resp.Body
	if strings.HasSuffix(url, ".gz") {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return err
		}
		defer gz.Close()
		body = gz
	}
	tmp := dest + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, io.LimitReader(body, 256<<20)); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	f.Close()
	// Refuse a file that is not a MaxMind database before it replaces a good one.
	if r, err := maxminddb.Open(tmp); err != nil {
		os.Remove(tmp)
		return errors.New("downloaded file is not a MaxMind database")
	} else {
		r.Close()
	}
	return os.Rename(tmp, dest)
}

// ---------------------------------------------------------------- API

func (m *Module) apiLookup(r *core.Req) (any, error) {
	var in struct {
		IPs []string `json:"ips"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	if len(in.IPs) > 500 {
		in.IPs = in.IPs[:500]
	}
	rd, geo := m.Enabled()
	return map[string]any{"reverse_dns": rd, "geoip": geo, "hosts": m.Lookup(in.IPs)}, nil
}

func (m *Module) apiStatus(r *core.Req) (any, error) {
	rd, geo := m.Enabled()
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]any{"reverse_dns": rd, "geoip": geo, "cached_names": len(m.cache), "queued": len(m.queue),
		"database": m.geoTag, "database_error": m.geoErr, "database_path": m.dbPath()}
	if st, err := os.Stat(m.dbPath()); err == nil {
		out["database_updated"] = st.ModTime().Unix()
		out["database_bytes"] = st.Size()
	}
	src := strings.TrimSpace(core.Str(m.ctx.Settings(), "geoip_url", defaultGeoURL))
	out["attribution"] = ""
	if geo && (src == "" || strings.Contains(src, "db-ip.com")) {
		out["attribution"] = "IP geolocation by DB-IP (db-ip.com), CC BY 4.0"
	}
	return out, nil
}
