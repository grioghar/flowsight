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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
	"github.com/oschwald/maxminddb-golang"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

// Default databases: DB-IP's free files (CC BY 4.0, attribution shown in the
// UI while one is in use). {YYYY-MM} is replaced by the current month, and
// the previous month is tried when the current one is not published yet. Any
// MaxMind-format database works here, including GeoLite2 with your own
// licence key in the URL.
//
// Two levels, because they are not the same size. The country file is a few
// megabytes and answers "where is this". The city file is far larger and is
// only worth downloading if something needs coordinates, which today means
// drawing a path on a map.
const (
	defaultGeoURL     = "https://download.db-ip.com/free/dbip-country-lite-{YYYY-MM}.mmdb.gz"
	defaultGeoCityURL = "https://download.db-ip.com/free/dbip-city-lite-{YYYY-MM}.mmdb.gz"
)

// Info is what a lookup returns for one address.
type Info struct {
	IP      string `json:"ip"`
	Name    string `json:"name,omitempty"`    // reverse DNS, without the trailing dot
	Country string `json:"country,omitempty"` // ISO 3166-1 alpha-2
	// City-level fields, present only while the city database is in use.
	// Lat and Lon are zero when unknown, which is a real answer here: a great
	// many addresses have no coordinates and inventing some would put points
	// on a map that mean nothing.
	City   string  `json:"city,omitempty"`
	Region string  `json:"region,omitempty"`
	Lat    float64 `json:"lat,omitempty"`
	Lon    float64 `json:"lon,omitempty"`
	Local  bool    `json:"local,omitempty"`
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

// Module implements core.Module, Enricher and GeoService.
type Module struct {
	ctx      *core.Context
	identity core.Identity
	resolver *net.Resolver
	client   *http.Client

	mu           sync.Mutex
	cache        map[string]*entry
	queue        chan string
	geo          *maxminddb.Reader
	geoAt        time.Time
	geoErr       string
	geoTag       string // the database's build epoch, for the status page
	geoEpoch     int64  // build epoch as unix timestamp
	geoCountries []core.CountryInfo

	// The country-level database used for building firewall tables and the
	// country list. It is the main database when the detail level is
	// "country"; with a city database in use a separate, far smaller country
	// file is fetched, because walking every city-level network on a small
	// gateway takes minutes.
	tbl        *maxminddb.Reader
	tblAt      time.Time
	tblEpoch   int64
	counts     map[string]int // prefixes per country, from a background walk
	countsFor  int64          // the epoch counts were made for
	countsBusy bool
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name:        "enrich",
		Version:     "1.0",
		Description: "Names and countries for bare addresses: reverse DNS and an IP geolocation database. Both off by default.",
		After:       []string{"identity"},
		Defaults: map[string]any{
			"enabled":      true,
			"reverse_dns":  false,
			"geoip":        false,
			"geoip_detail": "country",
			"geoip_url":    "",
			"cache_hours":  24,
		},
		Schema: []core.SettingField{
			{Key: "reverse_dns", Label: "Reverse DNS names", Type: "bool",
				Help: "Look up PTR records for addresses shown without a name, through the gateway's own resolver. Results are cached."},
			{Key: "geoip", Label: "Location lookup", Type: "bool",
				Help: "Show where public addresses are. Downloads a database (DB-IP Lite by default, refreshed monthly) into the data directory."},
			{Key: "geoip_detail", Label: "How much detail", Type: "choice", Choices: []string{"country", "city"},
				Help: "Country is a few megabytes and answers which country an address is in. City is a much larger download and adds the city, the region and the coordinates a map needs. Choose city only if something is going to draw one; the accuracy for anything other than end-user addresses is poor either way."},
			{Key: "geoip_url", Label: "Database URL", Type: "string",
				Help: "A MaxMind-format (.mmdb, optionally .gz) database. {YYYY-MM} is replaced by the current month. Empty: the DB-IP Lite file matching the detail above."},
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
	ctx.Publish("geo", m)
	ctx.Every("geoip", 6*time.Hour, m.refreshGeo)
	ctx.Every("prune", 1*time.Hour, m.prune, core.Delayed())
	ctx.Route("POST", "/api/enrich/lookup", m.apiLookup, core.Write(),
		core.Doc("Batch lookup of DNS names and geolocation countries for IP addresses; unknown names are cached"),
		core.Body(
			core.Fld("ips", "array", true, "List of IP addresses to enrich (max 500)", []string{"8.8.8.8", "1.1.1.1"}),
		),
		core.Returns("Enrichment data", map[string]any{
			"8.8.8.8": map[string]any{"name": "dns.google", "country": "US"},
			"1.1.1.1": map[string]any{"name": "one.one.one.one", "country": "US"},
		}))
	ctx.Route("GET", "/api/enrich/status", m.apiStatus, core.Doc("Query what enrichment is enabled, cache size, and database state"),
		core.Returns("Enrichment status", map[string]any{
			"reverse_dns": true, "geoip": true, "cached_names": 150, "database": "maxmind_geolite",
			"database_updated": 1790376243, "database_bytes": 10485760, "attribution": "IP geolocation by...",
		}))
	ctx.Route("GET", "/api/enrich/countries", m.apiCountries, core.Doc("List all countries available in the GeoIP database for location lookups"),
		core.Returns("Country list", map[string]any{
			"countries": []map[string]any{
				{"code": "US", "name": "United States"},
				{"code": "GB", "name": "United Kingdom"},
			},
			"epoch": 1790376243, "counted": true,
		}))
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
// CountryOf is the ISO country of a public address from the local
// database, or "" when the database is off or the address is local. It
// queues no reverse lookups and is cheap enough to call per flow.
func (m *Module) CountryOf(ip string) string {
	_, geo := m.Enabled()
	if !geo {
		return ""
	}
	addr := net.ParseIP(strings.TrimSpace(ip))
	if addr == nil || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return ""
	}
	if m.identity != nil && m.identity.IsLocal(addr.String()) {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.geo == nil {
		return ""
	}
	info := Info{IP: addr.String()}
	m.place(addr, &info)
	return info.Country
}

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
			m.place(addr, &info)
		}
		// Local addresses are named by identity (leases, reservations, the
		// device's own claim). A reverse record for one is at best the same
		// name and at worst the previous holder's, so it is not looked up.
		if rd && !local {
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

// geoRecord decodes both file shapes. A country database simply leaves the
// city, subdivision and location fields at their zero values, so the same
// struct reads either one and no switch is needed at lookup time.
type geoRecord struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Subdivisions []struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}

// place fills in whatever the loaded database knows about an address.
func (m *Module) place(ip net.IP, info *Info) {
	var rec geoRecord
	if err := m.geo.Lookup(ip, &rec); err != nil {
		return
	}
	info.Country = rec.Country.ISOCode
	info.City = rec.City.Names["en"]
	if len(rec.Subdivisions) > 0 {
		info.Region = rec.Subdivisions[0].Names["en"]
		if info.Region == "" {
			info.Region = rec.Subdivisions[0].ISOCode
		}
	}
	info.Lat, info.Lon = rec.Location.Latitude, rec.Location.Longitude
}

// detail is the level the operator asked for: "country" or "city".
func (m *Module) detail() string {
	if core.Str(m.ctx.Settings(), "geoip_detail", "country") == "city" {
		return "city"
	}
	return "country"
}

// geoURL is the configured URL, or the DB-IP file matching the detail level.
func (m *Module) geoURL() string {
	if u := strings.TrimSpace(core.Str(m.ctx.Settings(), "geoip_url", "")); u != "" {
		return u
	}
	if m.detail() == "city" {
		return defaultGeoCityURL
	}
	return defaultGeoURL
}

// dbPath carries the detail level in its name. Sharing one filename across
// both would let a country file already on disk stand in for the city one
// that was asked for, and the only symptom would be a map with nothing on it.
func (m *Module) dbPath() string {
	return filepath.Join(m.ctx.Platform.DataDir, "geoip-"+m.detail()+".mmdb")
}

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
	if old := m.geo; old != nil {
		// A table build may still be walking the old reader; give it time.
		time.AfterFunc(10*time.Minute, func() { old.Close() })
	}
	m.geo, m.geoAt, m.geoErr = r, modTime(path), ""
	m.geoEpoch = int64(r.Metadata.BuildEpoch)
	m.geoTag = time.Unix(m.geoEpoch, 0).UTC().Format("2006-01-02") + " (" + r.Metadata.DatabaseType + ")"
	m.geoCountries = nil // rebuilt from the new database on demand
	return nil
}

func modTime(p string) time.Time {
	st, err := os.Stat(p)
	if err != nil {
		return time.Time{}
	}
	return st.ModTime()
}

func (m *Module) download(dest string) error { return m.downloadFrom(m.geoURL(), dest) }

func (m *Module) downloadFrom(tmpl, dest string) error {
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
	src := m.geoURL()
	out["attribution"] = ""
	if geo && (src == "" || strings.Contains(src, "db-ip.com")) {
		out["attribution"] = "IP geolocation by DB-IP (db-ip.com), CC BY 4.0"
	}
	return out, nil
}

// ---------------------------------------------------------------- GeoService

var errNoGeo = fmt.Errorf("country lookup not available: Settings › enrich › Country lookup")

// walkRecord is the least a walk has to decode per network. Decoding city
// names and coordinates for millions of networks is what made the first
// version take minutes on the gateway.
type walkRecord struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	Traits struct {
		IsAnycast bool `maxminddb:"is_anycast"` // MaxMind databases carry this; DB-IP does not
	} `maxminddb:"traits"`
}

// tableDB returns the country-level reader, fetching the country file when
// the main database is a city one. Called with m.mu held or not held; it
// takes the lock itself.
func (m *Module) tableDB() (*maxminddb.Reader, int64, error) {
	_, geo := m.Enabled()
	if !geo {
		return nil, 0, errNoGeo
	}
	if m.detail() == "country" {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.geo == nil {
			return nil, 0, errNoGeo
		}
		return m.geo, m.geoEpoch, nil
	}
	path := filepath.Join(m.ctx.Platform.DataDir, "geoip-country.mmdb")
	st, err := os.Stat(path)
	if err != nil || time.Since(st.ModTime()) > 25*24*time.Hour {
		if derr := m.downloadFrom(defaultGeoURL, path); derr != nil && err != nil {
			return nil, 0, fmt.Errorf("country-level database: %w", derr)
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tbl != nil && m.tblAt.Equal(modTime(path)) {
		return m.tbl, m.tblEpoch, nil
	}
	r, err := maxminddb.Open(path)
	if err != nil {
		return nil, 0, err
	}
	if old := m.tbl; old != nil {
		time.AfterFunc(10*time.Minute, func() { old.Close() })
	}
	m.tbl, m.tblAt, m.tblEpoch = r, modTime(path), int64(r.Metadata.BuildEpoch)
	m.geoCountries = nil
	return m.tbl, m.tblEpoch, nil
}

// walk visits every network in the country-level database once.
func (m *Module) walk(visit func(cc string, rec *walkRecord, prefix string)) (int64, error) {
	r, epoch, err := m.tableDB()
	if err != nil {
		return 0, err
	}
	it := r.Networks(maxminddb.SkipAliasedNetworks)
	for it.Next() {
		var rec walkRecord
		prefix, err := it.Network(&rec)
		if err != nil || rec.Country.ISOCode == "" {
			continue
		}
		visit(rec.Country.ISOCode, &rec, prefix.String())
	}
	return epoch, it.Err()
}

// NetworksFor returns the prefixes registered to the given countries, or
// with invert to every other country, in a single pass. Ranges the database
// marks anycast, and any the caller's skip function recognises as anycast,
// are left out: they answer from a nearby site whatever their registration
// says, and a country rule over them would block the wrong thing.
func (m *Module) NetworksFor(ccs []string, invert bool, skip func(prefix string) bool) ([]string, int, error) {
	want := map[string]bool{}
	for _, cc := range ccs {
		want[strings.ToUpper(strings.TrimSpace(cc))] = true
	}
	var out []string
	skipped := 0
	_, err := m.walk(func(cc string, rec *walkRecord, prefix string) {
		if want[cc] == invert {
			return
		}
		if rec.Traits.IsAnycast || (skip != nil && skip(prefix)) {
			skipped++
			return
		}
		out = append(out, prefix)
	})
	return out, skipped, err
}

// Countries lists the countries a policy can name: the ISO 3166-1 table
// with English names, answered at once, plus prefix counts from a background
// walk of the database once it has run.
func (m *Module) Countries() ([]core.CountryInfo, error) {
	_, epoch, err := m.tableDB()
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	counts := m.counts
	if m.countsFor != epoch && !m.countsBusy {
		m.countsBusy = true
		go m.countPrefixes(epoch)
	}
	m.mu.Unlock()
	out := make([]core.CountryInfo, 0, len(isoNames))
	for cc, name := range isoNames {
		out = append(out, core.CountryInfo{Code: cc, Name: name, Prefixes: counts[cc]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Module) countPrefixes(epoch int64) {
	counts := map[string]int{}
	_, err := m.walk(func(cc string, _ *walkRecord, _ string) { counts[cc]++ })
	m.mu.Lock()
	m.countsBusy = false
	if err == nil {
		m.counts, m.countsFor = counts, epoch
	}
	m.mu.Unlock()
}

// DatabaseEpoch returns the build epoch of the country-level database, or 0.
func (m *Module) DatabaseEpoch() int64 {
	_, epoch, err := m.tableDB()
	if err != nil {
		return 0
	}
	return epoch
}

func (m *Module) apiCountries(r *core.Req) (any, error) {
	countries, err := m.Countries()
	if err != nil {
		return map[string]any{"error": err.Error(), "countries": []core.CountryInfo{}}, nil
	}
	m.mu.Lock()
	counted := m.countsFor != 0 && m.countsFor == m.tblEpochOrGeo()
	m.mu.Unlock()
	return map[string]any{"countries": countries, "epoch": m.DatabaseEpoch(), "counted": counted}, nil
}

// tblEpochOrGeo is the epoch of whichever reader tables are built from; m.mu held.
func (m *Module) tblEpochOrGeo() int64 {
	if m.detail() == "country" {
		return m.geoEpoch
	}
	return m.tblEpoch
}
