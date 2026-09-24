package paths

// What the database gets wrong, remembered.
//
// The address database places a block where it was registered. For a
// carrier that is a head office: every Akamai address on earth arrives at
// 42.36, -71.09, which is a building in Cambridge, Massachusetts, and the
// router named ae10.r02.rio01.icn is in Seoul. The name wins on the map, and
// the round trip agrees with it -- but the win was made afresh on every
// rebuild and never taught the database anything, so the next address in the
// same block, with no site in its name, went straight back to Cambridge.
//
// Two things are learned here, both from evidence the map already had.
//
// A correction: when a router's name or a measurement places a hop far from
// where the database put it, the announced prefix the hop belongs to is
// recorded as being there. Another address in that prefix that the database
// alone would place is placed by the correction instead, and says so.
//
// A distrusted coordinate: when the database puts addresses of one network
// at the same spot and two of them are shown, by name or measurement, to be
// somewhere else, that spot is the registrant's address, not a router's. The
// database is then not believed about any address of that network it puts
// there; the hop is left unplaced, which lets the timing put it between its
// neighbours -- a guess about where, honestly labelled, rather than a
// building on the wrong continent.
//
// Both are kept in the store, survive restarts, are listed on the API and can
// be forgotten one at a time. Neither is applied to an address the database
// places somewhere else: a correction is about one prefix, a distrust about
// one coordinate.

import (
	"fmt"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

const fixesKV = "paths.fixes"

// A database placement has to be this far off before anything is learned
// from it: well beyond a database's usual city-level error.
const learnKM = 500

// distrustAfter is how many contradictions a coordinate needs before the
// database stops being believed about it. One could be a bad name; two
// addresses of one network at one spot, both shown elsewhere, is a pattern.
const distrustAfter = 2

// Correction is where a prefix really is, learned from one of its routers.
type Correction struct {
	Prefix  string    `json:"prefix"`
	Lat     float64   `json:"lat"`
	Lon     float64   `json:"lon"`
	City    string    `json:"city,omitempty"`
	Region  string    `json:"region,omitempty"`
	Country string    `json:"country,omitempty"`
	By      string    `json:"by"`      // the router name or "RIPE IPmap"
	From    string    `json:"from"`    // where the database had put it
	FromKM  float64   `json:"from_km"` // how far off that was
	At      time.Time `json:"at"`
	Seen    int       `json:"seen"` // how many hops have confirmed it
}

// Distrust is a coordinate the database uses for a network's blocks that is
// not where the network's routers are.
type Distrust struct {
	Key      string    `json:"key"` // asn|lat|lon
	ASN      int       `json:"asn"`
	Lat      float64   `json:"lat"`
	Lon      float64   `json:"lon"`
	Place    string    `json:"place,omitempty"`
	Count    int       `json:"count"`
	Examples []string  `json:"examples,omitempty"` // "ip -> city (by)"
	At       time.Time `json:"at"`
}

type fixStore struct {
	Corrections map[string]*Correction `json:"corrections"`
	Distrusted  map[string]*Distrust   `json:"distrusted"`
}

// fixes is the in-memory copy, loaded once and written on change.
type fixes struct {
	mu   sync.Mutex
	s    fixStore
	nets map[string]*net.IPNet // parsed prefixes, same keys as Corrections
	on   bool
}

func (f *fixes) load(st *core.Store) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.s = fixStore{Corrections: map[string]*Correction{}, Distrusted: map[string]*Distrust{}}
	f.nets = map[string]*net.IPNet{}
	if st == nil {
		return
	}
	var s fixStore
	if st.KVGet(fixesKV, &s) {
		if s.Corrections != nil {
			f.s.Corrections = s.Corrections
		}
		if s.Distrusted != nil {
			f.s.Distrusted = s.Distrusted
		}
	}
	for p := range f.s.Corrections {
		if _, n, err := net.ParseCIDR(p); err == nil {
			f.nets[p] = n
		}
	}
}

func (f *fixes) save(st *core.Store) {
	if st != nil {
		_ = st.KVSet(fixesKV, f.s)
	}
}

func distrustKey(asn int, lat, lon float64) string {
	r := func(v float64) float64 { return math.Round(v*20) / 20 } // 0.05 degrees, a few km
	return fmt.Sprintf("%d|%.2f|%.2f", asn, r(lat), r(lon))
}

// prefixFor is the block a correction is recorded against: the announced
// prefix when the routing table gave one, otherwise a /24 or /48, which is
// the smallest thing anyone routes and so the smallest thing a database
// entry could reasonably cover.
func prefixFor(ip, announced string) string {
	if announced != "" {
		if _, n, err := net.ParseCIDR(announced); err == nil {
			return n.String()
		}
	}
	a := net.ParseIP(ip)
	if a == nil {
		return ""
	}
	if v4 := a.To4(); v4 != nil {
		return (&net.IPNet{IP: v4.Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)}).String()
	}
	return (&net.IPNet{IP: a.Mask(net.CIDRMask(48, 128)), Mask: net.CIDRMask(48, 128)}).String()
}

// learn records what a name or a measurement has just shown about a hop the
// database had elsewhere. Called only when the two disagree by more than
// learnKM.
func (m *Module) learn(ip string, d *Detail, by string, dbLat, dbLon float64, dbPlace string, lat, lon float64, city, region, country string, km float64) {
	if !m.fixes.on || ip == "" {
		return
	}
	prefix := prefixFor(ip, detailPrefix(d))
	if prefix == "" {
		return
	}
	f := &m.fixes
	f.mu.Lock()
	changed := false
	c := f.s.Corrections[prefix]
	if c == nil {
		c = &Correction{Prefix: prefix, Lat: lat, Lon: lon, City: city, Region: region, Country: country,
			By: by, From: dbPlace, FromKM: math.Round(km), At: time.Now(), Seen: 1}
		f.s.Corrections[prefix] = c
		if _, n, err := net.ParseCIDR(prefix); err == nil {
			f.nets[prefix] = n
		}
		changed = true
	} else if greatCircleKM(c.Lat, c.Lon, lat, lon) < 250 {
		c.Seen++
		changed = true
	}
	// The coordinate itself: one network, one spot, contradicted again.
	if asn := detailASN(d); asn > 0 && (dbLat != 0 || dbLon != 0) {
		k := distrustKey(asn, dbLat, dbLon)
		x := f.s.Distrusted[k]
		if x == nil {
			x = &Distrust{Key: k, ASN: asn, Lat: dbLat, Lon: dbLon, Place: dbPlace, At: time.Now()}
			f.s.Distrusted[k] = x
		}
		ex := fmt.Sprintf("%s -> %s (%s)", ip, firstNonEmptyStr(city, country), by)
		if !contains(x.Examples, ex) {
			x.Count++
			if len(x.Examples) < 6 {
				x.Examples = append(x.Examples, ex)
			}
			changed = true
		}
	}
	f.mu.Unlock()
	if changed {
		f.save(m.ctx.Store)
	}
}

// correctionFor is the learned position for an address, if one covers it.
func (m *Module) correctionFor(ip string) *Correction {
	if !m.fixes.on {
		return nil
	}
	a := net.ParseIP(ip)
	if a == nil {
		return nil
	}
	f := &m.fixes
	f.mu.Lock()
	defer f.mu.Unlock()
	var best *Correction
	bestBits := -1
	for p, n := range f.nets {
		if !n.Contains(a) {
			continue
		}
		if bits, _ := n.Mask.Size(); bits > bestBits { // the most specific prefix wins
			best, bestBits = f.s.Corrections[p], bits
		}
	}
	return best
}

// distrusted says whether the database's coordinate for this network is one
// its routers have been shown not to be at.
func (m *Module) distrusted(asn int, lat, lon float64) *Distrust {
	if !m.fixes.on || asn <= 0 {
		return nil
	}
	f := &m.fixes
	f.mu.Lock()
	defer f.mu.Unlock()
	x := f.s.Distrusted[distrustKey(asn, lat, lon)]
	if x == nil || x.Count < distrustAfter {
		return nil
	}
	return x
}

func (m *Module) fixCounts() (corrections, distrusted int) {
	f := &m.fixes
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, x := range f.s.Distrusted {
		if x.Count >= distrustAfter {
			distrusted++
		}
	}
	return len(f.s.Corrections), distrusted
}

// apiCorrections lists what has been learned.
func (m *Module) apiCorrections(r *core.Req) (any, error) {
	f := &m.fixes
	f.mu.Lock()
	cs := make([]Correction, 0, len(f.s.Corrections))
	for _, c := range f.s.Corrections {
		cs = append(cs, *c)
	}
	ds := make([]Distrust, 0, len(f.s.Distrusted))
	for _, d := range f.s.Distrusted {
		ds = append(ds, *d)
	}
	f.mu.Unlock()
	sort.Slice(cs, func(i, j int) bool { return cs[i].At.After(cs[j].At) })
	sort.Slice(ds, func(i, j int) bool { return ds[i].Count > ds[j].Count })
	return map[string]any{"on": m.fixes.on, "corrections": cs, "distrusted": ds, "distrust_after": distrustAfter,
		"note": "A correction places every address of a prefix where one of its routers was shown to be. A distrusted coordinate is a registrant's address the database uses for a network's blocks; once contradicted twice it is not believed, and hops there are placed by timing instead."}, nil
}

// apiForgetFix drops one learned item: a prefix, or a distrust key.
func (m *Module) apiForgetFix(r *core.Req) (any, error) {
	body := r.Body()
	prefix, _ := body["prefix"].(string)
	key, _ := body["key"].(string)
	prefix, key = strings.TrimSpace(prefix), strings.TrimSpace(key)
	if prefix == "" && key == "" {
		return nil, core.BadRequest("prefix or key is required")
	}
	f := &m.fixes
	f.mu.Lock()
	_, hadP := f.s.Corrections[prefix]
	_, hadK := f.s.Distrusted[key]
	delete(f.s.Corrections, prefix)
	delete(f.nets, prefix)
	delete(f.s.Distrusted, key)
	f.mu.Unlock()
	if !hadP && !hadK {
		return nil, core.NotFound("nothing learned under that prefix or key")
	}
	f.save(m.ctx.Store)
	m.mu.Lock()
	m.graphCache = nil // placements changed
	m.mu.Unlock()
	return map[string]any{"ok": true}, nil
}

func detailPrefix(d *Detail) string {
	if d == nil {
		return ""
	}
	return d.Prefix
}

func detailASN(d *Detail) int {
	if d == nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimPrefix(strings.ToUpper(d.ASN), "AS"))
	return n
}

func firstNonEmptyStr(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}
