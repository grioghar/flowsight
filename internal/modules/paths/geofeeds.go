package paths

// Geofeeds: the registry route to real city-level data.
//
// The registries' own address for a block is the registrant's head office.
// What some operators do instead is publish a geofeed -- RFC 8805, a CSV of
// prefix, country, region, city -- and point to it from the block's registry
// object: a "geofeed:" attribute at RIPE and APNIC, a remark titled Geofeed at
// ARIN, a link in the RDAP answer. FlowSight already asks RDAP about every
// hop; now it keeps any geofeed URL the answer carries, fetches each feed
// once a week through the public-only client, and treats its rows like a
// provider's own range list -- the operator's statement, outranking the
// database and a measurement made from somewhere else.

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

const geofeedsKV = "paths.geofeeds"

var geofeedURLRe = regexp.MustCompile(`https?://[^\s"'<>]+`)

// geofeedRecord is what is known about one discovered feed.
type geofeedRecord struct {
	URL       string `json:"url"`
	SeenOn    string `json:"seen_on"` // an address whose registry object named it
	Found     int64  `json:"found"`
	FetchedAt int64  `json:"fetched_at,omitempty"`
	Rows      int    `json:"rows,omitempty"`
	Unplaced  int    `json:"unplaced,omitempty"`
	Error     string `json:"error,omitempty"`
}

// geofeedFromRDAP finds a geofeed URL in an RDAP answer: a remark whose
// title or first line says geofeed, or a link with that relation.
func geofeedFromRDAP(r *rdapReply) string {
	for _, l := range r.Links {
		if strings.EqualFold(l.Rel, "geofeed") && l.Href != "" {
			return l.Href
		}
	}
	for _, rm := range r.Remarks {
		text := strings.ToLower(rm.Title + " " + strings.Join(rm.Description, " "))
		if !strings.Contains(text, "geofeed") {
			continue
		}
		if u := geofeedURLRe.FindString(strings.Join(rm.Description, " ")); u != "" {
			return strings.TrimRight(u, ".,;)")
		}
	}
	return ""
}

func (m *Module) geofeedsOn() bool {
	return m.ctx != nil && core.Bool(m.ctx.Settings(), "geofeeds", true)
}

// noteGeofeed records a discovered URL. Called from the registry lookup.
func (m *Module) noteGeofeed(u, ip string) {
	if u == "" || !m.geofeedsOn() || checkFetchURL(u) != nil || m.ctx.Store == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	recs := m.geofeedRecords()
	if _, ok := recs[u]; ok {
		return
	}
	if len(recs) >= 500 {
		return // enough; a registry cannot be allowed to hand us a crawl
	}
	recs[u] = &geofeedRecord{URL: u, SeenOn: ip, Found: time.Now().Unix()}
	_ = m.ctx.Store.KVSet(geofeedsKV, recs)
}

// geofeedRecords loads the registry; called with m.mu held.
func (m *Module) geofeedRecords() map[string]*geofeedRecord {
	recs := map[string]*geofeedRecord{}
	if m.ctx != nil && m.ctx.Store != nil {
		m.ctx.Store.KVGet(geofeedsKV, &recs)
	}
	return recs
}

func geofeedFile(u string) string {
	h := sha1.Sum([]byte(u))
	return "geofeed-" + hex.EncodeToString(h[:8]) + ".csv"
}

// refreshGeofeeds fetches the stalest discovered feed, one per run.
func (m *Module) refreshGeofeeds() error {
	if !m.geofeedsOn() {
		return nil
	}
	m.mu.Lock()
	recs := m.geofeedRecords()
	m.mu.Unlock()
	var pick *geofeedRecord
	for _, r := range recs {
		age := time.Since(time.Unix(r.FetchedAt, 0))
		if r.FetchedAt == 0 {
			age = 400 * 24 * time.Hour
		}
		if age < 7*24*time.Hour {
			continue
		}
		if pick == nil || r.FetchedAt < pick.FetchedAt {
			pick = r
		}
	}
	if pick == nil {
		return nil
	}
	dir := m.providersDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	rows, unplaced, err := m.fetchGeofeed(pick.URL, filepath.Join(dir, geofeedFile(pick.URL)))
	m.mu.Lock()
	recs = m.geofeedRecords()
	if r := recs[pick.URL]; r != nil {
		r.FetchedAt = time.Now().Unix()
		if err != nil {
			r.Error = err.Error()
		} else {
			r.Rows, r.Unplaced, r.Error = rows, unplaced, ""
		}
	}
	_ = m.ctx.Store.KVSet(geofeedsKV, recs)
	m.mu.Unlock()
	if err == nil && rows > 0 {
		m.mu.Lock()
		stats := m.provider.Feeds
		m.mu.Unlock()
		if stats == nil {
			stats = map[string]providerStats{}
		}
		return m.loadProviders(stats)
	}
	return nil
}

func (m *Module) fetchGeofeed(u, path string) (int, int, error) {
	if err := checkFetchURL(u); err != nil {
		return 0, 0, err
	}
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("User-Agent", "FlowSight/"+m.version()+" (+https://github.com/grioghar/flowsight; RFC 8805 geofeed)")
	resp, err := safeClient(2 * time.Minute).Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("%s", resp.Status)
	}
	host := shortHost(u)
	tmp := path + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return 0, 0, err
	}
	n, unplaced := 0, 0
	emit := func(prefix, region string, anycast bool) {
		pl, ok := regionPlace("do", region) // the geofeed city table
		if !ok {
			unplaced++
			return
		}
		fmt.Fprintf(out, "%s,%s,%s,%.4f,%.4f,%s,false\n", prefix, csvSafe("geofeed "+host), csvSafe(region), pl.Lat, pl.Lon, csvSafe(pl.City))
		n++
	}
	perr := parseGeofeed(&throttled{r: http.MaxBytesReader(nil, resp.Body, 32<<20), rate: 1 << 20}, emit)
	out.Close()
	if perr != nil {
		os.Remove(tmp)
		return 0, unplaced, perr
	}
	if n == 0 {
		os.Remove(tmp)
		return 0, unplaced, fmt.Errorf("no rows with a city the tables know (%d unplaced)", unplaced)
	}
	return n, unplaced, os.Rename(tmp, path)
}

// geofeedStatus summarises the registry for the card.
func (m *Module) geofeedStatus() map[string]any {
	m.mu.Lock()
	recs := m.geofeedRecords()
	m.mu.Unlock()
	rows, fetched, failed := 0, 0, 0
	for _, r := range recs {
		rows += r.Rows
		if r.FetchedAt > 0 {
			fetched++
		}
		if r.Error != "" {
			failed++
		}
	}
	return map[string]any{"on": m.geofeedsOn(), "urls": len(recs), "fetched": fetched, "failed": failed, "rows": rows}
}

// apiGeofeeds lists what has been discovered, for the API.
func (m *Module) apiGeofeeds(r *core.Req) (any, error) {
	m.mu.Lock()
	recs := m.geofeedRecords()
	m.mu.Unlock()
	out := make([]geofeedRecord, 0, len(recs))
	for _, x := range recs {
		out = append(out, *x)
	}
	return map[string]any{"geofeeds": out, "note": "RFC 8805 feeds named in the registry objects of hops seen on routes; each is fetched weekly and its rows place addresses like a provider's own range list."}, nil
}
