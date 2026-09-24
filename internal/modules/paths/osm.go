package paths

// Telecom lines from OpenStreetMap, as a low-weight land-route source.
//
// OpenStreetMap carries fibre and telecom lines where mappers have drawn
// them: dense in a few well-mapped countries, absent elsewhere, and mostly
// the visible kind -- overhead lines, marked ducts, the odd long-haul route
// -- rather than the buried long-haul a packet actually rides. So it is
// used, but at half weight: where an OSM line offers a route between two
// hops, the expected time is the average of following it and the plain
// detour estimate. It never touches the physics floor and is never drawn as
// the route a leg took.
//
// It comes from the Overpass API, which is a shared public service with
// rules about use. One ten-degree tile is fetched per run, runs are twenty
// minutes apart while tiles are outstanding, a tile is kept a month, a
// timeout waits an hour and a refusal six. Tiles are taken in order of how
// many placed hops fall in each, so the parts of the world this network's
// traffic actually crosses are covered first; the whole populated world is
// a few hundred tiles and takes about five days the first time.

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

const defaultOverpassURL = "https://overpass-api.de/api/interpreter"

// osmWeight is how much an OSM line counts against the detour estimate.
const osmWeight = 0.5

// osmBox is one region asked for at a time. Names are for the status card.
type osmBox struct {
	Name       string
	S, W, N, E float64
}

// osmBoxes cover the populated world in pieces small enough for one Overpass
// call each. Oceans and the poles are left out; nothing is buried there
// that OpenStreetMap knows about.
var osmBoxes = []osmBox{
	{"North America, east", 24, -100, 50, -60},
	{"North America, central", 24, -125, 50, -100},
	{"North America, north & west", 48, -170, 72, -50},
	{"Central America & Caribbean", 5, -120, 24, -58},
	{"South America, north", -20, -82, 13, -34},
	{"South America, south", -56, -76, -20, -34},
	{"Europe, west", 35, -12, 62, 20},
	{"Europe, east & Russia west", 35, 20, 72, 60},
	{"Middle East", 12, 25, 42, 64},
	{"Africa, north & west", 4, -20, 38, 25},
	{"Africa, east & south", -36, 10, 20, 52},
	{"Asia, central & south", 5, 60, 45, 95},
	{"Asia, east", 18, 95, 54, 150},
	{"Southeast Asia", -11, 92, 24, 142},
	{"Australia & New Zealand", -48, 110, -10, 180},
	{"Russia, east", 45, 60, 78, 180},
}

// osmTiles cuts the regions into ten-degree tiles. A whole region -- the
// eastern United States is forty degrees across -- timed out at the public
// Overpass server; a tile answers in seconds, and there are about a hundred
// of them over the populated world.
func osmTiles() []osmBox {
	var out []osmBox
	seen := map[string]bool{}
	for _, b := range osmBoxes {
		for s := b.S; s < b.N; s += 10 {
			for w := b.W; w < b.E; w += 10 {
				n, e := s+10, w+10
				if n > b.N {
					n = b.N
				}
				if e > b.E {
					e = b.E
				}
				t := osmBox{fmt.Sprintf("%s %+.0f%+.0f", b.Name, s, w), s, w, n, e}
				if !seen[t.Name] {
					seen[t.Name] = true
					out = append(out, t)
				}
			}
		}
	}
	return out
}

func osmFile(b osmBox) string {
	return fmt.Sprintf("osm-%s.geojson", strings.NewReplacer(" ", "-", ",", "", "&", "and", "+", "p").Replace(strings.ToLower(b.Name)))
}

// overpassQuery asks for every way tagged as a telecom line in the box, with
// its geometry. Three tags, because mappers have used all three.
func overpassQuery(b osmBox) string {
	bb := fmt.Sprintf("%.2f,%.2f,%.2f,%.2f", b.S, b.W, b.N, b.E)
	return fmt.Sprintf(`[out:json][timeout:90][maxsize:67108864];(way["telecom"="line"](%s);way["communication"="line"](%s);way["telecom"="cable"](%s););out geom;`, bb, bb, bb)
}

// overpassToGeoJSON turns an Overpass JSON answer into the GeoJSON shape the
// cable loader already reads: one MultiLineString feature per way, named by
// its name, else its operator, else its way id.
func overpassToGeoJSON(raw []byte) ([]byte, int, error) {
	var in struct {
		Elements []struct {
			Type     string            `json:"type"`
			ID       int64             `json:"id"`
			Tags     map[string]string `json:"tags"`
			Geometry []struct {
				Lat float64 `json:"lat"`
				Lon float64 `json:"lon"`
			} `json:"geometry"`
		} `json:"elements"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, 0, err
	}
	type feature struct {
		Type       string         `json:"type"`
		Properties map[string]any `json:"properties"`
		Geometry   struct {
			Type        string         `json:"type"`
			Coordinates [][][2]float64 `json:"coordinates"`
		} `json:"geometry"`
	}
	out := struct {
		Type     string    `json:"type"`
		Features []feature `json:"features"`
	}{Type: "FeatureCollection"}
	for _, e := range in.Elements {
		if e.Type != "way" || len(e.Geometry) < 2 {
			continue
		}
		f := feature{Type: "Feature", Properties: map[string]any{}}
		name := firstNonEmptyStr(e.Tags["name"], e.Tags["operator"])
		if name == "" {
			name = fmt.Sprintf("OSM way %d", e.ID)
		}
		f.Properties["id"] = fmt.Sprintf("osm-%d", e.ID)
		f.Properties["name"] = name
		if op := e.Tags["operator"]; op != "" {
			f.Properties["operator"] = op
		}
		run := make([][2]float64, 0, len(e.Geometry))
		for _, g := range e.Geometry {
			run = append(run, [2]float64{g.Lon, g.Lat})
		}
		f.Geometry.Type = "MultiLineString"
		f.Geometry.Coordinates = [][][2]float64{run}
		out.Features = append(out.Features, f)
	}
	b, err := json.Marshal(out)
	return b, len(out.Features), err
}

// osmState is what the status card shows.
type osmState struct {
	On      bool    `json:"on"`
	Ways    int     `json:"ways"`
	Regions int     `json:"regions_loaded"`
	Of      int     `json:"regions_total"`
	Next    string  `json:"next_region,omitempty"`
	Error   string  `json:"error,omitempty"`
	Until   int64   `json:"backing_off_until,omitempty"`
	Weight  float64 `json:"weight"`
}

// nextOSMBox is the region most worth fetching: stale (missing or a month
// old), and with the most placed hops in it.
func (m *Module) nextOSMBox() (osmBox, bool) {
	dir := m.terrestrialDir()
	m.mu.Lock()
	counts := map[string]int{}
	for k, v := range m.hopBoxes {
		counts[k] = v
	}
	m.mu.Unlock()
	var stale []osmBox
	for _, b := range osmTiles() {
		st, err := os.Stat(filepath.Join(dir, osmFile(b)))
		if err != nil || time.Since(st.ModTime()) > 30*24*time.Hour {
			stale = append(stale, b)
		}
	}
	if len(stale) == 0 {
		return osmBox{}, false
	}
	sort.SliceStable(stale, func(i, j int) bool { return counts[stale[i].Name] > counts[stale[j].Name] })
	return stale[0], true
}

// boxOf is which region a place falls in, for counting hops per region.
func boxOf(lat, lon float64) string {
	for _, b := range osmTiles() {
		if lat >= b.S && lat < b.N && lon >= b.W && lon < b.E {
			return b.Name
		}
	}
	return ""
}

// regionOf is the coarse region a place falls in, for tests and for
// reading a tile name.
func regionOf(lat, lon float64) string {
	for _, b := range osmBoxes {
		if lat >= b.S && lat < b.N && lon >= b.W && lon < b.E {
			return b.Name
		}
	}
	return ""
}

// refreshOSM fetches one stale tile, converts it, and reloads the OSM
// networks. Idle once every tile is fresh.
func (m *Module) refreshOSM() error {
	if !core.Bool(m.ctx.Settings(), "osm_telecom", true) {
		m.mu.Lock()
		m.osmNets, m.osm = nil, osmState{Weight: osmWeight}
		m.mu.Unlock()
		m.routes.reset()
		return nil
	}
	dir := m.terrestrialDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	m.mu.Lock()
	until := m.osmUntil
	m.mu.Unlock()
	if time.Now().Before(until) {
		return m.loadOSM()
	}
	if b, ok := m.nextOSMBox(); ok {
		if err := m.fetchOSMBox(b); err != nil {
			// A refusal (429) means asked too often: wait six hours. A
			// timeout or a server error means the tile or the server was
			// heavy just now: try again in an hour, with the next tile.
			wait := time.Hour
			if strings.Contains(err.Error(), "429") {
				wait = 6 * time.Hour
			}
			m.mu.Lock()
			m.osm.Error = b.Name + ": " + err.Error()
			m.osmUntil = time.Now().Add(wait)
			m.mu.Unlock()
		} else {
			m.mu.Lock()
			m.osm.Error = ""
			m.mu.Unlock()
		}
	}
	return m.loadOSM()
}

func (m *Module) fetchOSMBox(b osmBox) error {
	u := strings.TrimSpace(core.Str(m.ctx.Settings(), "osm_overpass_url", defaultOverpassURL))
	if u == "" {
		u = defaultOverpassURL
	}
	client := safeClient(4 * time.Minute)
	if err := checkFetchURL(u); err != nil {
		// A private Overpass is the one case where a private host is the
		// point: the operator runs their own on this network and says so.
		if !core.Bool(m.ctx.Settings(), "osm_overpass_local", false) || !isPrivateURL(u) {
			return err
		}
		client = &http.Client{Timeout: 4 * time.Minute}
	}
	req, err := http.NewRequest("POST", u, strings.NewReader("data="+overpassQuery(b)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "FlowSight/"+m.version()+" (+https://github.com/grioghar/flowsight; telecom lines, one region per run)")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("overpass: %s", resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	gj, n, err := overpassToGeoJSON(raw)
	if err != nil {
		return err
	}
	path := filepath.Join(m.terrestrialDir(), osmFile(b))
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, gj, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if m.ctx.Log != nil {
		m.ctx.Log.Info("osm telecom lines fetched", "region", b.Name, "ways", n)
	}
	return nil
}

func (m *Module) version() string {
	if m.ctx != nil && m.ctx.Core != nil {
		return m.ctx.Core.Version
	}
	return "dev"
}

// loadOSM reads every region on disk into networks at half weight.
func (m *Module) loadOSM() error {
	files, _ := filepath.Glob(filepath.Join(m.terrestrialDir(), "osm-*.geojson"))
	var nets []cableNet
	ways := 0
	for _, f := range files {
		routes, err := loadCables(f)
		if err != nil {
			continue
		}
		for _, r := range routes {
			n := buildNet(r)
			n.Weight = osmWeight
			nets = append(nets, n)
		}
		ways += len(routes)
	}
	if _, edges := netSize(nets); edges > maxNetEdges {
		m.mu.Lock()
		m.osmNets = nil
		m.osm = osmState{On: true, Of: len(osmTiles()), Weight: osmWeight, Error: fmt.Sprintf("%d edges after stitching, more than this daemon will hold; not loaded", edges)}
		m.mu.Unlock()
		return nil
	}
	next := ""
	if b, ok := m.nextOSMBox(); ok {
		next = b.Name
	}
	m.mu.Lock()
	prevErr, until := m.osm.Error, m.osmUntil
	m.osmNets = nets
	m.osm = osmState{On: true, Ways: ways, Regions: len(files), Of: len(osmTiles()), Next: next, Weight: osmWeight, Error: prevErr}
	if time.Now().Before(until) {
		m.osm.Until = until.Unix()
	}
	m.mu.Unlock()
	m.routes.reset()
	return nil
}

// tallyHopBoxes counts placed hops per region, so fetching starts where the
// traffic is.
func (m *Module) tallyHopBoxes(nodes []Node) {
	counts := map[string]int{}
	for _, n := range nodes {
		if n.Located {
			if k := boxOf(n.Lat, n.Lon); k != "" {
				counts[k]++
			}
		}
	}
	m.mu.Lock()
	m.hopBoxes = counts
	m.mu.Unlock()
}

// isPrivateURL says whether a URL points at an address on a private range,
// as opposed to being malformed or a public host the public-only client
// would have accepted anyway.
func isPrivateURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if ip == nil {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return false
		}
		ip = ips[0]
	}
	return publicOnly(ip) != nil && !ip.IsLoopback() && !ip.IsUnspecified()
}
