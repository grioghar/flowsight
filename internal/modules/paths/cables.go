package paths

// Submarine cables: which ones a leg could have crossed, and which it could
// not.
//
// A traceroute never names a cable. It gives router addresses and round
// trips, and if two places are joined by eight cables then all eight fit the
// observation equally well. So nothing here claims a packet took a particular
// cable. What it does is narrow the field and, more usefully, rule members of
// it out.
//
// The ruling out is the part that is not guesswork. Light in fibre covers
// about 200,000 km per second, so a cable of length L cannot carry a round
// trip faster than 2L/200,000. A leg measured faster than that did not use
// that cable, whatever the map suggests. Cables are long and often far from
// direct, so this discards a great many candidates outright.
//
// The data is TeleGeography's, fetched at runtime from their public endpoint
// rather than shipped, and cached like the location database.

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/grioghar/flowsight/internal/core"
)

const defaultCableURL = "https://www.submarinecablemap.com/api/v3/cable/cable-geo.json"

// Cable is one cable, reduced to what matching needs.
type Cable struct {
	ID   string     `json:"id"`
	Name string     `json:"name"`
	Legs [][]LatLon `json:"-"` // the routed geometry, one run per segment
	KM   float64    `json:"km"`
}

// LatLon is a point on a cable.
type LatLon struct {
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
}

// Candidate is a cable a leg could have crossed, with the stretch of it that
// lies between the two ends.
type Candidate struct {
	Name    string  `json:"name"`
	KM      float64 `json:"km"`       // along the cable, between the two landfalls
	FloorMS float64 `json:"floor_ms"` // the fastest that stretch could answer
}

// ---------------------------------------------------------------- fetching

func (m *Module) cablePath() string {
	return filepath.Join(m.ctx.Platform.DataDir, "submarine-cables.json")
}

// refreshCables keeps a local copy, downloading when it is missing or a month
// old. Cables are laid over years; there is nothing to gain by asking often.
func (m *Module) refreshCables() error {
	if !core.Bool(m.ctx.Settings(), "cables", false) {
		m.mu.Lock()
		m.cables, m.cableErr = nil, ""
		m.mu.Unlock()
		return nil
	}
	path := m.cablePath()
	st, err := os.Stat(path)
	stale := err != nil || time.Since(st.ModTime()) > 30*24*time.Hour
	if stale {
		if err := m.downloadCables(path); err != nil {
			m.mu.Lock()
			m.cableErr = err.Error()
			m.mu.Unlock()
			// An old copy is better than none; fall through and load it.
			if _, e := os.Stat(path); e != nil {
				return nil
			}
		}
	}
	cables, err := loadCables(path)
	if err != nil {
		m.mu.Lock()
		m.cableErr = err.Error()
		m.mu.Unlock()
		return nil
	}
	m.mu.Lock()
	// Stitched once, here, rather than on every request: a cable is a set of
	// runs and the search needs it as one connected thing.
	nets := make([]cableNet, 0, len(cables))
	for _, c := range cables {
		nets = append(nets, buildNet(c))
	}
	m.cables, m.nets, m.cableErr = cables, nets, ""
	m.mu.Unlock()
	return nil
}

func (m *Module) downloadCables(path string) error {
	url := strings.TrimSpace(core.Str(m.ctx.Settings(), "cables_url", ""))
	if url == "" {
		url = defaultCableURL
	}
	return m.downloadTo(url, path)
}

// downloadTo fetches one published map to a local file, replacing it only
// once the whole thing has arrived: a half-written copy is worse than a
// month-old one.
func (m *Module) downloadTo(url, path string) error {
	if err := checkFetchURL(url); err != nil {
		return err
	}
	// Generous overall, tight on the parts that hang: the same shape the
	// updater uses, after a thirty-second overall limit once failed a
	// fourteen-megabyte download on an ordinary connection. Public hosts only:
	// this URL is operator-supplied, and a daemon that fetches whatever it is
	// told is a proxy into the network it sits in.
	client := safeClient(10 * time.Minute)
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", url, resp.Status)
	}
	var r io.Reader = io.LimitReader(resp.Body, 64<<20)
	if strings.HasSuffix(url, ".gz") {
		gz, err := gzip.NewReader(r)
		if err != nil {
			return err
		}
		defer gz.Close()
		// The limit above is on the wire; a file that inflates past it is
		// not a cable map, and must not be allowed to fill the disk.
		r = io.LimitReader(gz, 256<<20)
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	f.Close()
	return os.Rename(tmp, path)
}

// geoJSON is the shape of the published file, reduced to what is read.
type geoJSON struct {
	Features []struct {
		Properties struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Operator string `json:"operator"` // AfTerFibre names routes this way instead
			Country  string `json:"country"`
		} `json:"properties"`
		Geometry struct {
			Type        string          `json:"type"`
			Coordinates json.RawMessage `json:"coordinates"`
		} `json:"geometry"`
	} `json:"features"`
}

func loadCables(path string) ([]Cable, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc geoJSON
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("cable data: %w", err)
	}
	byID := map[string]*Cable{}
	for i, f := range doc.Features {
		if f.Geometry.Type != "MultiLineString" {
			continue
		}
		// Positions may carry a third element -- GIS exports write
		// [lon, lat, elevation] -- and decoding into pairs rejected every one
		// of them without a word. That is how a 5 MB file of 133 routes loaded
		// as nothing and reported no error.
		var runs [][][]float64
		if err := json.Unmarshal(f.Geometry.Coordinates, &runs); err != nil {
			continue
		}
		// TeleGeography gives every feature an id and a name. AfTerFibre gives
		// neither, so keyed on the id all 133 of its routes became one cable
		// with no name. A feature with no id is its own route; a route with no
		// name is called after who runs it and where.
		id := f.Properties.ID
		if id == "" {
			id = fmt.Sprintf("feature-%d", i)
		}
		name := repairMojibake(f.Properties.Name)
		if name == "" {
			name = strings.TrimSpace(strings.Join(nonEmptyStrings(f.Properties.Operator, f.Properties.Country), ", "))
		}
		if name == "" {
			name = "route " + fmt.Sprint(i+1)
		}
		c := byID[id]
		if c == nil {
			c = &Cable{ID: id, Name: name}
			byID[id] = c
		}
		for _, run := range runs {
			if len(run) < 2 {
				continue
			}
			pts := make([]LatLon, 0, len(run))
			for _, p := range run {
				if len(p) < 2 {
					continue
				}
				pts = append(pts, LatLon{Lat: p[1], Lon: p[0]}) // GeoJSON is lon,lat; anything after is ignored
			}
			if len(pts) < 2 {
				continue
			}
			c.Legs = append(c.Legs, pts)
			c.KM += runLengthKM(pts)
		}
	}
	out := make([]Cable, 0, len(byID))
	for _, id := range sortedKeys(byID) {
		if c := byID[id]; len(c.Legs) > 0 {
			out = append(out, *c)
		}
	}
	return out, nil
}

func runLengthKM(pts []LatLon) float64 {
	total := 0.0
	for i := 1; i < len(pts); i++ {
		total += greatCircleKM(pts[i-1].Lat, pts[i-1].Lon, pts[i].Lat, pts[i].Lon)
	}
	return total
}

// ---------------------------------------------------------------- matching

// nearestOn finds the closest point of a run to somewhere, returning its
// index and the distance.
func nearestOn(pts []LatLon, lat, lon float64) (int, float64) {
	best, bestKM := -1, math.MaxFloat64
	for i, p := range pts {
		if d := greatCircleKM(lat, lon, p.Lat, p.Lon); d < bestKM {
			best, bestKM = i, d
		}
	}
	return best, bestKM
}

// candidates returns the cables that could carry a leg between two points,
// with the stretch of each that lies between them.
//
// nearKM is how close a cable has to pass to count as serving a place.
// Landfalls are rarely where a router is, and a router is rarely where the
// database says, so this is deliberately loose. observedMS is the leg's
// measured round trip; when it is known, cables too long to have produced it
// are discarded, which is the only part of this that is not inference.
func candidates(cables []Cable, aLat, aLon, bLat, bLon, nearKM, observedMS float64) []Candidate {
	var out []Candidate
	for _, c := range cables {
		bestKM := math.MaxFloat64
		found := false
		for _, run := range c.Legs {
			ia, da := nearestOn(run, aLat, aLon)
			ib, db := nearestOn(run, bLat, bLon)
			if ia < 0 || ib < 0 || da > nearKM || db > nearKM || ia == ib {
				continue
			}
			lo, hi := ia, ib
			if lo > hi {
				lo, hi = hi, lo
			}
			if km := runLengthKM(run[lo : hi+1]); km < bestKM {
				bestKM, found = km, true
			}
		}
		if !found {
			continue
		}
		floor := floorMS(bestKM)
		if observedMS > 0 && observedMS < floor {
			continue // too long to have answered that fast; it was not this one
		}
		out = append(out, Candidate{Name: c.Name, KM: math.Round(bestKM), FloorMS: math.Round(floor*10) / 10})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].KM < out[j].KM })
	if len(out) > 6 {
		out = out[:6]
	}
	return out
}

// annotateCables records, for each leg long enough to have crossed water,
// which cables could have carried it. Short legs are skipped: a hop across
// town has not been near a submarine cable and asking costs the same as
// asking for a real one.
func (m *Module) annotateCables(g Graph) {
	m.mu.Lock()
	cables := m.cables
	m.mu.Unlock()
	if len(cables) == 0 {
		return
	}
	near := float64(core.Int(m.ctx.Settings(), "cable_near_km", 400))
	if near < 25 {
		near = 25
	}
	byID := map[string]*Node{}
	for i := range g.Nodes {
		byID[g.Nodes[i].ID] = &g.Nodes[i]
	}
	for i := range g.Legs {
		l := &g.Legs[i]
		a, b := byID[l.From], byID[l.To]
		if a == nil || b == nil || !a.Located || !b.Located {
			continue
		}
		straight := greatCircleKM(a.Lat, a.Lon, b.Lat, b.Lon)
		if straight < 1000 {
			continue // too short to have left the continent
		}
		observed := 0.0
		if b.RTT > 0 && a.RTT > 0 && b.RTT > a.RTT {
			observed = b.RTT - a.RTT // what this leg added, not the whole path
		}
		l.Cables = candidates(cables, a.Lat, a.Lon, b.Lat, b.Lon, near, observed)
		l.StraightKM = math.Round(straight)
		// The best reading of which crossing this was, and the shape of it,
		// so the leg can be drawn along the cable rather than ruled straight
		// through water no cable goes near.
		if r := m.drawRoute(a.Lat, a.Lon, b.Lat, b.Lon); r.OK {
			l.Via, l.ViaKM, l.Route = r.Name, math.Round(r.KM), r.Route
		}
	}
}

// repairMojibake undoes one round of UTF-8 having been read as Latin-1.
//
// Three cables in the published map arrive this way: Sta'O'Nuk, Sharm El
// Sheikh-Taba and the Sir Abu Nu'ayr Cable, each with a punctuation mark that
// was decoded as single bytes somewhere upstream and encoded again. The
// damage is exactly reversible -- take the string's runes back to the bytes
// they came from and read those as UTF-8 -- and doing so is worth it, because
// a reader who sees a mangled name reasonably doubts everything next to it.
//
// It only acts where the result is a genuine improvement: every rune has to
// fit in a byte, the bytes have to be valid UTF-8, and the answer has to
// differ. Anything else is returned untouched.
func repairMojibake(s string) string {
	if !strings.ContainsRune(s, 'â') && !strings.ContainsRune(s, 'Ã') {
		return s
	}
	b := make([]byte, 0, len(s))
	for _, r := range s {
		if r > 0xFF {
			return s // never was a Latin-1 round trip
		}
		b = append(b, byte(r))
	}
	if !utf8.Valid(b) {
		return s
	}
	if out := string(b); out != s {
		return out
	}
	return s
}

func nonEmptyStrings(xs ...string) []string {
	var out []string
	for _, x := range xs {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}
