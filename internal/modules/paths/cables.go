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
	m.cables, m.cableErr = cables, ""
	m.mu.Unlock()
	return nil
}

func (m *Module) downloadCables(path string) error {
	url := strings.TrimSpace(core.Str(m.ctx.Settings(), "cables_url", ""))
	if url == "" {
		url = defaultCableURL
	}
	// Generous overall, tight on the parts that hang: the same shape the
	// updater uses, after a thirty-second overall limit once failed a
	// fourteen-megabyte download on an ordinary connection.
	client := &http.Client{Timeout: 10 * time.Minute}
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
		r = gz
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
			ID   string `json:"id"`
			Name string `json:"name"`
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
	for _, f := range doc.Features {
		if f.Geometry.Type != "MultiLineString" {
			continue
		}
		var runs [][][2]float64
		if err := json.Unmarshal(f.Geometry.Coordinates, &runs); err != nil {
			continue
		}
		c := byID[f.Properties.ID]
		if c == nil {
			c = &Cable{ID: f.Properties.ID, Name: f.Properties.Name}
			byID[f.Properties.ID] = c
		}
		for _, run := range runs {
			if len(run) < 2 {
				continue
			}
			pts := make([]LatLon, 0, len(run))
			for _, p := range run {
				pts = append(pts, LatLon{Lat: p[1], Lon: p[0]}) // GeoJSON is lon,lat
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
