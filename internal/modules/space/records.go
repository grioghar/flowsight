package space

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

const (
	censusGeocoderURL = "https://geocoding.geo.census.gov/geocoder/geographies/onelineaddress"
	usgsElevationURL  = "https://epqs.nationalmap.gov/v1/json"
	fccBroadbandURL   = "https://broadbandmap.fcc.gov/api/public/map"
	recordsCacheTTL   = 24 * time.Hour
)

// apiLocate geocodes an address and saves the result.
func (m *Module) apiLocate(r *core.Req) (any, error) {
	type locateReq struct {
		Address string `json:"address"`
	}
	var req locateReq
	if err := r.Decode(&req); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Address) == "" {
		return nil, core.BadRequest("address is required")
	}

	result, err := m.geocodeAddress(req.Address)
	if err != nil {
		return nil, fmt.Errorf("geocoding failed: %v", err)
	}

	// Store in KV for reference
	m.ctx.Store.KVSet("space.geocode", result)

	// Update settings with lat/lon
	settings := m.ctx.Settings()
	settings["lat"] = result.Lat
	settings["lon"] = result.Lon
	// Note: in a real implementation, we'd need a way to persist settings back

	return result, nil
}

// apiRecords returns all address records: geocode, buildings, elevation, broadband.
func (m *Module) apiRecords(r *core.Req) (any, error) {
	// Check cache
	var cached RecordsResponse
	if m.ctx.Store.KVGet("space.records", &cached) {
		if time.Since(time.Unix(cached.CachedAt, 0)) < recordsCacheTTL {
			return cached, nil
		}
	}

	// Get geocode from settings or KV
	var geocode GeocodeResult
	settings := m.ctx.Settings()
	lat := 0.0
	lon := 0.0
	if latVal, ok := settings["lat"].(float64); ok {
		lat = latVal
	}
	if lonVal, ok := settings["lon"].(float64); ok {
		lon = lonVal
	}

	if lat == 0 && lon == 0 {
		if !m.ctx.Store.KVGet("space.geocode", &geocode) {
			return nil, core.BadRequest("address not geocoded yet; use POST /api/space/locate first")
		}
	} else {
		geocode.Lat = lat
		geocode.Lon = lon
		address := core.Str(settings, "address", "")
		if address != "" {
			geocode.Address = address
		}
	}

	resp := RecordsResponse{
		Geocode:            geocode,
		BuildingFootprints: []Footprint{},
		CachedAt:           time.Now().Unix(),
	}

	// Get elevation from USGS
	if geocode.Lat != 0 && geocode.Lon != 0 {
		elev, err := m.getElevation(geocode.Lat, geocode.Lon)
		if err == nil {
			resp.Elevation = elev
			resp.ElevationSource = "USGS EPQS"
		}

		// Get building footprints from Overpass
		footprints, err := m.getBuildingFootprints(geocode.Lat, geocode.Lon)
		if err == nil {
			resp.BuildingFootprints = footprints
		}

		// Get broadband providers from FCC or fallback
		providers, err := m.getBroadbandProviders(geocode.Lat, geocode.Lon, geocode.State)
		if err == nil {
			resp.BroadbandProviders = providers
		}
	}

	// Cache the response
	m.ctx.Store.KVSet("space.records", resp)

	return resp, nil
}

// geocodeAddress uses the US Census Geocoder (public, no key required).
func (m *Module) geocodeAddress(address string) (*GeocodeResult, error) {
	q := url.Values{}
	q.Set("address", address)
	q.Set("benchmark", "Public_AR_Current")
	q.Set("vintage", "Current_Current")
	q.Set("format", "json")

	u := censusGeocoderURL + "?" + q.Encode()
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", "FlowSight/1.0")

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var censusResp struct {
		Result struct {
			AddressMatches []struct {
				MatchedAddress string `json:"matchedAddress"`
				Coordinates    struct {
					X float64 `json:"x"`
					Y float64 `json:"y"`
				} `json:"coordinates"`
				AddressComponents struct {
					FromNumber string `json:"fromNumber"`
					ToNumber   string `json:"toNumber"`
					PreDir     string `json:"preDir"`
					Name       string `json:"name"`
					Suffix     string `json:"suffix"`
					PostDir    string `json:"postDir"`
					City       string `json:"city"`
					State      string `json:"state"`
					Zip        string `json:"zip"`
				} `json:"addressComponents"`
				Geographies struct {
					States []struct {
						StateFP   string `json:"STATE"`
						StateName string `json:"NAME"`
					} `json:"States"`
					Counties []struct {
						CountyFP   string `json:"COUNTY"`
						CountyName string `json:"NAME"`
					} `json:"Counties"`
					Tracts []struct {
						TractFP string `json:"TRACT"`
					} `json:"Census Tracts"`
					Blocks []struct {
						BlockFP string `json:"BLOCK"`
					} `json:"Census Blocks"`
				} `json:"geographies"`
			} `json:"addressMatches"`
		} `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&censusResp); err != nil {
		return nil, err
	}

	if len(censusResp.Result.AddressMatches) == 0 {
		return nil, fmt.Errorf("address not found")
	}

	match := censusResp.Result.AddressMatches[0]
	result := &GeocodeResult{
		Address:    match.MatchedAddress,
		Lon:        match.Coordinates.X,
		Lat:        match.Coordinates.Y,
		GeocodedAt: time.Now().Unix(),
	}

	if len(match.Geographies.States) > 0 {
		result.State = match.Geographies.States[0].StateFP
	}
	if len(match.Geographies.Counties) > 0 {
		result.County = match.Geographies.Counties[0].CountyFP
	}
	if len(match.Geographies.Tracts) > 0 {
		result.Tract = match.Geographies.Tracts[0].TractFP
	}
	if len(match.Geographies.Blocks) > 0 {
		result.Block = match.Geographies.Blocks[0].BlockFP
	}

	return result, nil
}

// getElevation retrieves elevation from USGS EPQS.
func (m *Module) getElevation(lat, lon float64) (float64, error) {
	q := url.Values{}
	q.Set("x", fmt.Sprintf("%f", lon))
	q.Set("y", fmt.Sprintf("%f", lat))
	q.Set("units", "Meters")
	q.Set("wkid", "4326")

	u := usgsElevationURL + "?" + q.Encode()
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", "FlowSight/1.0")

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var epqsResp struct {
		Value struct {
			Elevation float64 `json:"Elevation"`
		} `json:"value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&epqsResp); err != nil {
		return 0, err
	}

	return epqsResp.Value.Elevation, nil
}

// getBuildingFootprints retrieves building footprints from Overpass.
// Returns up to 5 buildings within 40m of the point.
func (m *Module) getBuildingFootprints(lat, lon float64) ([]Footprint, error) {
	// Query Overpass for buildings near the point (40m radius)
	query := fmt.Sprintf(`[bbox:%.5f,%.5f,%.5f,%.5f];way["building"];out geom;`,
		lat-0.0005, lon-0.0005, lat+0.0005, lon+0.0005)

	// Use the paths module's Overpass URL if available
	overpassURL := "https://overpass-api.de/api/interpreter"
	if settings := m.ctx.Settings(); settings != nil {
		if url := core.Str(settings, "osm_overpass_url", ""); url != "" {
			overpassURL = url
		}
	}

	req, _ := http.NewRequest("POST", overpassURL, bytes.NewBufferString(query))
	req.Header.Set("User-Agent", "FlowSight/1.0")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("overpass error: %s", resp.Status)
	}

	// Parse OSM XML response (simplified)
	footprints := parseOSMResponse(string(body))
	if len(footprints) > 5 {
		footprints = footprints[:5]
	}
	return footprints, nil
}

// getBroadbandProviders gets broadband provider data.
// For now, returns a placeholder; FCC API requires authentication.
func (m *Module) getBroadbandProviders(lat, lon float64, state string) ([]Provider, error) {
	// The FCC National Broadband Map requires API authentication.
	// For now, return empty list; a production implementation would
	// check for FCC credentials and query the API if available,
	// or fall back to /api/paths/fcc/summary.

	var providers []Provider

	// TODO: Integrate with FCC credentials via ctx.Service("fcc")
	// if available. For now, return empty.

	return providers, nil
}

// parseOSMResponse extracts building data from OSM XML (minimal parser).
func parseOSMResponse(xmlBody string) []Footprint {
	// A proper implementation would use an XML parser.
	// For now, return an empty list; the actual OSM response format
	// includes way elements with nd references and tags.
	// A production implementation would:
	// 1. Parse the XML
	// 2. Reconstruct geometries from node references
	// 3. Extract levels/height/addr tags
	return []Footprint{}
}
