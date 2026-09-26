// Package space provides physical space mapping and device placement visualization.
package space

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

// Module implements core.Module for space mapping.
type Module struct {
	ctx      *core.Context
	mu       sync.RWMutex
	identity core.Identity
}

// Layout represents the physical space model.
type Layout struct {
	Floors     []Floor     `json:"floors"`
	Rooms      []Room      `json:"rooms"`
	Placements []Placement `json:"placements"`
	Scan       ScanInfo    `json:"scan,omitempty"`
	Scale      float64     `json:"scale"`  // metres per unit
	Origin     [2]float64  `json:"origin"` // x, y in metres
	UpdatedAt  int64       `json:"updated_at"`
}

// Floor represents a floor in the building.
type Floor struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	ElevationM float64 `json:"elevation_m"`
}

// Room represents a room in the space.
type Room struct {
	ID       string      `json:"id"`
	Name     string      `json:"name"`
	Floor    string      `json:"floor"`
	Polygon  [][]float64 `json:"polygon"` // [[x,y],...] in metres
	CeilingM float64     `json:"ceiling_m"`
}

// Placement represents a device location in space.
type Placement struct {
	MAC   string  `json:"mac"`
	Label string  `json:"label"`
	X     float64 `json:"x"`
	Y     float64 `json:"y"`
	Z     float64 `json:"z"`
	Floor string  `json:"floor"`
	Room  string  `json:"room"`
	Note  string  `json:"note"`
	IP    string  `json:"ip,omitempty"`
}

// ScanInfo describes an uploaded scan file.
type ScanInfo struct {
	File      string    `json:"file"`
	Format    string    `json:"format"` // glb, obj, ply, roomplan
	Transform Transform `json:"transform"`
	UpAxis    string    `json:"up_axis"` // z, y
}

// Transform describes how to position the scan in space.
type Transform struct {
	Scale       float64    `json:"scale"`
	RotationDeg float64    `json:"rotation_deg"`
	Offset      [3]float64 `json:"offset"` // x, y, z in metres
}

// GeocodeResult represents address geocoding.
type GeocodeResult struct {
	Address    string  `json:"address"`
	Lat        float64 `json:"lat"`
	Lon        float64 `json:"lon"`
	State      string  `json:"state"`
	County     string  `json:"county"`
	Tract      string  `json:"tract"`
	Block      string  `json:"block"`
	GeocodedAt int64   `json:"geocoded_at"`
}

// RecordsResponse combines all address-related records.
type RecordsResponse struct {
	Geocode            GeocodeResult `json:"geocode"`
	BuildingFootprints []Footprint   `json:"building_footprints"`
	Elevation          float64       `json:"elevation_m"`
	ElevationSource    string        `json:"elevation_source"`
	BroadbandProviders []Provider    `json:"broadband_providers"`
	CachedAt           int64         `json:"cached_at"`
}

// Footprint is a building footprint from OSM.
type Footprint struct {
	ID      string      `json:"id"`
	Name    string      `json:"name"`
	Levels  string      `json:"levels"`
	Height  string      `json:"height"`
	Polygon [][]float64 `json:"polygon"`
}

// Provider is a broadband provider at the address.
type Provider struct {
	Name       string `json:"name"`
	Technology string `json:"technology"`
	Available  bool   `json:"available"`
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name:        "space",
		Version:     "1.0",
		Tier:        "pro",
		Description: "Physical space mapping: draw your layout, scan your space, place your devices in 3D.",
		After:       []string{"enroll", "identity", "web"},
		Defaults: map[string]any{
			"address":        "",
			"lat":            0.0,
			"lon":            0.0,
			"floor_height_m": 2.6,
			"units":          "metric", // metric or imperial
		},
	}
}

// Setup initializes the module.
func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx

	// Ensure data directories exist
	spaceDir := filepath.Join(ctx.Platform.DataDir, "space")
	if err := os.MkdirAll(spaceDir, 0755); err != nil {
		return err
	}

	// Get identity service for device info
	if svc := ctx.Service("identity"); svc != nil {
		if id, ok := svc.(core.Identity); ok {
			m.identity = id
		}
	}

	// API routes for address records
	ctx.Route("POST", "/api/space/locate", m.apiLocate, core.Write(), core.Doc("Geocode a physical address using US Census Geocoder and save coordinates"),
		core.Body(
			core.Fld("address", "string", true, "Street address to geocode", "1600 Pennsylvania Avenue NW, Washington, DC 20500"),
		),
		core.Returns("Geocoded address with coordinates", map[string]any{
			"address": "1600 Pennsylvania Avenue NW, Washington, DC 20500", "lat": 38.8951, "lon": -77.0369, "state": "DC", "county": "District of Columbia", "tract": "0061", "block": "1000", "geocoded_at": 1790376243,
		}))
	ctx.Route("GET", "/api/space/records", m.apiRecords, core.Doc("Get address records: geocode, buildings, elevation, broadband providers"),
		core.Returns("Combined address records response", map[string]any{
			"geocode":             map[string]any{"address": "1600 Pennsylvania Avenue NW, Washington, DC 20500", "lat": 38.8951, "lon": -77.0369},
			"building_footprints": []map[string]any{{"id": "osm123", "name": "The White House", "levels": "2", "height": "18", "polygon": [][]float64{}}},
			"elevation_m":         20.5, "elevation_source": "USGS EPQS",
			"broadband_providers": []map[string]any{{"name": "Verizon", "technology": "Fiber", "available": true}},
			"cached_at":           1790376243,
		}))

	// API routes for layout
	ctx.Route("GET", "/api/space/layout", m.apiGetLayout, core.Doc("Get the current space layout with floors, rooms, and device placements"),
		core.Returns("Complete space layout definition", map[string]any{
			"floors":     []map[string]any{{"id": "f1", "name": "First Floor", "elevation_m": 0.0}},
			"rooms":      []map[string]any{{"id": "r1", "name": "Office", "floor": "f1", "polygon": [][]float64{}, "ceiling_m": 2.6}},
			"placements": []map[string]any{{"mac": "aa:bb:cc:dd:ee:ff", "label": "AP-Office", "x": 5.0, "y": 3.0, "z": 2.0, "floor": "f1", "room": "r1"}},
			"scale":      1.0, "origin": []float64{0.0, 0.0}, "updated_at": 1790376243,
		}))
	ctx.Route("PUT", "/api/space/layout", m.apiPutLayout, core.Write(), core.Doc("Update the space layout (floors, rooms, placements but not scans)"),
		core.Body(
			core.Fld("floors", "array", false, "Floors in the building", []map[string]any{{"id": "f1", "name": "First Floor", "elevation_m": 0.0}}),
			core.Fld("rooms", "array", false, "Rooms in the space", []map[string]any{{"id": "r1", "name": "Office", "floor": "f1", "polygon": [][]float64{}, "ceiling_m": 2.6}}),
			core.Fld("placements", "array", false, "Device placements in 3D space", []map[string]any{{"mac": "aa:bb:cc:dd:ee:ff", "x": 5.0, "y": 3.0, "z": 2.0}}),
			core.Fld("scale", "number", false, "Metres per unit", 1.0),
			core.Fld("origin", "array", false, "Origin coordinates [x, y] in metres", []float64{0.0, 0.0}),
		),
		core.Returns("Updated layout returned", map[string]any{
			"floors": []map[string]any{}, "rooms": []map[string]any{}, "placements": []map[string]any{}, "scale": 1.0,
		}))

	// API routes for scans
	ctx.Route("POST", "/api/space/scan", m.apiPostScan, core.Write(), core.Doc("Upload a 3D scan file (GLB, OBJ, PLY, or RoomPlan JSON)"),
		core.Query("name", "string", "Custom filename for the uploaded scan", false, "office-scan"),
		core.Returns("Scan uploaded and indexed", map[string]any{
			"file": "scan-20260925-101530-office-scan.glb", "format": "glb", "size": 5242880, "triangles": 125000, "vertices": 65000, "points": 0,
		}))
	ctx.Route("GET", "/api/space/scan", m.apiGetScan, core.Doc("Retrieve the uploaded 3D scan file with correct MIME type"),
		core.Returns("3D scan file binary data", map[string]any{"content_type": "model/gltf-binary"}))
	ctx.Route("DELETE", "/api/space/scan", m.apiDeleteScan, core.Write(), core.Doc("Delete the uploaded 3D scan file from storage"),
		core.Returns("Scan file deleted successfully", map[string]any{"deleted": true}))

	// API routes for devices and placements
	ctx.Route("GET", "/api/space/devices", m.apiGetDevices, core.Doc("List all devices with their current placement status and location"),
		core.Query("filter", "string", "Filter by placement status: 'placed', 'unplaced', or empty for all", false, "placed"),
		core.Returns("Devices with placement information", map[string]any{
			"devices": []map[string]any{
				{"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.10", "hostname": "office-ap", "label": "AP-Office", "placed": true, "placement": map[string]any{"mac": "aa:bb:cc:dd:ee:ff", "x": 5.0, "y": 3.0, "z": 2.0, "floor": "f1", "room": "r1"}},
			},
			"total": 1,
		}))
	ctx.Route("POST", "/api/space/place", m.apiPlace, core.Write(), core.Doc("Place a device in physical space with 3D coordinates and optional room assignment"),
		core.Body(
			core.Fld("mac", "string", true, "MAC address of device to place", "aa:bb:cc:dd:ee:ff"),
			core.Fld("x", "number", true, "X coordinate in metres", 5.0),
			core.Fld("y", "number", true, "Y coordinate in metres", 3.0),
			core.Fld("z", "number", true, "Z coordinate in metres", 2.0),
			core.Fld("floor", "string", false, "Floor ID from layout", "f1"),
			core.Fld("room", "string", false, "Room ID from layout", "r1"),
			core.Fld("label", "string", false, "Display label for the device", "AP-Office"),
			core.Fld("note", "string", false, "Optional notes about placement", "Near window"),
		),
		core.Returns("Device placement saved", map[string]any{
			"mac": "aa:bb:cc:dd:ee:ff", "placed": true, "placement": map[string]any{"mac": "aa:bb:cc:dd:ee:ff", "x": 5.0, "y": 3.0, "z": 2.0},
		}))
	ctx.Route("DELETE", "/api/space/place/{mac}", m.apiDeletePlace, core.Write(), core.Doc("Remove a device from the space and unplace it"),
		core.PathParam("mac", "string", "MAC address of device to unplace", "aa:bb:cc:dd:ee:ff"),
		core.Returns("Device unplaced successfully", map[string]any{"deleted": true}))

	// Panel
	ctx.Panel(core.Panel{ID: "space", Title: "Space", Group: "Inventory", Order: 150, Icon: "space"})

	return nil
}

// Stop shuts down the module.
func (m *Module) Stop() {}

// Health returns module health status.
func (m *Module) Health() core.Health {
	return core.Health{OK: true, Detail: "space module ready"}
}

// spacePath returns the path for a named file in the space data directory.
func (m *Module) spacePath(name string) string {
	return filepath.Join(m.ctx.Platform.DataDir, "space", name)
}

// loadLayout loads the layout from disk or returns an empty one.
func (m *Module) loadLayout() (*Layout, error) {
	layoutPath := m.spacePath("layout.json")
	data, err := os.ReadFile(layoutPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &Layout{
				Floors:     []Floor{},
				Rooms:      []Room{},
				Placements: []Placement{},
				Scale:      1.0,
				Origin:     [2]float64{0, 0},
				UpdatedAt:  time.Now().Unix(),
			}, nil
		}
		return nil, err
	}
	var layout Layout
	if err := json.Unmarshal(data, &layout); err != nil {
		return nil, fmt.Errorf("invalid layout.json: %v", err)
	}
	return &layout, nil
}

// saveLayout saves the layout to disk atomically.
func (m *Module) saveLayout(layout *Layout) error {
	layout.UpdatedAt = time.Now().Unix()
	data, err := json.MarshalIndent(layout, "", "  ")
	if err != nil {
		return err
	}
	layoutPath := m.spacePath("layout.json")
	tmpPath := layoutPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmpPath, layoutPath)
}
