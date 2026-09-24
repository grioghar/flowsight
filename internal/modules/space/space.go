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
	ctx.Route("POST", "/api/space/locate", m.apiLocate, core.Write(), core.Doc("Geocode an address using US Census Geocoder"))
	ctx.Route("GET", "/api/space/records", m.apiRecords, core.Doc("Get address records: geocode, buildings, elevation, broadband"))

	// API routes for layout
	ctx.Route("GET", "/api/space/layout", m.apiGetLayout, core.Doc("Get the current space layout"))
	ctx.Route("PUT", "/api/space/layout", m.apiPutLayout, core.Write(), core.Doc("Update the layout"))

	// API routes for scans
	ctx.Route("POST", "/api/space/scan", m.apiPostScan, core.Write(), core.Doc("Upload a scan file (GLB, OBJ, PLY, or RoomPlan JSON)"))
	ctx.Route("GET", "/api/space/scan", m.apiGetScan, core.Doc("Get the uploaded scan file"))
	ctx.Route("DELETE", "/api/space/scan", m.apiDeleteScan, core.Write(), core.Doc("Delete the scan file"))

	// API routes for devices and placements
	ctx.Route("GET", "/api/space/devices", m.apiGetDevices, core.Doc("List all devices with placement status"))
	ctx.Route("POST", "/api/space/place", m.apiPlace, core.Write(), core.Doc("Place a device in space ({mac,x,y,z,floor,room})"))
	ctx.Route("DELETE", "/api/space/place/{mac}", m.apiDeletePlace, core.Write(), core.Doc("Unplace a device"))

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
