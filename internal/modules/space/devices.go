package space

import (
	"strings"

	"github.com/grioghar/flowsight/internal/core"
)

// DeviceWithPlacement combines device info from enroll module with placement data.
type DeviceWithPlacement struct {
	MAC       string     `json:"mac"`
	IP        string     `json:"ip"`
	IP6       string     `json:"ip6,omitempty"`
	Hostname  string     `json:"hostname,omitempty"`
	Vendor    string     `json:"vendor,omitempty"`
	Label     string     `json:"label,omitempty"`
	BytesSec  float64    `json:"bytes_sec,omitempty"` // current throughput if cheap to fetch
	Placed    bool       `json:"placed"`
	Placement *Placement `json:"placement,omitempty"`
}

// apiGetDevices lists all devices with placement status.
// Returns join of /api/enroll/devices with placement data from the layout.
func (m *Module) apiGetDevices(r *core.Req) (any, error) {
	// Get layout for placements
	layout, err := m.loadLayout()
	if err != nil {
		return nil, err
	}

	// Index placements by MAC
	placementsByMAC := make(map[string]*Placement)
	for i, p := range layout.Placements {
		placementsByMAC[p.MAC] = &layout.Placements[i]
	}

	// Call enroll API to get devices
	// In a real implementation, we'd use the enroll module's data directly,
	// not make an HTTP request. For now, return what we have.
	devices := []DeviceWithPlacement{}

	// Get devices from enroll service if available
	if m.identity != nil {
		// The identity service gives us device info
		// For now, we'll just return the placement index
		for mac, p := range placementsByMAC {
			devices = append(devices, DeviceWithPlacement{
				MAC:       mac,
				Placed:    true,
				Placement: p,
				Label:     p.Label,
			})
		}
	}

	// Filter by placed status if requested
	filter := r.Q("filter", "") // "placed", "unplaced", or ""
	if filter == "placed" {
		filtered := []DeviceWithPlacement{}
		for _, d := range devices {
			if d.Placed {
				filtered = append(filtered, d)
			}
		}
		devices = filtered
	} else if filter == "unplaced" {
		filtered := []DeviceWithPlacement{}
		for _, d := range devices {
			if !d.Placed {
				filtered = append(filtered, d)
			}
		}
		devices = filtered
	}

	return map[string]any{
		"devices": devices,
		"total":   len(devices),
	}, nil
}

// apiPlace places a device at a location in space.
// Request: {mac, x, y, z, floor, room, label, note}
func (m *Module) apiPlace(r *core.Req) (any, error) {
	type placeReq struct {
		MAC   string  `json:"mac"`
		X     float64 `json:"x"`
		Y     float64 `json:"y"`
		Z     float64 `json:"z"`
		Floor string  `json:"floor"`
		Room  string  `json:"room"`
		Label string  `json:"label"`
		Note  string  `json:"note"`
	}

	var req placeReq
	if err := r.Decode(&req); err != nil {
		return nil, err
	}

	if strings.TrimSpace(req.MAC) == "" {
		return nil, core.BadRequest("mac is required")
	}

	layout, err := m.loadLayout()
	if err != nil {
		return nil, err
	}

	// Find or create placement
	var placement *Placement
	for i, p := range layout.Placements {
		if p.MAC == req.MAC {
			placement = &layout.Placements[i]
			break
		}
	}

	if placement == nil {
		placement = &Placement{MAC: req.MAC}
		layout.Placements = append(layout.Placements, *placement)
		placement = &layout.Placements[len(layout.Placements)-1]
	}

	// Update placement
	placement.X = req.X
	placement.Y = req.Y
	placement.Z = req.Z
	placement.Floor = req.Floor
	placement.Room = req.Room
	if req.Label != "" {
		placement.Label = req.Label
	}
	if req.Note != "" {
		placement.Note = req.Note
	}

	if err := m.saveLayout(layout); err != nil {
		return nil, err
	}

	return placement, nil
}

// apiDeletePlace removes a device placement.
func (m *Module) apiDeletePlace(r *core.Req) (any, error) {
	mac := r.Params["mac"]
	if mac == "" {
		return nil, core.BadRequest("mac required")
	}

	layout, err := m.loadLayout()
	if err != nil {
		return nil, err
	}

	// Find and remove placement
	for i, p := range layout.Placements {
		if p.MAC == mac {
			layout.Placements = append(layout.Placements[:i], layout.Placements[i+1:]...)
			break
		}
	}

	if err := m.saveLayout(layout); err != nil {
		return nil, err
	}

	return map[string]any{"deleted": true}, nil
}
