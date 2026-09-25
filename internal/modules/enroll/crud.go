package enroll

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"

	"github.com/grioghar/flowsight/internal/core"
)

// ZONES

func (m *Module) apiGetZoneByID(r *core.Req) (any, error) {
	id := r.Params["id"]
	if id == "" {
		return nil, core.BadRequest("id is required")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, z := range m.zones.Zones {
		if z.ID == id {
			return map[string]any{"zone": z}, nil
		}
	}
	return nil, core.NotFound("no zone with id %q", id)
}

func (m *Module) apiUpdateZoneByID(r *core.Req) (any, error) {
	id := r.Params["id"]
	if id == "" {
		return nil, core.BadRequest("id is required")
	}
	var in struct {
		Zone Zone `json:"zone"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}

	// Validate Subnet6 if provided
	if in.Zone.Subnet6 != "" {
		_, _, err := net.ParseCIDR(in.Zone.Subnet6)
		if err != nil {
			return nil, core.BadRequest("subnet6 must be a valid IPv6 CIDR: %v", err)
		}
	}

	m.mu.Lock()
	idx := -1
	for i, z := range m.zones.Zones {
		if z.ID == id {
			idx = i
			break
		}
	}
	m.mu.Unlock()
	if idx == -1 {
		return nil, core.NotFound("no zone with id %q", id)
	}
	m.mu.Lock()
	in.Zone.ID = id
	m.zones.Zones[idx] = &in.Zone
	doc := m.zones
	m.mu.Unlock()

	// Save to file
	path := filepath.Join(m.ctx.Platform.EtcDir, "zones.json")
	data, _ := json.MarshalIndent(doc, "", "  ")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true}, nil
}

func (m *Module) apiDeleteZoneByID(r *core.Req) (any, error) {
	id := r.Params["id"]
	if id == "" {
		return nil, core.BadRequest("id is required")
	}
	m.mu.Lock()
	idx := -1
	for i, z := range m.zones.Zones {
		if z.ID == id {
			idx = i
			break
		}
	}
	if idx == -1 {
		m.mu.Unlock()
		return nil, core.NotFound("no zone with id %q", id)
	}
	// Check if any devices are assigned to this zone
	for _, d := range m.devices {
		if d.Zone == id {
			m.mu.Unlock()
			return nil, core.BadRequest("zone %q is in use by device %q", id, d.MAC)
		}
	}
	m.zones.Zones = append(m.zones.Zones[:idx], m.zones.Zones[idx+1:]...)
	doc := m.zones
	m.mu.Unlock()

	// Save to file
	path := filepath.Join(m.ctx.Platform.EtcDir, "zones.json")
	data, _ := json.MarshalIndent(doc, "", "  ")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true}, nil
}

// DEVICES

func (m *Module) apiGetDeviceByMAC(r *core.Req) (any, error) {
	mac := r.Params["mac"]
	if mac == "" {
		return nil, core.BadRequest("mac is required")
	}
	m.mu.RLock()
	d, ok := m.devices[mac]
	m.mu.RUnlock()
	if !ok {
		return nil, core.NotFound("no device with MAC %q", mac)
	}
	return map[string]any{"device": d}, nil
}

func (m *Module) apiDeleteDeviceByMAC(r *core.Req) (any, error) {
	mac := r.Params["mac"]
	if mac == "" {
		return nil, core.BadRequest("mac is required")
	}
	m.mu.Lock()
	_, ok := m.devices[mac]
	if !ok {
		m.mu.Unlock()
		return nil, core.NotFound("no device with MAC %q", mac)
	}
	delete(m.devices, mac)
	m.mu.Unlock()
	return map[string]any{"ok": true}, nil
}
