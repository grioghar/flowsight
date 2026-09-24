package web

import (
	"github.com/grioghar/flowsight/internal/core"
)

// PINNED NAMES

func (m *Module) apiDeletePinnedName(r *core.Req) (any, error) {
	name := r.Params["name"]
	if name == "" {
		return nil, core.BadRequest("name is required")
	}

	if m.pin == nil {
		return nil, core.BadRequest("pinning is not enabled")
	}

	m.pin.mu.Lock()
	if _, ok := m.pin.entries[name]; !ok {
		m.pin.mu.Unlock()
		return nil, core.NotFound("no pinned name %q", name)
	}
	delete(m.pin.entries, name)
	m.pin.dirty = true
	m.pin.mu.Unlock()

	m.savePinned()
	return map[string]any{"ok": true}, nil
}
