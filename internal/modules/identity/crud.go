package identity

import (
	"net"

	"github.com/grioghar/flowsight/internal/core"
)

// NAME

func (m *Module) apiDeleteNameByIP(r *core.Req) (any, error) {
	ip := r.Params["ip"]
	if ip == "" {
		return nil, core.BadRequest("ip is required")
	}
	if net.ParseIP(ip) == nil {
		return nil, core.BadRequest("ip must be an address")
	}

	m.mu.Lock()
	if _, ok := m.overr[ip]; !ok {
		m.mu.Unlock()
		return nil, core.NotFound("no name override for %q", ip)
	}
	delete(m.overr, ip)
	snapshot := map[string]string{}
	for k, v := range m.overr {
		snapshot[k] = v
	}
	m.mu.Unlock()

	if err := m.ctx.Store.KVSet("identity.names", snapshot); err != nil {
		return nil, err
	}
	_ = m.ctx.Store.UpsertHosts([]core.HostUpdate{{IP: ip, Name: "", Source: "operator"}})
	return map[string]any{"ok": true}, nil
}
