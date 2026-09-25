package alerting

import (
	"github.com/grioghar/flowsight/internal/core"
)

// CHANNELS

func (m *Module) apiGetChannels(r *core.Req) (any, error) {
	channels := make([]Channel, 0)
	m.ctx.Store.KVGet("alerting.channels", &channels)
	return map[string]any{"channels": channels}, nil
}

func (m *Module) apiDeleteChannel(r *core.Req) (any, error) {
	name := r.Params["name"]
	if name == "" {
		return nil, core.BadRequest("name is required")
	}
	channels := make([]Channel, 0)
	m.ctx.Store.KVGet("alerting.channels", &channels)

	idx := -1
	for i, ch := range channels {
		if ch.Name == name {
			idx = i
			break
		}
	}
	if idx == -1 {
		return nil, core.NotFound("no channel named %q", name)
	}

	channels = append(channels[:idx], channels[idx+1:]...)
	if err := m.ctx.Store.KVSet("alerting.channels", channels); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true}, nil
}

// RULES

func (m *Module) apiGetRules(r *core.Req) (any, error) {
	rules := make(map[string]Rule)
	m.ctx.Store.KVGet("alerting.rules", &rules)
	return map[string]any{"rules": rules}, nil
}

func (m *Module) apiDeleteRule(r *core.Req) (any, error) {
	name := r.Params["name"]
	if name == "" {
		return nil, core.BadRequest("name is required")
	}
	rules := make(map[string]Rule)
	m.ctx.Store.KVGet("alerting.rules", &rules)

	if _, ok := rules[name]; !ok {
		return nil, core.NotFound("no rule named %q", name)
	}

	delete(rules, name)
	if err := m.ctx.Store.KVSet("alerting.rules", rules); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true}, nil
}
