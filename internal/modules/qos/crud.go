package qos

import (
	"strconv"

	"github.com/grioghar/flowsight/internal/core"
)

// RULES

func (m *Module) apiGetRules(r *core.Req) (any, error) {
	rules := parseRules(core.Strs(m.ctx.Settings(), "rules"))
	return map[string]any{"rules": rules}, nil
}

func (m *Module) apiCreateRule(r *core.Req) (any, error) {
	var in struct {
		Rule string `json:"rule"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	if in.Rule == "" {
		return nil, core.BadRequest("rule is required")
	}

	// Get current rules and add the new one
	rules := core.Strs(m.ctx.Settings(), "rules")
	rules = append(rules, in.Rule)

	// Save back to settings
	if err := m.ctx.Config.SetModule(m.ctx.Name, map[string]any{"rules": rules}); err != nil {
		return nil, err
	}

	return map[string]any{"ok": true}, nil
}

func (m *Module) apiDeleteRule(r *core.Req) (any, error) {
	id := r.Params["id"]
	if id == "" {
		return nil, core.BadRequest("id is required")
	}

	// The id is the index in the rules list
	idx, err := strconv.Atoi(id)
	if err != nil {
		return nil, core.BadRequest("invalid rule id: not a number")
	}

	rules := core.Strs(m.ctx.Settings(), "rules")
	if idx < 0 || idx >= len(rules) {
		return nil, core.NotFound("no rule at index %d", idx)
	}

	// Remove the rule at index idx
	rules = append(rules[:idx], rules[idx+1:]...)

	// Save back to settings
	if err := m.ctx.Config.SetModule(m.ctx.Name, map[string]any{"rules": rules}); err != nil {
		return nil, err
	}

	return map[string]any{"ok": true}, nil
}
