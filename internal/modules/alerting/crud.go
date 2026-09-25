package alerting

import (
	"github.com/grioghar/flowsight/internal/core"
)

// CHANNELS

// apiGetChannels lists all channels
func (m *Module) apiGetChannels(r *core.Req) (any, error) {
	channels := make([]Channel, 0)
	m.ctx.Store.KVGet("alerting.channels", &channels)

	// Mask secrets
	masked := make([]map[string]any, 0)
	for _, c := range channels {
		masked = append(masked, m.maskChannelSecrets(c))
	}

	return map[string]any{"channels": masked}, nil
}

// apiGetChannel gets a specific channel
func (m *Module) apiGetChannel(r *core.Req) (any, error) {
	id := r.Params["id"]
	if id == "" {
		return nil, core.BadRequest("id is required")
	}

	channels := make([]Channel, 0)
	m.ctx.Store.KVGet("alerting.channels", &channels)

	for _, c := range channels {
		if c.Name == id {
			return map[string]any{"channel": m.maskChannelSecrets(c)}, nil
		}
	}

	return nil, core.NotFound("channel not found")
}

// apiCreateChannel creates a new channel
func (m *Module) apiCreateChannel(r *core.Req) (any, error) {
	var reqBody struct {
		Name    string            `json:"name"`
		Type    string            `json:"type"`
		Enabled bool              `json:"enabled"`
		Config  map[string]string `json:"config"`
	}

	if err := r.Decode(&reqBody); err != nil {
		return nil, err
	}

	if reqBody.Name == "" {
		return nil, core.BadRequest("name is required")
	}
	if reqBody.Type == "" {
		return nil, core.BadRequest("type is required")
	}

	// Get the channel type and validate config
	ct, err := Get(reqBody.Type)
	if err != nil {
		return nil, core.BadRequest("unknown channel type: %s", reqBody.Type)
	}

	if err := ct.Validate(reqBody.Config); err != nil {
		return nil, core.BadRequest("invalid config: %v", err)
	}

	// Check if channel already exists
	channels := make([]Channel, 0)
	m.ctx.Store.KVGet("alerting.channels", &channels)

	for _, c := range channels {
		if c.Name == reqBody.Name {
			return nil, core.BadRequest("channel %q already exists", reqBody.Name)
		}
	}

	// Create new channel
	newChannel := Channel{
		Name:    reqBody.Name,
		Type:    reqBody.Type,
		Enabled: reqBody.Enabled,
		Config:  reqBody.Config,
	}

	channels = append(channels, newChannel)
	if err := m.ctx.Store.KVSet("alerting.channels", channels); err != nil {
		return nil, err
	}

	return map[string]any{"channel": m.maskChannelSecrets(newChannel)}, nil
}

// apiUpdateChannel updates an existing channel
func (m *Module) apiUpdateChannel(r *core.Req) (any, error) {
	id := r.Params["id"]
	if id == "" {
		return nil, core.BadRequest("id is required")
	}

	var reqBody struct {
		Name    string            `json:"name"`
		Type    string            `json:"type"`
		Enabled bool              `json:"enabled"`
		Config  map[string]string `json:"config"`
	}

	if err := r.Decode(&reqBody); err != nil {
		return nil, err
	}

	channels := make([]Channel, 0)
	m.ctx.Store.KVGet("alerting.channels", &channels)

	idx := -1
	for i, c := range channels {
		if c.Name == id {
			idx = i
			break
		}
	}

	if idx == -1 {
		return nil, core.NotFound("channel not found")
	}

	// Get the channel type and validate config
	ct, err := Get(reqBody.Type)
	if err != nil {
		return nil, core.BadRequest("unknown channel type: %s", reqBody.Type)
	}

	if err := ct.Validate(reqBody.Config); err != nil {
		return nil, core.BadRequest("invalid config: %v", err)
	}

	// Update channel
	channels[idx] = Channel{
		Name:    reqBody.Name,
		Type:    reqBody.Type,
		Enabled: reqBody.Enabled,
		Config:  reqBody.Config,
	}

	if err := m.ctx.Store.KVSet("alerting.channels", channels); err != nil {
		return nil, err
	}

	return map[string]any{"channel": m.maskChannelSecrets(channels[idx])}, nil
}

// apiDeleteChannel deletes a channel
func (m *Module) apiDeleteChannel(r *core.Req) (any, error) {
	id := r.Params["id"]
	if id == "" {
		return nil, core.BadRequest("id is required")
	}

	channels := make([]Channel, 0)
	m.ctx.Store.KVGet("alerting.channels", &channels)

	idx := -1
	for i, c := range channels {
		if c.Name == id {
			idx = i
			break
		}
	}

	if idx == -1 {
		return nil, core.NotFound("channel not found")
	}

	channels = append(channels[:idx], channels[idx+1:]...)
	if err := m.ctx.Store.KVSet("alerting.channels", channels); err != nil {
		return nil, err
	}

	return map[string]any{"ok": true}, nil
}

// apiTestChannel sends a test message to a channel
func (m *Module) apiTestChannel(r *core.Req) (any, error) {
	id := r.Params["id"]
	if id == "" {
		return nil, core.BadRequest("id is required")
	}

	channels := make([]Channel, 0)
	m.ctx.Store.KVGet("alerting.channels", &channels)

	var channel *Channel
	for i := range channels {
		if channels[i].Name == id {
			channel = &channels[i]
			break
		}
	}

	if channel == nil {
		return nil, core.NotFound("channel not found")
	}

	ct, err := Get(channel.Type)
	if err != nil {
		return nil, core.Errorf(400, "unknown channel type: %s", channel.Type)
	}

	latency, err := ct.Test(r.Context(), channel)
	if err != nil {
		return nil, core.Errorf(500, "test failed: %v", err)
	}

	return map[string]any{"ok": true, "latency_ms": latency}, nil
}

// RULES

// apiGetRules lists all rules
func (m *Module) apiGetRules(r *core.Req) (any, error) {
	rules := make(map[string]RuleConfig)
	m.ctx.Store.KVGet("alerting.rules", &rules)
	// A record with no id or name is a leftover of a malformed save; it is
	// not a rule and is not shown (or kept).
	dirty := false
	for id, rule := range rules {
		if id == "" || rule.ID == "" || rule.Name == "" {
			delete(rules, id)
			dirty = true
		}
	}
	if dirty {
		_ = m.ctx.Store.KVSet("alerting.rules", rules)
	}
	return map[string]any{"rules": rules}, nil
}

// apiGetRule gets a specific rule
func (m *Module) apiGetRule(r *core.Req) (any, error) {
	id := r.Params["id"]
	if id == "" {
		return nil, core.BadRequest("id is required")
	}

	rules := make(map[string]RuleConfig)
	m.ctx.Store.KVGet("alerting.rules", &rules)

	if rule, ok := rules[id]; ok {
		return map[string]any{"rule": rule}, nil
	}

	return nil, core.NotFound("rule not found")
}

// apiCreateRule creates a new rule
func (m *Module) apiCreateRule(r *core.Req) (any, error) {
	var rule RuleConfig
	if err := r.Decode(&rule); err != nil {
		return nil, err
	}

	if rule.ID == "" {
		return nil, core.BadRequest("id is required")
	}

	rules := make(map[string]RuleConfig)
	m.ctx.Store.KVGet("alerting.rules", &rules)

	if _, exists := rules[rule.ID]; exists {
		return nil, core.BadRequest("rule %q already exists", rule.ID)
	}

	rules[rule.ID] = rule
	if err := m.ctx.Store.KVSet("alerting.rules", rules); err != nil {
		return nil, err
	}

	return map[string]any{"rule": rule}, nil
}

// apiUpdateRule updates an existing rule
func (m *Module) apiUpdateRule(r *core.Req) (any, error) {
	id := r.Params["id"]
	if id == "" {
		return nil, core.BadRequest("id is required")
	}

	var rule RuleConfig
	if err := r.Decode(&rule); err != nil {
		return nil, err
	}
	if rule.Name == "" {
		return nil, core.BadRequest("a rule needs a name")
	}

	rules := make(map[string]RuleConfig)
	m.ctx.Store.KVGet("alerting.rules", &rules)

	if _, exists := rules[id]; !exists {
		return nil, core.NotFound("rule not found")
	}

	rule.ID = id
	rules[id] = rule
	if err := m.ctx.Store.KVSet("alerting.rules", rules); err != nil {
		return nil, err
	}

	return map[string]any{"rule": rule}, nil
}

// apiDeleteRule deletes a rule
func (m *Module) apiDeleteRule(r *core.Req) (any, error) {
	id := r.Params["id"]
	if id == "" {
		return nil, core.BadRequest("id is required")
	}

	rules := make(map[string]RuleConfig)
	m.ctx.Store.KVGet("alerting.rules", &rules)

	if _, exists := rules[id]; !exists {
		return nil, core.NotFound("rule not found")
	}

	delete(rules, id)
	if err := m.ctx.Store.KVSet("alerting.rules", rules); err != nil {
		return nil, err
	}

	return map[string]any{"ok": true}, nil
}
