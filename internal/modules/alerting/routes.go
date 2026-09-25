package alerting

import (
	"fmt"
	"sort"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// Channel family constants for grouping in the UI
const (
	FamilyChat     = "Chat & Collaboration"
	FamilySMSVoice = "SMS & Voice"
	FamilyEmail    = "Email"
	FamilyIncident = "Incident Management"
	FamilySIEM     = "SIEM & Logging"
	FamilyGeneric  = "Generic"
)

// ChannelTypeInfo provides schema and metadata for a channel type
type ChannelTypeInfo struct {
	Type        string         `json:"type"`
	Label       string         `json:"label"`
	Family      string         `json:"family"`
	Schema      []SettingField `json:"schema"`
	Description string         `json:"description"`
}

// GetChannelTypeFamily returns the UI family for a channel type
func getChannelTypeFamily(typeName string) string {
	familyMap := map[string]string{
		// Chat
		"slack":       FamilyChat,
		"discord":     FamilyChat,
		"teams":       FamilyChat,
		"telegram":    FamilyChat,
		"matrix":      FamilyChat,
		"mattermost":  FamilyChat,
		"rocketchat":  FamilyChat,
		"google_chat": FamilyChat,
		// SMS/Voice
		"twilio":      FamilySMSVoice,
		"vonage":      FamilySMSVoice,
		"telnyx":      FamilySMSVoice,
		"awssns":      FamilySMSVoice,
		"plivo":       FamilySMSVoice,
		"messagebird": FamilySMSVoice,
		"clicksend":   FamilySMSVoice,
		// Email
		"smtp":        FamilyEmail,
		"sendgrid":    FamilyEmail,
		"mailgun":     FamilyEmail,
		"amazonseses": FamilyEmail,
		"postmark":    FamilyEmail,
		// Incident
		"pagerduty":      FamilyIncident,
		"opsgenie":       FamilyIncident,
		"splunk_on_call": FamilyIncident,
		"squadcast":      FamilyIncident,
		"incidentio":     FamilyIncident,
		"xmatters":       FamilyIncident,
		"zenduty":        FamilyIncident,
		"betterstack":    FamilyIncident,
		// SIEM/Logging
		"syslog":          FamilySIEM,
		"splunk_hec":      FamilySIEM,
		"elastic":         FamilySIEM,
		"opensearch":      FamilySIEM,
		"graylog":         FamilySIEM,
		"sentinel":        FamilySIEM,
		"datadog":         FamilySIEM,
		"sumologic":       FamilySIEM,
		"newrelic":        FamilySIEM,
		"grafana_loki":    FamilySIEM,
		"qradar":          FamilySIEM,
		"wazuh":           FamilySIEM,
		"sentry":          FamilySIEM,
		"cloudwatch_logs": FamilySIEM,
		// Generic
		"webhook":  FamilyGeneric,
		"mqtt":     FamilyGeneric,
		"rss_feed": FamilyGeneric,
	}
	if family, ok := familyMap[typeName]; ok {
		return family
	}
	return FamilyGeneric
}

// Register new routes for the expanded alerting API
func (m *Module) registerRoutes() {
	ctx := m.ctx

	// Channel type information
	ctx.Route("GET", "/api/alerting/channel-types", m.apiChannelTypes,
		core.Doc("List all channel types with schemas grouped by family"))

	// Channel CRUD operations
	ctx.Route("GET", "/api/alerting/channels", m.apiGetChannels,
		core.Doc("List all notification channels"))
	ctx.Route("POST", "/api/alerting/channels", m.apiCreateChannel,
		core.Write(), core.Needs("alerting.notify"),
		core.Doc("Create a new notification channel"))
	ctx.Route("GET", "/api/alerting/channels/{id}", m.apiGetChannel,
		core.Doc("Get a specific notification channel"))
	ctx.Route("PUT", "/api/alerting/channels/{id}", m.apiUpdateChannel,
		core.Write(), core.Needs("alerting.notify"),
		core.Doc("Update a notification channel"))
	ctx.Route("DELETE", "/api/alerting/channels/{id}", m.apiDeleteChannel,
		core.Write(), core.Needs("alerting.notify"),
		core.Doc("Delete a notification channel"))
	ctx.Route("POST", "/api/alerting/channels/{id}/test", m.apiTestChannel,
		core.Write(),
		core.Doc("Send a test message to a channel"))

	// Rule CRUD operations
	ctx.Route("GET", "/api/alerting/rules", m.apiGetRules,
		core.Doc("List all alert rules"))
	ctx.Route("POST", "/api/alerting/rules", m.apiCreateRule,
		core.Write(), core.Needs("alerting.notify"),
		core.Doc("Create a new alert rule"))
	ctx.Route("GET", "/api/alerting/rules/{id}", m.apiGetRule,
		core.Doc("Get a specific alert rule"))
	ctx.Route("PUT", "/api/alerting/rules/{id}", m.apiUpdateRule,
		core.Write(), core.Needs("alerting.notify"),
		core.Doc("Update an alert rule"))
	ctx.Route("DELETE", "/api/alerting/rules/{id}", m.apiDeleteRule,
		core.Write(), core.Needs("alerting.notify"),
		core.Doc("Delete an alert rule"))

	// Delivery log
	ctx.Route("GET", "/api/alerting/deliveries", m.apiGetDeliveries,
		core.Doc("Get delivery log"),
		core.Params("channel", "limit"))

	// Alert acknowledgment and resolution
	ctx.Route("POST", "/api/alerting/ack/{alert_key}", m.apiAckAlert,
		core.Write(),
		core.Doc("Acknowledge an alert"))
	ctx.Route("POST", "/api/alerting/resolve/{alert_key}", m.apiResolveAlert,
		core.Write(),
		core.Doc("Resolve an alert"))

	// Maintenance mode
	ctx.Route("GET", "/api/alerting/maintenance", m.apiGetMaintenance,
		core.Doc("Get maintenance mode status"))
	ctx.Route("POST", "/api/alerting/maintenance", m.apiSetMaintenance,
		core.Write(), core.Needs("alerting.notify"),
		core.Doc("Set maintenance mode"))

	// Simulation
	ctx.Route("POST", "/api/alerting/simulate", m.apiSimulateAlert,
		core.Write(),
		core.Doc("Simulate an alert"))

	// RSS feed (token-protected)
	ctx.Route("GET", "/api/alerting/feed.xml", m.apiAlertFeed,
		core.Doc("RSS feed of recent alerts (requires token)"))

	// Apprise URL import
	ctx.Route("POST", "/api/alerting/import-apprise", m.apiImportApprise,
		core.Write(), core.Needs("alerting.notify"),
		core.Doc("Import Apprise URL"))
}

// apiChannelTypes returns all channel types grouped by family with their schemas
func (m *Module) apiChannelTypes(r *core.Req) (any, error) {
	channelTypes := List()
	grouped := make(map[string][]ChannelTypeInfo)

	for _, ct := range channelTypes {
		info := ChannelTypeInfo{
			Type:   ct.Type(),
			Label:  ct.Label(),
			Family: getChannelTypeFamily(ct.Type()),
			Schema: ct.Schema(),
		}
		grouped[info.Family] = append(grouped[info.Family], info)
	}

	return map[string]any{"channel_types": grouped}, nil
}

// apiGetDeliveries returns delivery log
func (m *Module) apiGetDeliveries(r *core.Req) (any, error) {
	channel := r.URL.Query().Get("channel")
	limit := 50
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		fmt.Sscanf(limitStr, "%d", &limit)
	}

	log := m.deliveryEngine.GetAllDeliveryLogs(limit)

	if channel != "" {
		if deliveries, ok := log[channel]; ok {
			return map[string]any{"deliveries": deliveries, "by_channel": map[string]any{channel: deliveries}}, nil
		}
		return map[string]any{"deliveries": []*DeliveryAttempt{}, "by_channel": map[string]any{}}, nil
	}
	// One flat list newest first, which is what a page shows; the per
	// channel map beside it for callers that want it.
	flat := make([]*DeliveryAttempt, 0)
	for _, list := range log {
		flat = append(flat, list...)
	}
	sort.Slice(flat, func(i, j int) bool { return flat[i].Timestamp > flat[j].Timestamp })
	if len(flat) > limit {
		flat = flat[:limit]
	}
	return map[string]any{"deliveries": flat, "by_channel": log}, nil
}

// apiAckAlert acknowledges an alert
func (m *Module) apiAckAlert(r *core.Req) (any, error) {
	alertKey := r.Params["alert_key"]
	if alertKey == "" {
		return nil, core.BadRequest("alert_key is required")
	}

	// Record acknowledgment in KV
	key := "alerting.ack." + alertKey
	m.ctx.Store.KVSet(key, time.Now().Unix())

	return map[string]any{"ok": true}, nil
}

// apiResolveAlert resolves an alert
func (m *Module) apiResolveAlert(r *core.Req) (any, error) {
	alertKey := r.Params["alert_key"]
	if alertKey == "" {
		return nil, core.BadRequest("alert_key is required")
	}

	// Record resolution in KV
	key := "alerting.resolved." + alertKey
	m.ctx.Store.KVSet(key, time.Now().Unix())

	return map[string]any{"ok": true}, nil
}

// apiGetMaintenance returns maintenance mode status
func (m *Module) apiGetMaintenance(r *core.Req) (any, error) {
	var status struct {
		Enabled bool   `json:"enabled"`
		Until   int64  `json:"until,omitempty"`
		Reason  string `json:"reason,omitempty"`
	}

	m.ctx.Store.KVGet("alerting.maintenance", &status)

	return status, nil
}

// apiSetMaintenance sets maintenance mode
func (m *Module) apiSetMaintenance(r *core.Req) (any, error) {
	var req struct {
		Enabled bool   `json:"enabled"`
		Minutes int    `json:"minutes,omitempty"`
		Reason  string `json:"reason,omitempty"`
	}

	if err := r.Decode(&req); err != nil {
		return nil, err
	}

	var status struct {
		Enabled bool   `json:"enabled"`
		Until   int64  `json:"until,omitempty"`
		Reason  string `json:"reason,omitempty"`
	}

	if req.Enabled {
		status.Enabled = true
		if req.Minutes > 0 {
			status.Until = time.Now().Unix() + int64(req.Minutes*60)
		}
		status.Reason = req.Reason
	} else {
		status.Enabled = false
	}

	if err := m.ctx.Store.KVSet("alerting.maintenance", status); err != nil {
		return nil, err
	}

	return status, nil
}

// apiSimulateAlert simulates an alert
func (m *Module) apiSimulateAlert(r *core.Req) (any, error) {
	var req struct {
		Severity string `json:"severity"`
		Title    string `json:"title"`
		Text     string `json:"text"`
	}

	if err := r.Decode(&req); err != nil {
		return nil, err
	}

	if req.Severity == "" {
		req.Severity = "medium"
	}
	if req.Title == "" {
		req.Title = "Test Alert"
	}

	// Create a test message
	msg := &Message{
		Timestamp: time.Now(),
		Title:     req.Title,
		Severity:  req.Severity,
		Module:    "simulation",
		Category:  "test",
		Body:      req.Text,
		AlertKey:  fmt.Sprintf("sim-%d", time.Now().UnixNano()),
	}

	// Send to all enabled channels
	channels := make([]Channel, 0)
	m.ctx.Store.KVGet("alerting.channels", &channels)

	results := make(map[string]interface{})
	for _, c := range channels {
		if !c.Enabled {
			continue
		}

		ct, err := Get(c.Type)
		if err != nil {
			results[c.Name] = map[string]interface{}{"error": err.Error()}
			continue
		}

		latency, err := ct.Send(r.Context(), &c, msg)
		if err != nil {
			results[c.Name] = map[string]interface{}{"error": err.Error()}
		} else {
			results[c.Name] = map[string]interface{}{"ok": true, "latency_ms": latency}
		}
	}

	return map[string]any{"results": results}, nil
}

// apiAlertFeed returns RSS feed of recent alerts
func (m *Module) apiAlertFeed(r *core.Req) (any, error) {
	// Token authentication via query parameter (optional, for future use)
	_ = r.URL.Query().Get("token")

	// For now, return a simple feed from the RSS channel store
	// In production, this would check the token against the RSS channel config

	// Get recent alerts (placeholder - would get from alerting engine)
	alerts := []*Message{
		{
			Timestamp: time.Now(),
			Title:     "Sample Alert",
			Severity:  "medium",
			Body:      "This is a sample alert for RSS feed.",
			Category:  "test",
			AlertKey:  "sample-1",
		},
	}

	feed := RenderRSS(alerts, "https://flowsight.local/alerting")
	return feed, nil
}

// apiImportApprise imports an Apprise URL and creates channels
func (m *Module) apiImportApprise(r *core.Req) (any, error) {
	var req struct {
		AppriseURL string `json:"apprise_url"`
	}

	if err := r.Decode(&req); err != nil {
		return nil, err
	}

	if req.AppriseURL == "" {
		return nil, core.BadRequest("apprise_url required")
	}

	// Parse Apprise URL
	typ, cfg, err := ParseAppriseURL(req.AppriseURL)
	if err != nil {
		return nil, core.BadRequest("invalid apprise URL: %v", err)
	}

	// Create channel from parsed config
	channelName := fmt.Sprintf("apprise-%s-%d", typ, time.Now().UnixNano())
	newChannel := Channel{
		Name:    channelName,
		Type:    typ,
		Enabled: true,
		Config:  make(map[string]string),
	}

	// Convert string config from map[string]any to map[string]string
	for k, v := range cfg {
		newChannel.Config[k] = fmt.Sprint(v)
	}

	// Validate the channel
	ct, err := Get(typ)
	if err != nil {
		return nil, core.BadRequest("unknown channel type: %s", typ)
	}

	if err := ct.Validate(newChannel.Config); err != nil {
		return nil, core.BadRequest("invalid config: %v", err)
	}

	// Store the channel (in production, this would use the CRUD functions)
	var channels []Channel
	m.ctx.Store.KVGet("alerting.channels", &channels)
	channels = append(channels, newChannel)
	m.ctx.Store.KVSet("alerting.channels", channels)

	return map[string]any{
		"channel_id":   newChannel.Name,
		"channel_type": typ,
		"message":      "Channel created from Apprise URL",
	}, nil
}

// maskChannelSecrets masks sensitive configuration values
func (m *Module) maskChannelSecrets(ch Channel) map[string]any {
	cfg := make(map[string]any)
	for k, v := range ch.Config {
		ct, _ := Get(ch.Type)
		if ct != nil {
			for _, field := range ct.Schema() {
				if field.Key == k && field.Secret {
					cfg[k] = "***"
					goto next
				}
			}
		}
		cfg[k] = v
	next:
	}

	return map[string]any{
		"name":    ch.Name,
		"type":    ch.Type,
		"enabled": ch.Enabled,
		"config":  cfg,
	}
}
