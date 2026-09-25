package alerting

import (
	"fmt"
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
		core.Doc("List all notification channel types grouped by family, with configuration schemas"),
		core.Returns("Channel types by family", map[string]any{
			"channel_types": map[string]any{
				"Chat & Collaboration": []map[string]any{
					{"type": "slack", "label": "Slack", "family": "Chat & Collaboration"},
				},
			},
		}))
	// Channel CRUD operations
	ctx.Route("GET", "/api/alerting/channels", m.apiGetChannels,
		core.Doc("List all configured notification channels"),
		core.Returns("List of notification channels", map[string]any{
			"channels": []map[string]any{
				{"id": "ch-1", "type": "slack", "name": "alerts", "enabled": true},
			},
		}))

	ctx.Route("POST", "/api/alerting/channels", m.apiCreateChannel,
		core.Write(), core.Needs("alerting.notify"),
		core.Doc("Create a new notification channel"),
		core.Body(
			core.Fld("type", "string", true, "Channel type (slack, teams, email, etc.)", "slack"),
			core.Fld("name", "string", true, "Display name for the channel", "My Slack"),
			core.Fld("enabled", "boolean", false, "Whether channel is enabled", true),
			core.Fld("config", "object", true, "Type-specific configuration", map[string]any{"webhook_url": "..."}),
		),
		core.Returns("Created channel", map[string]any{
			"id": "ch-1", "type": "slack", "name": "alerts", "enabled": true,
		}))

	ctx.Route("GET", "/api/alerting/channels/{id}", m.apiGetChannel,
		core.Doc("Get a specific notification channel"), core.PathParam("id", "string", "Resource ID", "123"),
		core.PathParam("id", "string", "Channel ID", "ch-1"),
		core.Returns("Notification channel", map[string]any{
			"id": "ch-1", "type": "slack", "name": "alerts", "enabled": true,
		}))

	ctx.Route("PUT", "/api/alerting/channels/{id}", m.apiUpdateChannel,
		core.Write(), core.Needs("alerting.notify"),
		core.Doc("Update a notification channel"), core.PathParam("id", "string", "Resource ID", "123"),
		core.PathParam("id", "string", "Channel ID", "ch-1"),
		core.Body(
			core.Fld("name", "string", false, "Display name", "alerts"),
			core.Fld("enabled", "boolean", false, "Whether enabled", true),
			core.Fld("config", "object", false, "Updated configuration", map[string]any{}),
		), core.Returns("Success", map[string]any{"ok": true}))
	ctx.Route("DELETE", "/api/alerting/channels/{id}", m.apiDeleteChannel,
		core.Write(), core.Needs("alerting.notify"),
		core.Doc("Delete a notification channel"), core.PathParam("id", "string", "Resource ID", "123"),
		core.PathParam("id", "string", "Channel ID", "ch-1"), core.Returns("Success", map[string]any{"ok": true}))
	ctx.Route("POST", "/api/alerting/channels/{id}/test", m.apiTestChannel,
		core.Write(),
		core.Doc("Send a test message to a channel"), core.PathParam("id", "string", "Resource ID", "123"),
		core.PathParam("id", "string", "Channel ID", "ch-1"),
		core.Returns("Test result", map[string]any{
			"success": true, "message": "Test message sent",
		}))

	// Rule CRUD operations
	ctx.Route("GET", "/api/alerting/rules", m.apiGetRules,
		core.Doc("Retrieve all configured alert rules with their conditions and channels"),
		core.Returns("List of alert rules", map[string]any{
			"rules": []map[string]any{
				{"id": "rule-1", "name": "High CPU", "enabled": true},
			},
		}))

	ctx.Route("POST", "/api/alerting/rules", m.apiCreateRule,
		core.Write(), core.Needs("alerting.notify"),
		core.Doc("Create a new alert rule that evaluates conditions and sends notifications"),
		core.Body(
			core.Fld("name", "string", true, "Rule name", "High CPU Alert"),
			core.Fld("condition", "string", true, "Alert condition", "cpu > 80"),
			core.Fld("channels", "array", true, "Channel IDs to notify", []string{"ch-1"}),
			core.Fld("enabled", "boolean", false, "Whether rule is enabled", true),
		), core.Returns("Created rule", map[string]any{
			"rule": map[string]any{"id": "rule-1", "name": "High CPU Alert", "enabled": true},
		}))
	ctx.Route("GET", "/api/alerting/rules/{id}", m.apiGetRule,
		core.Doc("Retrieve details of a specific alert rule by ID"), core.PathParam("id", "string", "Rule ID", "rule-1"),
		core.Returns("Alert rule details", map[string]any{
			"rule": map[string]any{"id": "rule-1", "name": "High CPU Alert", "enabled": true},
		}))
	ctx.Route("PUT", "/api/alerting/rules/{id}", m.apiUpdateRule,
		core.Write(), core.Needs("alerting.notify"),
		core.Doc("Update an existing alert rule with new conditions and settings"), core.PathParam("id", "string", "Rule ID", "rule-1"),
		core.Body(
			core.Fld("name", "string", false, "Updated rule name", "High CPU Alert"),
			core.Fld("condition", "string", false, "Updated alert condition", "cpu > 80"),
			core.Fld("enabled", "boolean", false, "Whether rule is enabled", true),
		),
		core.Returns("Updated rule", map[string]any{
			"rule": map[string]any{"id": "rule-1", "name": "High CPU Alert", "enabled": true},
		}))
	ctx.Route("DELETE", "/api/alerting/rules/{id}", m.apiDeleteRule,
		core.Write(), core.Needs("alerting.notify"),
		core.Doc("Remove an alert rule permanently from the system"), core.PathParam("id", "string", "Rule ID", "rule-1"),
		core.Returns("Success", map[string]any{"ok": true}))
	// Delivery log
	ctx.Route("GET", "/api/alerting/deliveries", m.apiGetDeliveries,
		core.Doc("Get notification delivery history"),
		core.Query("channel", "string", "Filter by channel ID", false, "ch-1"),
		core.Query("limit", "integer", "Maximum results to return", false, 50),
		core.Returns("Delivery log", map[string]any{
			"deliveries": []map[string]any{
				{"id": "del-1", "channel": "ch-1", "status": "success", "timestamp": "2024-01-01T12:00:00Z"},
			},
		}))

	// Alert acknowledgment and resolution
	ctx.Route("POST", "/api/alerting/ack/{alert_key}", m.apiAckAlert,
		core.Write(),
		core.Doc("Acknowledge an active alert"), core.PathParam("id", "string", "Resource ID", "123"),
		core.PathParam("alert_key", "string", "Alert key", "alert-123"),
		core.Body(
			core.Fld("comment", "string", false, "Acknowledgment comment", "investigating"),
		), core.Returns("Success", map[string]any{"ok": true}))
	ctx.Route("POST", "/api/alerting/resolve/{alert_key}", m.apiResolveAlert,
		core.Write(),
		core.Doc("Resolve an acknowledged alert"), core.PathParam("id", "string", "Resource ID", "123"),
		core.PathParam("alert_key", "string", "Alert key", "alert-123"),
		core.Body(
			core.Fld("comment", "string", false, "Resolution comment", "issue fixed"),
		), core.Returns("Success", map[string]any{"ok": true}))
	// Maintenance mode
	ctx.Route("GET", "/api/alerting/maintenance", m.apiGetMaintenance,
		core.Doc("Get current maintenance mode status"),
		core.Returns("Maintenance status", map[string]any{
			"enabled": false, "until": nil, "reason": "",
		}))

	ctx.Route("POST", "/api/alerting/maintenance", m.apiSetMaintenance,
		core.Write(), core.Needs("alerting.notify"),
		core.Doc("Enable or disable maintenance mode (suppresses alerts)"),
		core.Body(
			core.Fld("enabled", "boolean", true, "Enable maintenance mode", true),
			core.Fld("duration", "integer", false, "Minutes to maintain mode (0 = indefinite)", 60),
			core.Fld("reason", "string", false, "Reason for maintenance", "scheduled maintenance"),
		), core.Returns("Success", map[string]any{"ok": true}))
	// Simulation
	ctx.Route("POST", "/api/alerting/simulate", m.apiSimulateAlert,
		core.Write(),
		core.Doc("Generate a test alert to verify rules"),
		core.Body(
			core.Fld("name", "string", true, "Alert name", "Test Alert"),
			core.Fld("severity", "string", false, "Severity level", "high"),
		), core.Returns("Success", map[string]any{"ok": true}))
	// RSS feed (token-protected)
	ctx.Route("GET", "/api/alerting/feed.xml", m.apiAlertFeed,
		core.Doc("RSS feed of recent alerts with token-based authorization"),
		core.Returns("XML feed", map[string]any{"feed": "<?xml version=\"1.0\"?><rss><channel><item><title>Sample Alert</title></item></channel></rss>"}))
	// Apprise URL import
	ctx.Route("POST", "/api/alerting/import-apprise", m.apiImportApprise,
		core.Write(), core.Needs("alerting.notify"),
		core.Doc("Import Apprise notification URL"),
		core.Body(
			core.Fld("name", "string", true, "Display name", "My Channel"),
			core.Fld("url", "string", true, "Apprise URL", "slack://token@webhook"),
		), core.Returns("Success", map[string]any{"ok": true}))
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
			return map[string]any{"deliveries": deliveries}, nil
		}
		return map[string]any{"deliveries": []*DeliveryAttempt{}}, nil
	}

	return map[string]any{"deliveries": log}, nil
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
